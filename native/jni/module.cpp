// SPDX-License-Identifier: GPL-3.0-or-later

#include <android/log.h>
#include <ctype.h>
#include <errno.h>
#include <jni.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "zygisk.hpp"

namespace {

constexpr char kLogTag[] = "MiPushSpoofNext";
constexpr char kStateDir[] = "/data/adb/mipush-spoof-next";
constexpr char kOptionsPath[] = "/data/adb/mipush-spoof-next/options.conf";
constexpr char kProfilePath[] = "/data/adb/mipush-spoof-next/profile.properties";
constexpr char kManualPackagesPath[] = "/data/adb/mipush-spoof-next/packages.txt";
constexpr char kAutoPackagesPath[] = "/data/adb/mipush-spoof-next/packages.auto.txt";

constexpr uint32_t kMagic = 0x4d50534e;  // MPSN
constexpr uint32_t kProtocolVersion = 1;
constexpr uint64_t kFakeHandlePrefix = 0x4d50534e00000000ULL;
constexpr uint64_t kFakeHandleMask = 0xffffffff00000000ULL;

constexpr size_t kProcessSize = 192;
constexpr size_t kDataDirSize = 384;
constexpr size_t kPropertyKeySize = 128;
constexpr size_t kValueSize = 256;
constexpr size_t kBuildFieldSize = 64;
constexpr size_t kMaxProperties = 64;
constexpr size_t kMaxBuildFields = 24;
constexpr size_t kMaxObservedKeys = 64;
constexpr int kIpcTimeoutMs = 2000;

enum ResponseStatus : uint32_t {
    kNotTarget = 0,
    kTarget = 1,
    kConfigError = 2,
};

enum FeatureFlags : uint32_t {
    kSpoofProperties = 1u << 0,
    kSpoofBuildFields = 1u << 1,
    kObserveProperties = 1u << 2,
};

struct Request {
    uint32_t magic;
    uint32_t version;
    int32_t uid;
    char process[kProcessSize];
    char app_data_dir[kDataDirSize];
};

struct PropertyEntry {
    char key[kPropertyKeySize];
    char value[kValueSize];
};

struct BuildEntry {
    char field[kBuildFieldSize];
    char value[kValueSize];
};

struct Response {
    uint32_t magic;
    uint32_t version;
    uint32_t status;
    uint32_t flags;
    int32_t log_level;
    uint32_t property_count;
    uint32_t build_count;
    PropertyEntry properties[kMaxProperties];
    BuildEntry build_fields[kMaxBuildFields];
};

struct Options {
    bool spoof_properties = true;
    bool spoof_build_fields = true;
    bool observe_properties = false;
    int log_level = 1;
};

static_assert(sizeof(Request) == 588, "IPC request layout changed");
static_assert(sizeof(Response) == 32284, "IPC response layout changed");
static_assert(sizeof(Response) < 65536, "IPC response must remain bounded");

static Response g_config{};
static bool g_is_target = false;
static bool g_fake_handles_ready = false;
static char g_process[kProcessSize]{};

enum ObservedState : uint32_t {
    kObservedEmpty = 0,
    kObservedWriting = 1,
    kObservedReady = 2,
    kObservedLogged = 3,
};

static uint32_t g_observed_states[kMaxObservedKeys]{};
static char g_observed_keys[kMaxObservedKeys][kPropertyKeySize]{};
static bool g_observed_spoofed[kMaxObservedKeys]{};

#define LOG_ERROR(...) __android_log_print(ANDROID_LOG_ERROR, kLogTag, __VA_ARGS__)
#define LOG_INFO(...) do { if (g_config.log_level >= 1) __android_log_print(ANDROID_LOG_INFO, kLogTag, __VA_ARGS__); } while (0)
#define LOG_DEBUG(...) do { if (g_config.log_level >= 2) __android_log_print(ANDROID_LOG_DEBUG, kLogTag, __VA_ARGS__); } while (0)

static void clear_pending_exception(JNIEnv *env);

static bool deadline_after_ms(struct timespec *deadline, int milliseconds) {
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) return false;
    deadline->tv_sec += milliseconds / 1000;
    deadline->tv_nsec += static_cast<long>(milliseconds % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        ++deadline->tv_sec;
        deadline->tv_nsec -= 1000000000L;
    }
    return true;
}

static int remaining_milliseconds(const struct timespec &deadline) {
    struct timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    const int64_t seconds = static_cast<int64_t>(deadline.tv_sec) - now.tv_sec;
    const int64_t nanoseconds = static_cast<int64_t>(deadline.tv_nsec) - now.tv_nsec;
    const int64_t total_nanoseconds = seconds * 1000000000LL + nanoseconds;
    if (total_nanoseconds <= 0) return 0;
    const int64_t rounded = (total_nanoseconds + 999999LL) / 1000000LL;
    return rounded > INT_MAX ? INT_MAX : static_cast<int>(rounded);
}

static bool wait_for_fd(int fd, short events, const struct timespec &deadline) {
    while (true) {
        const int timeout = remaining_milliseconds(deadline);
        if (timeout <= 0) return false;
        struct pollfd descriptor { fd, events, 0 };
        const int result = poll(&descriptor, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return false;
        return (descriptor.revents & events) != 0;
    }
}

static bool read_fully(int fd, void *buffer, size_t size, const struct timespec &deadline) {
    auto *cursor = static_cast<unsigned char *>(buffer);
    while (size > 0) {
        if (!wait_for_fd(fd, POLLIN, deadline)) return false;
        const ssize_t result = recv(fd, cursor, size, MSG_DONTWAIT);
        if (result == 0) return false;
        if (result < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return false;
        }
        cursor += result;
        size -= static_cast<size_t>(result);
    }
    return true;
}

static bool write_fully(int fd, const void *buffer, size_t size,
                        const struct timespec &deadline) {
    const auto *cursor = static_cast<const unsigned char *>(buffer);
    while (size > 0) {
        if (!wait_for_fd(fd, POLLOUT, deadline)) return false;
        const ssize_t result = send(fd, cursor, size, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (result == 0) return false;
        if (result < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return false;
        }
        cursor += result;
        size -= static_cast<size_t>(result);
    }
    return true;
}

static bool copy_string(char *destination, size_t destination_size, const char *source) {
    if (destination == nullptr || destination_size == 0 || source == nullptr) return false;
    const size_t length = strlen(source);
    if (length >= destination_size) return false;
    memcpy(destination, source, length + 1);
    return true;
}

static char *trim(char *text) {
    if (text == nullptr) return nullptr;
    while (*text != '\0' && isspace(static_cast<unsigned char>(*text))) ++text;
    char *end = text + strlen(text);
    while (end > text && isspace(static_cast<unsigned char>(end[-1]))) --end;
    *end = '\0';
    return text;
}

static bool equals_ignore_case(const char *left, const char *right) {
    if (left == nullptr || right == nullptr) return false;
    while (*left != '\0' && *right != '\0') {
        if (tolower(static_cast<unsigned char>(*left)) !=
            tolower(static_cast<unsigned char>(*right))) return false;
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

static bool parse_boolean(const char *value, bool fallback) {
    if (value == nullptr) return fallback;
    if (equals_ignore_case(value, "1") || equals_ignore_case(value, "true") ||
        equals_ignore_case(value, "yes") || equals_ignore_case(value, "on")) return true;
    if (equals_ignore_case(value, "0") || equals_ignore_case(value, "false") ||
        equals_ignore_case(value, "no") || equals_ignore_case(value, "off")) return false;
    return fallback;
}

static bool has_prefix(const char *value, const char *prefix) {
    if (value == nullptr || prefix == nullptr) return false;
    const size_t prefix_length = strlen(prefix);
    return strncmp(value, prefix, prefix_length) == 0;
}

static bool is_valid_property_key(const char *key) {
    if (key == nullptr || *key == '\0') return false;
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(key); *p != '\0'; ++p) {
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) return false;
    }
    return true;
}

static bool is_safe_profile_value(const char *value) {
    if (value == nullptr) return false;
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value);
         *p != '\0'; ++p) {
        if (*p < 0x20 || *p > 0x7e) return false;
    }
    return true;
}

static bool is_terminated(const char *value, size_t size) {
    return value != nullptr && memchr(value, '\0', size) != nullptr;
}

static bool is_allowed_build_field(const char *field) {
    static constexpr const char *kAllowed[] = {
        "BOARD", "BOOTLOADER", "BRAND", "DEVICE", "DISPLAY", "FINGERPRINT",
        "HARDWARE", "HOST", "ID", "MANUFACTURER", "MODEL", "PRODUCT",
        "TAGS", "TYPE", "USER", "VERSION.INCREMENTAL"
    };
    for (const char *allowed : kAllowed) {
        if (strcmp(field, allowed) == 0) return true;
    }
    return false;
}

static void parse_options(Options *options) {
    FILE *file = fopen(kOptionsPath, "r");
    if (file == nullptr) return;

    char line[512];
    while (fgets(line, sizeof(line), file) != nullptr) {
        char *comment = strchr(line, '#');
        if (comment != nullptr) *comment = '\0';
        char *entry = trim(line);
        if (*entry == '\0') continue;
        char *separator = strchr(entry, '=');
        if (separator == nullptr) continue;
        *separator = '\0';
        char *key = trim(entry);
        char *value = trim(separator + 1);

        if (strcmp(key, "spoof_properties") == 0) {
            options->spoof_properties = parse_boolean(value, options->spoof_properties);
        } else if (strcmp(key, "spoof_build_fields") == 0) {
            options->spoof_build_fields = parse_boolean(value, options->spoof_build_fields);
        } else if (strcmp(key, "observe_properties") == 0) {
            options->observe_properties = parse_boolean(value, options->observe_properties);
        } else if (strcmp(key, "log_level") == 0) {
            char *end = nullptr;
            const long parsed = strtol(value, &end, 10);
            if (end != value && *end == '\0' && parsed >= 0 && parsed <= 2) {
                options->log_level = static_cast<int>(parsed);
            }
        }
    }
    fclose(file);
}

static void add_or_replace_property(Response *response, const char *key, const char *value) {
    for (uint32_t i = 0; i < response->property_count; ++i) {
        if (strcmp(response->properties[i].key, key) == 0) {
            if (!copy_string(response->properties[i].value, sizeof(response->properties[i].value), value)) {
                response->properties[i].value[0] = '\0';
            }
            return;
        }
    }
    if (response->property_count >= kMaxProperties) return;
    PropertyEntry *entry = &response->properties[response->property_count];
    if (!copy_string(entry->key, sizeof(entry->key), key) ||
        !copy_string(entry->value, sizeof(entry->value), value)) return;
    ++response->property_count;
}

static void add_or_replace_build_field(Response *response, const char *field, const char *value) {
    for (uint32_t i = 0; i < response->build_count; ++i) {
        if (strcmp(response->build_fields[i].field, field) == 0) {
            if (!copy_string(response->build_fields[i].value,
                             sizeof(response->build_fields[i].value), value)) {
                response->build_fields[i].value[0] = '\0';
            }
            return;
        }
    }
    if (response->build_count >= kMaxBuildFields) return;
    BuildEntry *entry = &response->build_fields[response->build_count];
    if (!copy_string(entry->field, sizeof(entry->field), field) ||
        !copy_string(entry->value, sizeof(entry->value), value)) return;
    ++response->build_count;
}

static bool parse_profile(Response *response) {
    FILE *file = fopen(kProfilePath, "r");
    if (file == nullptr) return false;

    char line[768];
    while (fgets(line, sizeof(line), file) != nullptr) {
        char *comment = strchr(line, '#');
        if (comment != nullptr) *comment = '\0';
        char *entry = trim(line);
        if (*entry == '\0') continue;
        char *separator = strchr(entry, '=');
        if (separator == nullptr) continue;
        *separator = '\0';
        char *key = trim(entry);
        char *value = trim(separator + 1);

        if (!is_safe_profile_value(value)) continue;
        if (has_prefix(key, "prop.")) {
            key += strlen("prop.");
            if (is_valid_property_key(key)) add_or_replace_property(response, key, value);
        } else if (has_prefix(key, "build.")) {
            key += strlen("build.");
            if (is_allowed_build_field(key)) add_or_replace_build_field(response, key, value);
        }
    }
    fclose(file);
    return response->property_count > 0 || response->build_count > 0;
}

static bool validate_request(const Request &request) {
    return request.magic == kMagic && request.version == kProtocolVersion &&
           is_terminated(request.process, sizeof(request.process)) && request.process[0] != '\0' &&
           is_terminated(request.app_data_dir, sizeof(request.app_data_dir));
}

static bool validate_response(const Response &response) {
    constexpr uint32_t kKnownFlags = kSpoofProperties | kSpoofBuildFields | kObserveProperties;
    if (response.magic != kMagic || response.version != kProtocolVersion ||
        response.status > kConfigError || (response.flags & ~kKnownFlags) != 0 ||
        response.log_level < 0 || response.log_level > 2 ||
        response.property_count > kMaxProperties || response.build_count > kMaxBuildFields) {
        return false;
    }
    for (uint32_t i = 0; i < response.property_count; ++i) {
        const PropertyEntry &entry = response.properties[i];
        if (!is_terminated(entry.key, sizeof(entry.key)) ||
            !is_terminated(entry.value, sizeof(entry.value)) ||
            !is_valid_property_key(entry.key) || !is_safe_profile_value(entry.value)) return false;
    }
    for (uint32_t i = 0; i < response.build_count; ++i) {
        const BuildEntry &entry = response.build_fields[i];
        if (!is_terminated(entry.field, sizeof(entry.field)) ||
            !is_terminated(entry.value, sizeof(entry.value)) ||
            !is_allowed_build_field(entry.field) || !is_safe_profile_value(entry.value)) return false;
    }
    if (response.status == kTarget && response.property_count == 0 && response.build_count == 0) {
        return false;
    }
    return true;
}

static void package_from_data_dir(const char *app_data_dir, char *package_name,
                                  size_t package_name_size) {
    package_name[0] = '\0';
    if (app_data_dir == nullptr || *app_data_dir == '\0') return;
    const char *end = app_data_dir + strlen(app_data_dir);
    while (end > app_data_dir && end[-1] == '/') --end;
    const char *start = end;
    while (start > app_data_dir && start[-1] != '/') --start;
    const size_t length = static_cast<size_t>(end - start);
    if (length == 0 || length >= package_name_size) return;
    memcpy(package_name, start, length);
    package_name[length] = '\0';
}

static bool matches_rule(const char *rule, const char *package_name, const char *process) {
    if (strchr(rule, ':') != nullptr) return strcmp(rule, process) == 0;
    if (package_name[0] != '\0' && strcmp(rule, package_name) == 0) return true;
    const size_t length = strlen(rule);
    return strncmp(rule, process, length) == 0 &&
           (process[length] == '\0' || process[length] == ':');
}

static bool built_in_denied(const char *package_name, const char *process, int32_t uid) {
    const int32_t app_id = uid >= 0 ? uid % 100000 : uid;
    if (app_id >= 0 && app_id < 10000) return true;

    const char *candidate = package_name[0] != '\0' ? package_name : process;
    static constexpr const char *kExact[] = {
        "android", "system_server", "com.android.vending", "com.google.android.gms",
        "com.xiaomi.xmsf", "com.topjohnwu.magisk", "me.weishu.kernelsu",
        "com.rifsxd.ksunext", "me.bmax.apatch", "org.lsposed.manager",
        "com.tencent.mm", "top.trumeet.mipush"
    };
    for (const char *denied : kExact) {
        if (strcmp(candidate, denied) == 0) return true;
    }
    static constexpr const char *kPrefixes[] = {
        "com.android.", "com.google.android.gms:", "com.xiaomi.xmsf:"
    };
    for (const char *prefix : kPrefixes) {
        if (has_prefix(candidate, prefix) || has_prefix(process, prefix)) return true;
    }
    return false;
}

static void evaluate_rule_file(const char *path, const char *package_name, const char *process,
                               bool *allowed, bool *denied) {
    FILE *file = fopen(path, "r");
    if (file == nullptr) return;
    char line[512];
    while (fgets(line, sizeof(line), file) != nullptr) {
        char *comment = strchr(line, '#');
        if (comment != nullptr) *comment = '\0';
        char *rule = trim(line);
        if (*rule == '\0') continue;
        bool is_deny = false;
        if (*rule == '!') {
            is_deny = true;
            rule = trim(rule + 1);
        }
        if (*rule == '\0' || !matches_rule(rule, package_name, process)) continue;
        if (is_deny) *denied = true;
        else *allowed = true;
    }
    fclose(file);
}

static bool is_target_process(const Request &request) {
    char package_name[kProcessSize]{};
    package_from_data_dir(request.app_data_dir, package_name, sizeof(package_name));
    if (built_in_denied(package_name, request.process, request.uid)) return false;

    bool allowed = false;
    bool denied = false;
    evaluate_rule_file(kManualPackagesPath, package_name, request.process, &allowed, &denied);
    evaluate_rule_file(kAutoPackagesPath, package_name, request.process, &allowed, &denied);
    return allowed && !denied;
}

static const PropertyEntry *find_property(const char *key) {
    if (key == nullptr) return nullptr;
    for (uint32_t i = 0; i < g_config.property_count; ++i) {
        if (strcmp(g_config.properties[i].key, key) == 0) return &g_config.properties[i];
    }
    return nullptr;
}

static void observe_key(const char *key, bool spoofed) {
    if ((g_config.flags & kObserveProperties) == 0 || key == nullptr || *key == '\0') return;
    uint32_t hash = 2166136261u;
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(key); *p != '\0'; ++p) {
        hash = (hash ^ *p) * 16777619u;
    }
    for (size_t attempt = 0; attempt < kMaxObservedKeys; ++attempt) {
        const size_t index = (static_cast<size_t>(hash) + attempt) % kMaxObservedKeys;
        uint32_t state = __atomic_load_n(&g_observed_states[index], __ATOMIC_ACQUIRE);
        if (state >= kObservedReady && strcmp(g_observed_keys[index], key) == 0) return;
        if (state != kObservedEmpty) continue;
        uint32_t expected = kObservedEmpty;
        if (!__atomic_compare_exchange_n(&g_observed_states[index], &expected, kObservedWriting,
                                         false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) continue;
        if (!copy_string(g_observed_keys[index], sizeof(g_observed_keys[index]), key)) {
            __atomic_store_n(&g_observed_states[index], kObservedEmpty, __ATOMIC_RELEASE);
            return;
        }
        g_observed_spoofed[index] = spoofed;
        __atomic_store_n(&g_observed_states[index], kObservedReady, __ATOMIC_RELEASE);
        return;
    }
}

static void *observer_logger(void * /*unused*/) {
    while (true) {
        for (size_t i = 0; i < kMaxObservedKeys; ++i) {
            uint32_t expected = kObservedReady;
            if (__atomic_compare_exchange_n(&g_observed_states[i], &expected, kObservedLogged,
                                             false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                LOG_INFO("observe process=%s key=%s spoofed=%d", g_process, g_observed_keys[i],
                         g_observed_spoofed[i] ? 1 : 0);
            }
        }
        sleep(1);
    }
}

static void start_observer_logger() {
    pthread_t thread{};
    const int result = pthread_create(&thread, nullptr, observer_logger, nullptr);
    if (result != 0) {
        LOG_ERROR("Unable to start observer logger process=%s error=%d", g_process, result);
        return;
    }
    pthread_detach(thread);
}

static const PropertyEntry *property_from_jstring(JNIEnv *env, jstring key) {
    if (key == nullptr) return nullptr;
    const char *utf_key = env->GetStringUTFChars(key, nullptr);
    if (utf_key == nullptr) {
        clear_pending_exception(env);
        return nullptr;
    }
    const PropertyEntry *entry = find_property(utf_key);
    observe_key(utf_key, entry != nullptr && (g_config.flags & kSpoofProperties) != 0);
    env->ReleaseStringUTFChars(key, utf_key);
    if ((g_config.flags & kSpoofProperties) == 0) return nullptr;
    return entry;
}

using GetStringFn = jstring (*)(JNIEnv *, jclass, jstring, jstring);
using GetStringLegacyFn = jstring (*)(JNIEnv *, jclass, jstring);
using GetIntFn = jint (*)(JNIEnv *, jclass, jstring, jint);
using GetLongFn = jlong (*)(JNIEnv *, jclass, jstring, jlong);
using GetBooleanFn = jboolean (*)(JNIEnv *, jclass, jstring, jboolean);
using FindFn = jlong (*)(JNIEnv *, jclass, jstring);
using GetHandleStringFn = jstring (*)(JNIEnv *, jclass, jlong);
using GetHandleIntFn = jint (*)(jlong, jint);
using GetHandleLongFn = jlong (*)(jlong, jlong);
using GetHandleBooleanFn = jboolean (*)(jlong, jboolean);

static GetStringFn g_original_get_string = nullptr;
static GetStringLegacyFn g_original_get_string_legacy = nullptr;
static GetIntFn g_original_get_int = nullptr;
static GetLongFn g_original_get_long = nullptr;
static GetBooleanFn g_original_get_boolean = nullptr;
static FindFn g_original_find = nullptr;
static GetHandleStringFn g_original_get_handle_string = nullptr;
static GetHandleIntFn g_original_get_handle_int = nullptr;
static GetHandleLongFn g_original_get_handle_long = nullptr;
static GetHandleBooleanFn g_original_get_handle_boolean = nullptr;

static bool parse_integer(const char *value, long long minimum, long long maximum,
                          long long *result) {
    if (value == nullptr || *value == '\0') return false;
    char *end = nullptr;
    errno = 0;
    const long long parsed = strtoll(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0' || parsed < minimum || parsed > maximum) {
        return false;
    }
    *result = parsed;
    return true;
}

static bool parse_android_boolean(const char *value, bool *result) {
    if (value == nullptr) return false;
    if (strcmp(value, "1") == 0 || strcmp(value, "y") == 0 || strcmp(value, "yes") == 0 ||
        strcmp(value, "on") == 0 || strcmp(value, "true") == 0) {
        *result = true;
        return true;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "n") == 0 || strcmp(value, "no") == 0 ||
        strcmp(value, "off") == 0 || strcmp(value, "false") == 0) {
        *result = false;
        return true;
    }
    return false;
}

static jstring hooked_get_string(JNIEnv *env, jclass clazz, jstring key, jstring fallback) {
    const PropertyEntry *entry = property_from_jstring(env, key);
    if (entry != nullptr) {
        if (entry->value[0] != '\0') return env->NewStringUTF(entry->value);
        if (fallback != nullptr) return static_cast<jstring>(env->NewLocalRef(fallback));
        return env->NewStringUTF("");
    }
    return g_original_get_string != nullptr ? g_original_get_string(env, clazz, key, fallback)
                                            : fallback;
}

static jstring hooked_get_string_legacy(JNIEnv *env, jclass clazz, jstring key) {
    const PropertyEntry *entry = property_from_jstring(env, key);
    if (entry != nullptr) return env->NewStringUTF(entry->value);
    return g_original_get_string_legacy != nullptr
               ? g_original_get_string_legacy(env, clazz, key)
               : env->NewStringUTF("");
}

static jint hooked_get_int(JNIEnv *env, jclass clazz, jstring key, jint fallback) {
    const PropertyEntry *entry = property_from_jstring(env, key);
    long long parsed = 0;
    if (entry != nullptr && parse_integer(entry->value, INT_MIN, INT_MAX, &parsed)) {
        return static_cast<jint>(parsed);
    }
    return g_original_get_int != nullptr ? g_original_get_int(env, clazz, key, fallback) : fallback;
}

static jlong hooked_get_long(JNIEnv *env, jclass clazz, jstring key, jlong fallback) {
    const PropertyEntry *entry = property_from_jstring(env, key);
    long long parsed = 0;
    if (entry != nullptr && parse_integer(entry->value, LLONG_MIN, LLONG_MAX, &parsed)) {
        return static_cast<jlong>(parsed);
    }
    return g_original_get_long != nullptr ? g_original_get_long(env, clazz, key, fallback) : fallback;
}

static jboolean hooked_get_boolean(JNIEnv *env, jclass clazz, jstring key, jboolean fallback) {
    const PropertyEntry *entry = property_from_jstring(env, key);
    bool parsed = false;
    if (entry != nullptr && parse_android_boolean(entry->value, &parsed)) {
        return parsed ? JNI_TRUE : JNI_FALSE;
    }
    return g_original_get_boolean != nullptr
               ? g_original_get_boolean(env, clazz, key, fallback)
               : fallback;
}

static jlong fake_handle_for(const PropertyEntry *entry) {
    if (entry == nullptr || !g_fake_handles_ready) return 0;
    const ptrdiff_t index = entry - g_config.properties;
    if (index < 0 || static_cast<size_t>(index) >= kMaxProperties) return 0;
    return static_cast<jlong>(kFakeHandlePrefix | static_cast<uint64_t>(index + 1));
}

static const PropertyEntry *property_from_fake_handle(jlong handle) {
    const uint64_t raw = static_cast<uint64_t>(handle);
    if ((raw & kFakeHandleMask) != kFakeHandlePrefix) return nullptr;
    const uint64_t encoded_index = raw & 0xffffffffULL;
    if (encoded_index == 0 || encoded_index > g_config.property_count) return nullptr;
    return &g_config.properties[encoded_index - 1];
}

static jlong hooked_find(JNIEnv *env, jclass clazz, jstring key) {
    const PropertyEntry *entry = property_from_jstring(env, key);
    const jlong fake = fake_handle_for(entry);
    if (fake != 0) return fake;
    return g_original_find != nullptr ? g_original_find(env, clazz, key) : 0;
}

static jstring hooked_get_handle_string(JNIEnv *env, jclass clazz, jlong handle) {
    const PropertyEntry *entry = property_from_fake_handle(handle);
    if (entry != nullptr) return env->NewStringUTF(entry->value);
    return g_original_get_handle_string != nullptr
               ? g_original_get_handle_string(env, clazz, handle)
               : env->NewStringUTF("");
}

static jint hooked_get_handle_int(jlong handle, jint fallback) {
    const PropertyEntry *entry = property_from_fake_handle(handle);
    long long parsed = 0;
    if (entry != nullptr) {
        return parse_integer(entry->value, INT_MIN, INT_MAX, &parsed)
                   ? static_cast<jint>(parsed)
                   : fallback;
    }
    return g_original_get_handle_int != nullptr ? g_original_get_handle_int(handle, fallback) : fallback;
}

static jlong hooked_get_handle_long(jlong handle, jlong fallback) {
    const PropertyEntry *entry = property_from_fake_handle(handle);
    long long parsed = 0;
    if (entry != nullptr) {
        return parse_integer(entry->value, LLONG_MIN, LLONG_MAX, &parsed)
                   ? static_cast<jlong>(parsed)
                   : fallback;
    }
    return g_original_get_handle_long != nullptr ? g_original_get_handle_long(handle, fallback) : fallback;
}

static jboolean hooked_get_handle_boolean(jlong handle, jboolean fallback) {
    const PropertyEntry *entry = property_from_fake_handle(handle);
    bool parsed = false;
    if (entry != nullptr) {
        return parse_android_boolean(entry->value, &parsed)
                   ? (parsed ? JNI_TRUE : JNI_FALSE)
                   : fallback;
    }
    return g_original_get_handle_boolean != nullptr
               ? g_original_get_handle_boolean(handle, fallback)
               : fallback;
}

template <typename Function>
static void save_original(Function *destination, void *source) {
    *reinterpret_cast<void **>(destination) = source;
}

static bool install_system_property_hooks(zygisk::Api *api, JNIEnv *env) {
    JNINativeMethod methods[] = {
        {"native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(hooked_get_string)},
        {"native_get", "(Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void *>(hooked_get_string_legacy)},
        {"native_get_int", "(Ljava/lang/String;I)I", reinterpret_cast<void *>(hooked_get_int)},
        {"native_get_long", "(Ljava/lang/String;J)J", reinterpret_cast<void *>(hooked_get_long)},
        {"native_get_boolean", "(Ljava/lang/String;Z)Z", reinterpret_cast<void *>(hooked_get_boolean)},
        {"native_find", "(Ljava/lang/String;)J", reinterpret_cast<void *>(hooked_find)},
        {"native_get", "(J)Ljava/lang/String;", reinterpret_cast<void *>(hooked_get_handle_string)},
        {"native_get_int", "(JI)I", reinterpret_cast<void *>(hooked_get_handle_int)},
        {"native_get_long", "(JJ)J", reinterpret_cast<void *>(hooked_get_handle_long)},
        {"native_get_boolean", "(JZ)Z", reinterpret_cast<void *>(hooked_get_handle_boolean)},
    };
    api->hookJniNativeMethods(env, "android/os/SystemProperties", methods,
                              static_cast<int>(sizeof(methods) / sizeof(methods[0])));

    save_original(&g_original_get_string, methods[0].fnPtr);
    save_original(&g_original_get_string_legacy, methods[1].fnPtr);
    save_original(&g_original_get_int, methods[2].fnPtr);
    save_original(&g_original_get_long, methods[3].fnPtr);
    save_original(&g_original_get_boolean, methods[4].fnPtr);
    save_original(&g_original_find, methods[5].fnPtr);
    save_original(&g_original_get_handle_string, methods[6].fnPtr);
    save_original(&g_original_get_handle_int, methods[7].fnPtr);
    save_original(&g_original_get_handle_long, methods[8].fnPtr);
    save_original(&g_original_get_handle_boolean, methods[9].fnPtr);

    const bool string_key_ready = g_original_get_string != nullptr;
    g_fake_handles_ready = g_original_find != nullptr && g_original_get_handle_string != nullptr &&
                           g_original_get_handle_int != nullptr && g_original_get_handle_long != nullptr &&
                           g_original_get_handle_boolean != nullptr;
    LOG_INFO("SystemProperties hooks process=%s string=%d int=%d long=%d bool=%d handles=%d legacy=%d",
             g_process, string_key_ready ? 1 : 0, g_original_get_int != nullptr ? 1 : 0,
             g_original_get_long != nullptr ? 1 : 0, g_original_get_boolean != nullptr ? 1 : 0,
             g_fake_handles_ready ? 1 : 0, g_original_get_string_legacy != nullptr ? 1 : 0);
    return string_key_ready || g_original_get_int != nullptr || g_original_get_long != nullptr ||
           g_original_get_boolean != nullptr;
}

static void clear_pending_exception(JNIEnv *env) {
    if (env->ExceptionCheck()) env->ExceptionClear();
}

static void apply_build_fields(JNIEnv *env) {
    jclass build_class = env->FindClass("android/os/Build");
    if (build_class == nullptr) {
        clear_pending_exception(env);
        LOG_ERROR("Build class unavailable for process=%s", g_process);
        return;
    }
    jclass version_class = nullptr;

    for (uint32_t i = 0; i < g_config.build_count; ++i) {
        const BuildEntry &entry = g_config.build_fields[i];
        jclass target_class = build_class;
        const char *field_name = entry.field;
        if (has_prefix(field_name, "VERSION.")) {
            if (version_class == nullptr) {
                version_class = env->FindClass("android/os/Build$VERSION");
                if (version_class == nullptr) {
                    clear_pending_exception(env);
                    continue;
                }
            }
            target_class = version_class;
            field_name += strlen("VERSION.");
        }

        const jfieldID field = env->GetStaticFieldID(target_class, field_name, "Ljava/lang/String;");
        if (field == nullptr) {
            clear_pending_exception(env);
            LOG_DEBUG("Build field missing process=%s field=%s", g_process, entry.field);
            continue;
        }
        jstring value = env->NewStringUTF(entry.value);
        if (value == nullptr) {
            clear_pending_exception(env);
            continue;
        }
        env->SetStaticObjectField(target_class, field, value);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            LOG_ERROR("Build field write failed process=%s field=%s", g_process, entry.field);
        } else {
            LOG_DEBUG("Build field applied process=%s field=%s", g_process, entry.field);
        }
        env->DeleteLocalRef(value);
    }

    if (version_class != nullptr) env->DeleteLocalRef(version_class);
    env->DeleteLocalRef(build_class);
    LOG_INFO("Build profile applied process=%s fields=%u", g_process, g_config.build_count);
}

static void jstring_to_buffer(JNIEnv *env, jstring value, char *buffer, size_t buffer_size) {
    buffer[0] = '\0';
    if (value == nullptr) return;
    const char *utf = env->GetStringUTFChars(value, nullptr);
    if (utf == nullptr) {
        clear_pending_exception(env);
        return;
    }
    copy_string(buffer, buffer_size, utf);
    env->ReleaseStringUTFChars(value, utf);
}

class MiPushSpoofModule final : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args->is_child_zygote != nullptr && *args->is_child_zygote == JNI_TRUE) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        Request request{};
        request.magic = kMagic;
        request.version = kProtocolVersion;
        request.uid = args->uid;
        jstring_to_buffer(env_, args->nice_name, request.process, sizeof(request.process));
        jstring_to_buffer(env_, args->app_data_dir, request.app_data_dir, sizeof(request.app_data_dir));

        if (request.process[0] == '\0') {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const int companion = api_->connectCompanion();
        Response response{};
        struct timespec deadline{};
        const bool exchanged = companion >= 0 && deadline_after_ms(&deadline, kIpcTimeoutMs) &&
                               write_fully(companion, &request, sizeof(request), deadline) &&
                               read_fully(companion, &response, sizeof(response), deadline);
        if (companion >= 0) close(companion);
        const bool valid_response = exchanged && validate_response(response);
        if (valid_response && response.status == kConfigError) {
            LOG_ERROR("Target matched but profile is missing or invalid process=%s", request.process);
        }
        if (!valid_response || response.status != kTarget) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        g_config = response;
        g_is_target = true;
        copy_string(g_process, sizeof(g_process), request.process);
        LOG_INFO("target selected process=%s props=%u fields=%u flags=0x%x state=%s",
                 g_process, g_config.property_count, g_config.build_count, g_config.flags, kStateDir);

        if ((g_config.flags & (kSpoofProperties | kObserveProperties)) != 0) {
            if (!install_system_property_hooks(api_, env_)) {
                LOG_ERROR("No compatible SystemProperties JNI methods process=%s; continuing Build-only", g_process);
            }
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
        if (g_is_target && (g_config.flags & kSpoofBuildFields) != 0) apply_build_fields(env_);
        if (g_is_target && (g_config.flags & kObserveProperties) != 0) start_observer_logger();
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs * /*args*/) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
};

static void companion_handler(int client) {
    Request request{};
    struct timespec deadline{};
    if (!deadline_after_ms(&deadline, kIpcTimeoutMs) ||
        !read_fully(client, &request, sizeof(request), deadline) || !validate_request(request)) return;

    Response response{};
    response.magic = kMagic;
    response.version = kProtocolVersion;
    response.status = kNotTarget;

    if (is_target_process(request)) {
        Options options;
        parse_options(&options);
        response.log_level = options.log_level;
        if (options.spoof_properties) response.flags |= kSpoofProperties;
        if (options.spoof_build_fields) response.flags |= kSpoofBuildFields;
        if (options.observe_properties) response.flags |= kObserveProperties;
        if (parse_profile(&response)) response.status = kTarget;
        else response.status = kConfigError;
    }

    write_fully(client, &response, sizeof(response), deadline);
}

}  // namespace

REGISTER_ZYGISK_MODULE(MiPushSpoofModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
