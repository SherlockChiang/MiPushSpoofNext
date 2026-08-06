APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
APP_PLATFORM := android-26
APP_STL := none
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
APP_CPPFLAGS := -std=c++20 -fno-exceptions -fno-rtti -fno-threadsafe-statics -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections -Wall -Wextra -Wpedantic -Werror=return-type
APP_LDFLAGS := -Wl,--gc-sections -Wl,-z,max-page-size=16384
