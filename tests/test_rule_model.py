import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE_HANDLE_PREFIX = 0x4D50534E00000000
FAKE_HANDLE_MASK = 0xFFFFFFFF00000000

SPOOF_PROPERTIES = 1 << 0
SPOOF_BUILD_FIELDS = 1 << 1
OBSERVE_PROPERTIES = 1 << 2
MODE_NAMES = ("inherit", "full", "properties", "build", "observe", "excluded")
REASON_NAMES = (
    "built_in_deny", "no_matching_allow", "explicit_deny", "mode_excluded",
    "mode_invalid", "no_capabilities", "manual_allow", "auto_allow",
)
DEFAULT_OPTIONS = {"spoof_properties": True, "spoof_build_fields": True,
                   "observe_properties": False}

DENIED_EXACT = {
    "android", "system_server", "com.android.vending", "com.google.android.gms",
    "com.xiaomi.xmsf", "com.topjohnwu.magisk", "me.weishu.kernelsu",
    "com.rifsxd.ksunext", "me.bmax.apatch", "org.lsposed.manager",
    "com.tencent.mm", "top.trumeet.mipush",
}
DENIED_PREFIXES = ("com.android.", "com.google.android.gms:", "com.xiaomi.xmsf:")


def package_from_data_dir(app_data_dir):
    return app_data_dir.rstrip("/").rsplit("/", 1)[-1] if app_data_dir else ""


def matches(rule, package_name, process):
    if ":" in rule:
        return rule == process
    if package_name and rule == package_name:
        return True
    return process == rule or process.startswith(rule + ":")


def rule_match(rules, package_name, process):
    allow = False
    deny = False
    for raw in rules:
        rule = raw.split("#", 1)[0].strip()
        if not rule:
            continue
        is_deny = rule.startswith("!")
        if is_deny:
            rule = rule[1:].strip()
        if rule and matches(rule, package_name, process):
            deny |= is_deny
            allow |= not is_deny
    return allow, deny


def evaluate(rules, package_name, process):
    allow, deny = rule_match(rules, package_name, process)
    return allow and not deny


def resolve_mode(entries, package_name, process):
    package_mode = "inherit"
    process_mode = None
    excluded = False
    invalid = False
    for raw in entries:
        line = raw.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        rule, value = (part.strip() for part in line.split("=", 1))
        if not rule or not matches(rule, package_name, process):
            continue
        mode = value.lower()
        if mode not in MODE_NAMES:
            invalid = True
        elif mode == "excluded":
            excluded = True
        elif ":" in rule:
            process_mode = mode
        else:
            package_mode = mode
    if invalid:
        return "invalid"
    if excluded:
        return "excluded"
    return process_mode or package_mode


def flags_for_mode(mode, options):
    if mode == "full":
        return SPOOF_PROPERTIES | SPOOF_BUILD_FIELDS
    if mode == "properties":
        return SPOOF_PROPERTIES
    if mode == "build":
        return SPOOF_BUILD_FIELDS
    if mode == "observe":
        return OBSERVE_PROPERTIES
    if mode == "inherit":
        return ((SPOOF_PROPERTIES if options["spoof_properties"] else 0) |
                (SPOOF_BUILD_FIELDS if options["spoof_build_fields"] else 0) |
                (OBSERVE_PROPERTIES if options["observe_properties"] else 0))
    return 0


def resolve_policy(package_name, process, uid=10100, manual=(), auto=(), modes=(),
                   options=None):
    """Returns (target, reason, source, flags) in the order resolve_policy() applies."""
    options = DEFAULT_OPTIONS if options is None else options
    if built_in_denied(package_name, process, uid):
        return False, "built_in_deny", "builtin", 0
    manual_allow, manual_deny = rule_match(manual, package_name, process)
    auto_allow, auto_deny = rule_match(auto, package_name, process)
    if manual_deny or auto_deny:
        return False, "explicit_deny", "manual" if manual_deny else "auto", 0
    if not manual_allow and not auto_allow:
        return False, "no_matching_allow", "none", 0
    mode = resolve_mode(modes, package_name, process)
    if mode in {"excluded", "invalid"}:
        return False, "mode_excluded" if mode == "excluded" else "mode_invalid", "modes", 0
    flags = flags_for_mode(mode, options)
    if not flags:
        return False, "no_capabilities", "options" if mode == "inherit" else "modes", 0
    source = "manual" if manual_allow else "auto"
    return True, source + "_allow", source, flags


def needs_property_hooks(flags):
    return bool(flags & (SPOOF_PROPERTIES | OBSERVE_PROPERTIES))


def native_string_table(name):
    source = (ROOT / "native/jni/module.cpp").read_text(encoding="utf-8")
    match = re.search(rf"\b{name}\[\] = \{{(.*?)\}};", source, re.DOTALL)
    if match is None:
        raise AssertionError(f"{name} not found in module.cpp")
    return tuple(re.findall(r'"([^"]*)"', match.group(1)))


def set_app_state(rules, package_name, state):
    retained = []
    for raw in rules:
        candidate = raw[1:] if raw.startswith("!") else raw
        if candidate == package_name or candidate.startswith(package_name + ":"):
            continue
        retained.append(raw)
    if state == "enabled":
        retained.append(package_name)
    elif state == "disabled":
        retained.append("!" + package_name)
    elif state != "auto":
        raise ValueError(state)
    return retained


def built_in_denied(package_name, process, uid):
    app_id = uid % 100000 if uid >= 0 else uid
    if 0 <= app_id < 10000:
        return True
    candidate = package_name or process
    return (candidate in DENIED_EXACT or
            any(candidate.startswith(prefix) or process.startswith(prefix)
                for prefix in DENIED_PREFIXES))


def parse_integer(value, minimum, maximum):
    if not value:
        return None
    try:
        # Profiles use decimal or explicit 0x/0o prefixes. This intentionally models
        # the accepted cases without claiming byte-for-byte libc strtoll coverage.
        parsed = int(value, 0)
    except ValueError:
        return None
    return parsed if minimum <= parsed <= maximum else None


def parse_android_boolean(value):
    if value in {"1", "y", "yes", "on", "true"}:
        return True
    if value in {"0", "n", "no", "off", "false"}:
        return False
    return None


def fake_handle(index, handles_ready=True):
    return FAKE_HANDLE_PREFIX | (index + 1) if handles_ready else 0


def fake_handle_index(handle, property_count):
    if handle & FAKE_HANDLE_MASK != FAKE_HANDLE_PREFIX:
        return None
    encoded = handle & 0xFFFFFFFF
    return encoded - 1 if 0 < encoded <= property_count else None


def fake_handle_primitive(value, fallback, parser):
    parsed = parser(value)
    return fallback if parsed is None else parsed


class RuleModelTest(unittest.TestCase):
    def test_package_covers_colon_process(self):
        self.assertTrue(matches("com.example.app", "com.example.app", "com.example.app:push"))

    def test_package_does_not_prefix_match_neighbor(self):
        self.assertFalse(matches("com.example.app", "com.example.application", "com.example.application"))

    def test_data_dir_package_covers_arbitrary_custom_process_name(self):
        package_name = package_from_data_dir("/data/user/10/com.example.app/")
        self.assertEqual(package_name, "com.example.app")
        self.assertTrue(matches("com.example.app", package_name, "vendor.named.push.worker"))

    def test_subprocess_rule_is_exact(self):
        self.assertTrue(matches("com.example.app:push", "com.example.app", "com.example.app:push"))
        self.assertFalse(matches("com.example.app:push", "com.example.app", "com.example.app:push2"))

    def test_deny_wins_across_sources(self):
        self.assertFalse(evaluate(["com.example.app", "!com.example.app:camera"],
                                  "com.example.app", "com.example.app:camera"))
        self.assertTrue(evaluate(["com.example.app", "!com.example.app:camera"],
                                 "com.example.app", "com.example.app:push"))

    def test_app_state_transition_removes_conflicting_and_process_rules(self):
        old = ["com.example.app", "!com.example.app", "!com.example.app:camera",
               "com.example.application"]
        self.assertEqual(set_app_state(old, "com.example.app", "enabled"),
                         ["com.example.application", "com.example.app"])
        self.assertEqual(set_app_state(old, "com.example.app", "disabled"),
                         ["com.example.application", "!com.example.app"])

    def test_app_auto_clears_only_the_selected_package_overrides(self):
        old = ["!com.example.app", "com.example.app:push", "com.example.application"]
        self.assertEqual(set_app_state(old, "com.example.app", "auto"),
                         ["com.example.application"])

    def test_builtin_deny_covers_privileged_and_manager_processes(self):
        self.assertTrue(built_in_denied("com.example.app", "com.example.app", 1000))
        self.assertTrue(built_in_denied("com.topjohnwu.magisk", "com.topjohnwu.magisk", 10123))
        self.assertTrue(built_in_denied("me.bmax.apatch", "me.bmax.apatch:service", 10124))
        self.assertTrue(built_in_denied("com.google.android.gms", "com.google.android.gms:push", 10125))
        self.assertFalse(built_in_denied("com.example.app", "com.example.app:push", 10126))

    def test_primitive_parsing_is_typed_and_bounded(self):
        self.assertEqual(parse_integer("0x10", -(2 ** 31), 2 ** 31 - 1), 16)
        self.assertIsNone(parse_integer("Xiaomi", -(2 ** 31), 2 ** 31 - 1))
        self.assertIsNone(parse_integer(str(2 ** 31), -(2 ** 31), 2 ** 31 - 1))
        self.assertIs(parse_android_boolean("true"), True)
        self.assertIs(parse_android_boolean("false"), False)
        self.assertIsNone(parse_android_boolean("TRUE"))

    def test_synthetic_handles_require_complete_hook_set(self):
        self.assertEqual(fake_handle(0, handles_ready=False), 0)
        handle = fake_handle(1)
        self.assertEqual(fake_handle_index(handle, property_count=3), 1)
        self.assertIsNone(fake_handle_index(0x1234, property_count=3))
        self.assertIsNone(fake_handle_index(FAKE_HANDLE_PREFIX | 4, property_count=3))

    def test_invalid_synthetic_handle_primitive_uses_fallback(self):
        parse_int32 = lambda value: parse_integer(value, -(2 ** 31), 2 ** 31 - 1)
        self.assertEqual(fake_handle_primitive("816", 7, parse_int32), 816)
        self.assertEqual(fake_handle_primitive("not-an-int", 7, parse_int32), 7)
        self.assertEqual(fake_handle_primitive("not-a-bool", True, parse_android_boolean), True)

    def test_default_profile_stays_minimal(self):
        text = (ROOT / "module/defaults/profiles/miui14.properties").read_text(encoding="utf-8")
        active = [line for line in text.splitlines() if line and not line.lstrip().startswith("#")]
        self.assertFalse(any("SDK_INT" in line for line in active))
        self.assertFalse(any("FINGERPRINT=" in line for line in active))
        self.assertIn("build.BRAND=Xiaomi", active)
        self.assertIn("build.MANUFACTURER=Xiaomi", active)


class PolicyModelTest(unittest.TestCase):
    QIDIAN = "com.qidian.QDReader"

    def test_explicit_deny_beats_auto_candidate_for_every_process(self):
        for process in (self.QIDIAN, self.QIDIAN + ":pushcore", "vendor.custom.worker"):
            self.assertEqual(
                resolve_policy(self.QIDIAN, process, manual=["!" + self.QIDIAN], auto=[self.QIDIAN]),
                (False, "explicit_deny", "manual", 0))

    def test_rescanned_auto_list_cannot_reinject_denied_package(self):
        manual = ["# user rules", "!" + self.QIDIAN]
        for auto in ([self.QIDIAN], [self.QIDIAN, "com.tencent.mobileqq"], [self.QIDIAN] * 3):
            self.assertFalse(resolve_policy(self.QIDIAN, self.QIDIAN, manual=manual, auto=auto)[0])
        self.assertTrue(resolve_policy("com.tencent.mobileqq", "com.tencent.mobileqq",
                                       manual=manual, auto=[self.QIDIAN, "com.tencent.mobileqq"])[0])

    def test_deny_does_not_reach_neighbor_package(self):
        neighbor = self.QIDIAN + "Lite"
        self.assertEqual(resolve_policy(neighbor, neighbor, manual=["!" + self.QIDIAN], auto=[neighbor]),
                         (True, "auto_allow", "auto", SPOOF_PROPERTIES | SPOOF_BUILD_FIELDS))

    def test_builtin_deny_cannot_be_bypassed_by_allow_or_mode(self):
        self.assertEqual(resolve_policy("com.xiaomi.xmsf", "com.xiaomi.xmsf", manual=["com.xiaomi.xmsf"],
                                        modes=["com.xiaomi.xmsf=full"]),
                         (False, "built_in_deny", "builtin", 0))
        self.assertEqual(resolve_policy("com.example.app", "com.example.app", uid=1000,
                                        manual=["com.example.app"])[1], "built_in_deny")

    def test_allow_reason_names_its_source(self):
        app = "com.example.app"
        self.assertEqual(resolve_policy(app, app, manual=[app], auto=[app])[1:3],
                         ("manual_allow", "manual"))
        self.assertEqual(resolve_policy(app, app + ":push", auto=[app])[1:3], ("auto_allow", "auto"))
        self.assertEqual(resolve_policy(app, app)[1:3], ("no_matching_allow", "none"))

    def test_mode_entry_never_selects_a_package(self):
        app = "com.example.app"
        self.assertEqual(resolve_policy(app, app, modes=[app + "=full"])[1], "no_matching_allow")

    def test_excluded_mode_covers_package_and_subprocesses(self):
        for process in (self.QIDIAN, self.QIDIAN + ":pushcore"):
            self.assertEqual(resolve_policy(self.QIDIAN, process, auto=[self.QIDIAN],
                                            modes=[self.QIDIAN + "=excluded"]),
                             (False, "mode_excluded", "modes", 0))

    def test_process_mode_beats_package_mode_but_never_beats_excluded(self):
        app = "com.example.app"
        modes = [app + "=build", app + ":push=full"]
        self.assertEqual(resolve_mode(modes, app, app), "build")
        self.assertEqual(resolve_mode(modes, app, app + ":push"), "full")
        self.assertEqual(resolve_mode(modes + [app + "=properties"], app, app), "properties")
        self.assertEqual(resolve_mode([app + "=excluded", app + ":push=full"], app, app + ":push"),
                         "excluded")
        self.assertEqual(resolve_mode([app + ":push=excluded"], app, app), "inherit")

    def test_unknown_mode_excludes_instead_of_inheriting(self):
        app = "com.example.app"
        self.assertEqual(resolve_policy(app, app, auto=[app], modes=[app + "=exclude"])[1], "mode_invalid")
        self.assertEqual(resolve_mode([" com.example.app = Excluded # hand edited"], app, app), "excluded")

    def test_modes_select_independent_capabilities(self):
        app = "com.example.app"
        flags = {mode: resolve_policy(app, app, auto=[app], modes=[f"{app}={mode}"])[3]
                 for mode in ("full", "properties", "build", "observe")}
        self.assertEqual(flags, {"full": SPOOF_PROPERTIES | SPOOF_BUILD_FIELDS,
                                 "properties": SPOOF_PROPERTIES,
                                 "build": SPOOF_BUILD_FIELDS,
                                 "observe": OBSERVE_PROPERTIES})
        # Build-only installs no JNI hook, so the native side may unload the library.
        self.assertFalse(needs_property_hooks(flags["build"]))
        self.assertTrue(needs_property_hooks(flags["observe"]))

    def test_inherit_follows_options_and_reports_empty_capabilities(self):
        app = "com.example.app"
        options = dict(DEFAULT_OPTIONS, spoof_properties=False)
        self.assertEqual(resolve_policy(app, app, auto=[app], options=options)[3], SPOOF_BUILD_FIELDS)
        # An explicit package mode is not narrowed by the global switches.
        self.assertEqual(resolve_policy(app, app, auto=[app], modes=[app + "=full"], options=options)[3],
                         SPOOF_PROPERTIES | SPOOF_BUILD_FIELDS)
        nothing = {key: False for key in DEFAULT_OPTIONS}
        self.assertEqual(resolve_policy(app, app, auto=[app], options=nothing),
                         (False, "no_capabilities", "options", 0))

    def test_model_tables_match_native_and_cli(self):
        self.assertEqual(native_string_table("kModeNames"), MODE_NAMES)
        self.assertEqual(native_string_table("kReasonNames"), REASON_NAMES)
        cli = (ROOT / "module/bin/mipushctl").read_text(encoding="utf-8")
        self.assertIn("    " + "|".join(MODE_NAMES) + ") return 0 ;;", cli)
        defaults = (ROOT / "module/defaults/package_modes.conf").read_text(encoding="utf-8")
        for mode in MODE_NAMES:
            self.assertRegex(defaults, rf"(?m)^#   {mode}\b")
        self.assertFalse([line for line in defaults.splitlines() if line and not line.startswith("#")])


if __name__ == "__main__":
    unittest.main()
