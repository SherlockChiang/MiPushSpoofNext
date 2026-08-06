import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE_HANDLE_PREFIX = 0x4D50534E00000000
FAKE_HANDLE_MASK = 0xFFFFFFFF00000000

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


def evaluate(rules, package_name, process):
    allow = False
    deny = False
    for raw in rules:
        rule = raw.split("#", 1)[0].strip()
        if not rule:
            continue
        is_deny = rule.startswith("!")
        if is_deny:
            rule = rule[1:].strip()
        if matches(rule, package_name, process):
            deny |= is_deny
            allow |= not is_deny
    return allow and not deny


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


if __name__ == "__main__":
    unittest.main()
