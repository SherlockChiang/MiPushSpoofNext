#!/usr/bin/env python3
import pathlib
import re
import sys


ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
ALLOWED_BUILD_FIELDS = {
    "BOARD", "BOOTLOADER", "BRAND", "DEVICE", "DISPLAY", "FINGERPRINT",
    "HARDWARE", "HOST", "ID", "MANUFACTURER", "MODEL", "PRODUCT", "TAGS",
    "TYPE", "USER", "VERSION.INCREMENTAL",
}


def parse_profile(path: pathlib.Path):
    props = {}
    fields = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise AssertionError(f"{path}:{number}: expected key=value")
        key, value = (part.strip() for part in line.split("=", 1))
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise AssertionError(f"{path}:{number}: values must use printable ASCII")
        if key.startswith("prop."):
            prop = key[5:]
            if not re.fullmatch(r"[A-Za-z0-9._-]+", prop):
                raise AssertionError(f"{path}:{number}: invalid property key")
            if len(prop.encode()) >= 128 or len(value.encode()) >= 256:
                raise AssertionError(f"{path}:{number}: property entry exceeds native limit")
            props[prop] = value
        elif key.startswith("build."):
            field = key[6:]
            if field not in ALLOWED_BUILD_FIELDS:
                raise AssertionError(f"{path}:{number}: unsafe/unsupported Build field {field}")
            if len(value.encode()) >= 256:
                raise AssertionError(f"{path}:{number}: Build value exceeds native limit")
            fields[field] = value
        else:
            raise AssertionError(f"{path}:{number}: unknown profile namespace")
    if len(props) > 64 or len(fields) > 24:
        raise AssertionError(f"{path}: profile exceeds native table size")
    return props, fields


def main():
    profiles = sorted((ROOT / "module/defaults/profiles").glob("*.properties"))
    if not profiles:
        raise AssertionError("no profiles found")
    for profile in profiles:
        props, fields = parse_profile(profile)
        if not props:
            raise AssertionError(f"{profile}: no properties")
        if fields.get("BRAND") != "Xiaomi":
            raise AssertionError(f"{profile}: build.BRAND must be Xiaomi")
        if fields.get("MANUFACTURER") != "Xiaomi":
            raise AssertionError(f"{profile}: build.MANUFACTURER must be Xiaomi")
        if "SDK_INT" in fields:
            raise AssertionError(f"{profile}: build.SDK_INT is forbidden")

    module_prop = (ROOT / "module/module.prop").read_text(encoding="utf-8")
    if not re.search(r"^id=mipush-spoof-next$", module_prop, re.MULTILINE):
        raise AssertionError("module.prop: missing expected module id")
    version_match = re.search(r"^version=([A-Za-z0-9._+-]+)$", module_prop, re.MULTILINE)
    if not version_match:
        raise AssertionError("module.prop: invalid or missing version")
    if not re.search(r"^versionCode=\d+$", module_prop, re.MULTILINE):
        raise AssertionError("module.prop: invalid or missing versionCode")

    for name in ("LICENSE", "NOTICE.md"):
        if (ROOT / name).read_bytes() != (ROOT / "module" / name).read_bytes():
            raise AssertionError(f"module/{name} must match the project-root copy")
    source_notice = (ROOT / "module/SOURCE.md").read_text(encoding="utf-8")
    expected_source_name = f"MiPushSpoofNext-{version_match.group(1)}-source.zip"
    if expected_source_name not in source_notice:
        raise AssertionError(f"module/SOURCE.md must name {expected_source_name}")

    for path in (ROOT / "module").rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            if data.startswith(b"\xef\xbb\xbf"):
                raise AssertionError(f"BOM is forbidden: {path}")
            if path.suffix in {".sh", ".conf", ".properties"} or path.name in {
                "mipushctl", "module.prop", "update-binary", "updater-script"
            }:
                if b"\r\n" in data:
                    raise AssertionError(f"CRLF is forbidden: {path}")
            if path.suffix == ".sh" or path.name in {"mipushctl", "update-binary"}:
                if not data.startswith(b"#!"):
                    raise AssertionError(f"executable script lacks shebang: {path}")
    print(f"validated {len(profiles)} profiles and module metadata")


if __name__ == "__main__":
    main()
