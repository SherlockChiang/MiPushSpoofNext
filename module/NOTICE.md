# Notices

## Zygisk public API header

`native/jni/zygisk.hpp` is copied unmodified from
`topjohnwu/zygisk-module-sample` commit
`7bb941ac8edfcffd1d23761e401c45ca95409dc1` (Zygisk API v4).
It is licensed under the 0BSD license contained in that header.

## Upstream behavior references

The project is an independent reimplementation informed by a review of:

- `yin-ol/MiPushFaker` (AGPL-3.0)
- `MiPushFramework/MiPushEnhancement` (AMTPL v1 + GPLv3)
- `tinkernels/zygisk-module-mipushfake` (no clear repository license)
- `MiPushFramework/MiPushFakeForRiru` (GPLv3)

No implementation source from those projects is included. Public class markers,
Android property names, package names, configuration behavior, and compatibility defects
were treated as factual requirements. See `docs/UPSTREAM_AUDIT.md`.

The Magisk recovery installer shim in
`module/META-INF/com/google/android/update-binary` follows the standard Magisk module
installer interface. This project as a whole is distributed under GPL-3.0-or-later.
