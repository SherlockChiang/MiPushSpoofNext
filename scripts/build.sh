#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

if [[ -z "$NDK" || ! -x "$NDK/ndk-build" ]]; then
  echo "Android NDK not found. Set ANDROID_NDK_HOME." >&2
  exit 2
fi

python3 "$ROOT/scripts/lint_project.py" "$ROOT"
python3 -m unittest discover -s "$ROOT/tests" -p 'test_*.py' -v

OUT="$ROOT/out"
mkdir -p "$ROOT/build" "$OUT"
WORK="$(mktemp -d "$ROOT/build/package.XXXXXXXX")"
STAGE="$WORK/module"
NATIVE_OBJ="$WORK/obj"
NATIVE_LIBS="$WORK/libs"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$STAGE/zygisk"

VERSION="$(sed -n 's/^version=//p' "$ROOT/module/module.prop")"
if [[ ! "$VERSION" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "module.prop must contain exactly one safe version value." >&2
  exit 2
fi

"$NDK/ndk-build" -C "$ROOT/native" \
  NDK_PROJECT_PATH=. \
  APP_BUILD_SCRIPT=jni/Android.mk \
  NDK_APPLICATION_MK=jni/Application.mk \
  "NDK_OUT=$NATIVE_OBJ" \
  "NDK_LIBS_OUT=$NATIVE_LIBS"

cp -a "$ROOT/module/." "$STAGE/"

cp "$NATIVE_LIBS/armeabi-v7a/libmipushspoofnext.so" "$STAGE/zygisk/armeabi-v7a.so"
cp "$NATIVE_LIBS/arm64-v8a/libmipushspoofnext.so" "$STAGE/zygisk/arm64-v8a.so"
cp "$NATIVE_LIBS/x86/libmipushspoofnext.so" "$STAGE/zygisk/x86.so"
cp "$NATIVE_LIBS/x86_64/libmipushspoofnext.so" "$STAGE/zygisk/x86_64.so"

ZIP="$OUT/MiPushSpoofNext-$VERSION.zip"
SOURCE_ZIP="$OUT/MiPushSpoofNext-$VERSION-source.zip"
TEMP_ZIP="$WORK/MiPushSpoofNext-$VERSION.zip"
TEMP_SOURCE_ZIP="$WORK/MiPushSpoofNext-$VERSION-source.zip"
(cd "$STAGE" && zip -qr "$TEMP_ZIP" .)

LLVM_PREBUILT=("$NDK"/toolchains/llvm/prebuilt/*)
LLVM_BIN="${LLVM_PREBUILT[0]}/bin"
python3 "$ROOT/scripts/verify_zip.py" "$TEMP_ZIP" \
  --module-dir "$ROOT/module" \
  --native-libs-dir "$NATIVE_LIBS" \
  --llvm-bin "$LLVM_BIN"
python3 "$ROOT/scripts/package_source.py" "$ROOT" "$TEMP_SOURCE_ZIP"

mv -f "$TEMP_ZIP" "$ZIP"
mv -f "$TEMP_SOURCE_ZIP" "$SOURCE_ZIP"
echo "Built: $ZIP"
echo "Built: $SOURCE_ZIP"
