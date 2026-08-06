#!/system/bin/sh

# Consumed by the module installer after this script is sourced.
# shellcheck disable=SC2034
SKIPUNZIP=0
STATE=/data/adb/mipush-spoof-next
umask 077

ui_print "*******************************"
ui_print "       MiPush Spoof Next       "
ui_print "*******************************"

DEVICE_API=${API:-$(getprop ro.build.version.sdk 2>/dev/null)}
case "$DEVICE_API" in
  ''|*[!0-9]*) abort "Unable to determine the Android API level." ;;
esac
[ "$DEVICE_API" -ge 26 ] || abort "Android 8.0 (API 26) or newer is required."

if [ "${KSU:-false}" != "true" ] && [ "${APATCH:-false}" != "true" ] && \
   [ "${MAGISK_VER_CODE:-0}" -gt 0 ] && [ "$MAGISK_VER_CODE" -lt 26000 ]; then
  abort "Magisk 26.0+ is required (Zygisk API v4)."
fi

case "${ARCH:-}" in
  arm|arm64|x86|x64|'') ;;
  *) abort "Unsupported architecture: $ARCH" ;;
esac

mkdir -p "$STATE/profiles" "$STATE/logs" || abort "Cannot create configuration directory."
chmod 0700 "$STATE" "$STATE/profiles" "$STATE/logs" || abort "Cannot secure configuration directory."

for profile in "$MODPATH"/defaults/profiles/*.properties; do
  [ -f "$profile" ] || continue
  target="$STATE/profiles/${profile##*/}"
  if [ ! -f "$target" ]; then
    cp -f "$profile" "$target" || abort "Cannot install profile ${profile##*/}."
  fi
done

if [ ! -f "$STATE/options.conf" ]; then
  cp -f "$MODPATH/defaults/options.conf" "$STATE/options.conf" || abort "Cannot initialize options."
fi
if [ ! -f "$STATE/profile.properties" ]; then
  cp -f "$STATE/profiles/miui14.properties" "$STATE/profile.properties" || abort "Cannot activate default profile."
fi
if [ ! -f "$STATE/packages.txt" ]; then
  cp -f "$MODPATH/defaults/packages.txt" "$STATE/packages.txt" || abort "Cannot initialize package rules."
fi
if [ ! -f "$STATE/packages.auto.txt" ]; then
  : > "$STATE/packages.auto.txt" || abort "Cannot initialize automatic package rules."
fi

chmod 0600 "$STATE/options.conf" "$STATE/profile.properties" \
  "$STATE/packages.txt" "$STATE/packages.auto.txt" "$STATE/profiles"/*.properties || \
  abort "Cannot secure configuration files."
chown -R 0:0 "$STATE" || abort "Cannot set configuration ownership."

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755

if [ "${KSU:-false}" = "true" ]; then
  ui_print "- KernelSU detected; enable a compatible external Zygisk provider."
elif [ "${APATCH:-false}" = "true" ]; then
  ui_print "- APatch detected; enable a compatible external Zygisk provider."
elif [ "${ZYGISK_ENABLED:-0}" != "1" ]; then
  ui_print "! Magisk Zygisk is not currently reported as enabled."
  ui_print "! Enable it before rebooting."
fi

ui_print "- Configuration: $STATE"
ui_print "- Use the module action button to scan installed MiPush apps."
ui_print "- Reboot after installation, then force-stop target apps."
