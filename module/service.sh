#!/system/bin/sh

MODDIR=${0%/*}
STATE=/data/adb/mipush-spoof-next
umask 077

mkdir -p "$STATE/profiles" "$STATE/logs" || exit 1
chmod 0700 "$STATE" "$STATE/profiles" "$STATE/logs" || exit 1

for profile in "$MODDIR"/defaults/profiles/*.properties; do
  [ -f "$profile" ] || continue
  target="$STATE/profiles/${profile##*/}"
  [ -f "$target" ] || cp -f "$profile" "$target" || exit 1
done

[ -f "$STATE/options.conf" ] || cp -f "$MODDIR/defaults/options.conf" "$STATE/options.conf" || exit 1
[ -f "$STATE/packages.txt" ] || cp -f "$MODDIR/defaults/packages.txt" "$STATE/packages.txt" || exit 1
[ -f "$STATE/packages.auto.txt" ] || : > "$STATE/packages.auto.txt" || exit 1
[ -f "$STATE/profile.properties" ] || \
  cp -f "$MODDIR/defaults/profiles/miui14.properties" "$STATE/profile.properties" || exit 1

chmod 0600 "$STATE/options.conf" "$STATE/profile.properties" \
  "$STATE/packages.txt" "$STATE/packages.auto.txt" "$STATE/profiles"/*.properties || exit 1
chown -R 0:0 "$STATE" || exit 1
