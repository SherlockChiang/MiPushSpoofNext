#!/system/bin/sh

SCRIPT_DIR=${0%/*}
if [ "${MPSN_ASH_STANDALONE:-0}" != "1" ]; then
  exec "$SCRIPT_DIR/mipushctl" scan
fi

STATE=/data/adb/mipush-spoof-next
OUTPUT="$STATE/packages.auto.txt"
LOG="$STATE/logs/scan.log"
LOCK="$STATE/.scan.lock"
TMP=
PUBLISH_TMP=
LOCK_HELD=0
LOCK_TOKEN=
umask 077

cleanup() {
  [ -z "$TMP" ] || rm -rf "$TMP"
  [ -z "$PUBLISH_TMP" ] || rm -f "$PUBLISH_TMP"
  rm -f "$LOG.tmp.$$"
  if [ "$LOCK_HELD" -ne 0 ] && [ -n "$LOCK_TOKEN" ] && [ -f "$LOCK/token" ]; then
    owner_token=
    read -r owner_token < "$LOCK/token"
    [ "$owner_token" = "$LOCK_TOKEN" ] && rm -rf "$LOCK"
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

fail_scan() {
  reason=$1
  {
    echo "scan_time=$(date '+%Y-%m-%dT%H:%M:%S%z')"
    echo "status=error"
    echo "reason=$reason"
    echo "previous_rules_preserved=true"
    [ -z "$TMP" ] || sed 's/^/detail=/' "$TMP/errors" 2>/dev/null
  } > "$LOG.tmp.$$" && chmod 0600 "$LOG.tmp.$$" && mv -f "$LOG.tmp.$$" "$LOG"
  echo "MiPush scan failed: $reason. Previous automatic rules were preserved." >&2
  exit 1
}

mkdir -p "$STATE/logs" || exit 1
chmod 0700 "$STATE" "$STATE/logs" || exit 1
current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if ! mkdir "$LOCK" 2>/dev/null; then
  active=0
  # A PID alone is not enough: after a reboot Android can reuse it for an
  # unrelated process while /data/adb still contains the old lock directory.
  # Give a just-created lock a moment to publish its owner before classifying it.
  [ -f "$LOCK/pid" ] || sleep 1
  if [ -f "$LOCK/pid" ]; then
    read -r lock_pid < "$LOCK/pid"
    lock_boot_id=
    [ ! -f "$LOCK/boot_id" ] || read -r lock_boot_id < "$LOCK/boot_id"
    boot_matches=1
    if [ -n "$current_boot_id" ] && [ -n "$lock_boot_id" ]; then
      [ "$lock_boot_id" = "$current_boot_id" ] || boot_matches=0
    fi
    case "$lock_pid" in
      ''|*[!0-9]*) ;;
      *)
        if [ "$boot_matches" -ne 0 ] && kill -0 "$lock_pid" 2>/dev/null && \
          tr '\000' ' ' < "/proc/$lock_pid/cmdline" 2>/dev/null | \
            grep -Fq 'scan_packages.sh'; then
          active=1
        fi
        ;;
    esac
  fi
  if [ "$active" -ne 0 ]; then
    echo "Another MiPush package scan is already running." >&2
    exit 1
  fi
  rm -rf "$LOCK" || exit 1
  mkdir "$LOCK" || exit 1
fi
LOCK_HELD=1
LOCK_TOKEN="$$.${current_boot_id:-unknown}"
echo "$LOCK_TOKEN" > "$LOCK/token" || fail_scan "cannot create scan lock token"
echo "$$" > "$LOCK/pid" || fail_scan "cannot create scan lock owner"
[ -z "$current_boot_id" ] || echo "$current_boot_id" > "$LOCK/boot_id" || \
  fail_scan "cannot record scan lock boot ID"
# Android 16 package-service commands can return a Binder transaction error when
# their stdout is redirected to the KernelSU-owned /data/adb tree. Keep the
# private transient scan workspace in /data/local/tmp and publish only the final
# 0600 result/log under the protected state directory.
TMP=$(mktemp -d /data/local/tmp/mipush-spoof-next.XXXXXXXX) || \
  fail_scan "cannot create private temporary directory under /data/local/tmp"
chmod 0700 "$TMP" || fail_scan "cannot secure temporary directory"
: > "$TMP/found" || fail_scan "cannot initialize scan result"
: > "$TMP/errors" || fail_scan "cannot initialize error log"
: > "$TMP/skipped" || fail_scan "cannot initialize skip log"

if ! command -v cmd >/dev/null 2>&1 || ! command -v pm >/dev/null 2>&1 || \
   ! command -v unzip >/dev/null 2>&1; then
  fail_scan "required cmd, pm, or BusyBox unzip command is unavailable"
fi

scan_system_apps=false
scan_deep=false
scan_max_apk_bytes=157286400
if [ -f "$STATE/options.conf" ]; then
  scan_system_apps=$(awk -F= '$1 == "scan_system_apps" { print $2; exit }' \
    "$STATE/options.conf" 2>/dev/null)
  scan_deep=$(awk -F= '$1 == "scan_deep" { print $2; exit }' \
    "$STATE/options.conf" 2>/dev/null)
  configured_max=$(awk -F= '$1 == "scan_max_apk_bytes" { print $2; exit }' \
    "$STATE/options.conf" 2>/dev/null)
  case "$configured_max" in
    ''|*[!0-9]*) ;;
    *) scan_max_apk_bytes=$configured_max ;;
  esac
fi
scan_rc=0
if [ "$scan_system_apps" = "true" ]; then
  cmd package list packages -f > "$TMP/packages" 2> "$TMP/package-list.err" || scan_rc=$?
else
  cmd package list packages -3 -f > "$TMP/packages" 2> "$TMP/package-list.err" || scan_rc=$?
fi
if [ "$scan_rc" -ne 0 ]; then
  fail_scan "package enumeration failed"
fi

scan_failed=0
scan_incomplete=0
while IFS= read -r line; do
  case "$line" in
    package:*=*) ;;
    *) continue ;;
  esac

  record=${line#package:}
  package=${record##*=}
  case "$package" in
    ''|android|android.*|com.android.*|com.google.*|com.xiaomi.xmsf|com.tencent.mm|top.trumeet.mipush|\
    com.topjohnwu.magisk|me.weishu.kernelsu|com.rifsxd.ksunext|me.bmax.apatch|org.lsposed.manager)
      continue
      ;;
  esac

  # The package manager already exposes the MiPush receiver/service names from
  # the parsed binary manifest. This is substantially cheaper than starting
  # ART for every installed app and catches split-APK integrations. Deep mode
  # remains available for apps that hide all
  # component markers and only retain SDK classes in dex.
  if command -v dumpsys >/dev/null 2>&1; then
    if ! dumpsys package "$package" > "$TMP/package-dump" 2>/dev/null; then
      echo "package_dump_failed=$package" >> "$TMP/errors"
      scan_failed=1
      continue
    fi
    grep -q -E \
      'com\.xiaomi\.mipush\.(MESSAGE_ARRIVED|RECEIVE_MESSAGE|ERROR)|com\.xiaomi\.mipush\.sdk\.|com\.xiaomi\.push\.(PING_TIMER|service\.)' \
      "$TMP/package-dump"
    component_status=$?
    if [ "$component_status" -eq 0 ]; then
      echo "$package" >> "$TMP/found"
      continue
    fi
    if [ "$component_status" -gt 1 ]; then
      echo "package_marker_scan_failed=$package" >> "$TMP/errors"
      scan_failed=1
      continue
    fi
    if [ "$scan_deep" != "true" ]; then
      echo "package_fast_scan_no_marker=$package" >> "$TMP/skipped"
      scan_incomplete=1
      continue
    fi
  fi

  if ! pm path "$package" > "$TMP/apks" 2>/dev/null || [ ! -s "$TMP/apks" ]; then
    echo "package_path_failed=$package" >> "$TMP/errors"
    scan_failed=1
    continue
  fi

  found=0
  package_failed=0
  while IFS= read -r apk_line; do
    case "$apk_line" in package:*) apk=${apk_line#package:} ;; *) continue ;; esac
    [ -f "$apk" ] || { echo "apk_missing=$package:$apk" >> "$TMP/errors"; package_failed=1; continue; }

    # Bound both the ART fast path and the optional dex decompression path.
    # dexlist reads the complete APK before emitting class names, so checking
    # the size only after invoking it can still cause a large allocation.
    apk_size=$(stat -c '%s' "$apk" 2>/dev/null) || {
      echo "apk_stat_failed=$package:$apk" >> "$TMP/errors"
      package_failed=1
      continue
    }
    case "$apk_size" in
      ''|*[!0-9]*)
        echo "apk_size_invalid=$package:$apk" >> "$TMP/errors"
        package_failed=1
        continue
        ;;
    esac
    if [ "$scan_max_apk_bytes" -ne 0 ] && [ "$apk_size" -gt "$scan_max_apk_bytes" ]; then
      echo "apk_skipped_large=$package:$apk:$apk_size" >> "$TMP/skipped"
      scan_incomplete=1
      continue
    fi

    # In deep mode ART's dexlist reads class names from an APK before the
    # compressed-dex fallback. It is optional because some older ROMs omit it.
    fast_status=1
    fast_reason=dexlist_unavailable
    if command -v dexlist >/dev/null 2>&1; then
      if dexlist "$apk" > "$TMP/dexlist" 2> "$TMP/dexlist.err"; then
        grep -q -E \
          'com\.xiaomi\.mipush\.sdk\.(MiPushClient|PushMessageHandler)|com\.xiaomi\.push\.service\.XMPushService' \
          "$TMP/dexlist"
        fast_status=$?
        if [ "$fast_status" -eq 0 ]; then
          found=1
          break
        fi
        if [ "$fast_status" -gt 1 ]; then
          echo "dexlist_marker_scan_failed=$package:$apk" >> "$TMP/errors"
          package_failed=1
          continue
        fi
        fast_reason=dexlist_no_public_marker
      else
        echo "dexlist_failed=$package:$apk" >> "$TMP/errors"
        if [ "$scan_deep" != "true" ]; then
          package_failed=1
          continue
        fi
        fast_reason=dexlist_failed_deep_fallback
      fi
    fi
    if [ "$scan_deep" != "true" ]; then
      echo "apk_deep_scan_disabled=$package:$apk:$fast_reason" >> "$TMP/skipped"
      scan_incomplete=1
      continue
    fi

    if ! unzip -l "$apk" > "$TMP/archive-list" 2>/dev/null; then
      echo "apk_list_failed=$package:$apk" >> "$TMP/errors"
      package_failed=1
      continue
    fi
    awk '$NF ~ /^classes([0-9]+)?\.dex$/ { print $NF }' "$TMP/archive-list" > "$TMP/dex" || {
      echo "dex_list_failed=$package:$apk" >> "$TMP/errors"
      package_failed=1
      continue
    }
    while IFS= read -r dex; do
      [ -n "$dex" ] || continue
      # Writing every dex to a temporary file is acceptable only in the
      # explicitly enabled deep path: it lets us
      # distinguish a corrupt/truncated ZIP from a valid dex with no marker.
      if ! unzip -p "$apk" "$dex" > "$TMP/dex-bytes" 2>/dev/null; then
        echo "dex_extract_failed=$package:$apk:$dex" >> "$TMP/errors"
        package_failed=1
        break
      fi
      grep -q -E \
        'com/xiaomi/mipush/sdk/(MiPushClient|PushMessageHandler)|com/xiaomi/push/service/XMPushService' \
        "$TMP/dex-bytes"
      grep_status=$?
      if [ "$grep_status" -eq 0 ]; then
        found=1
        break
      fi
      if [ "$grep_status" -gt 1 ]; then
        echo "dex_marker_scan_failed=$package:$apk:$dex" >> "$TMP/errors"
        package_failed=1
        break
      fi
    done < "$TMP/dex"
    [ "$found" -eq 0 ] || break
  done < "$TMP/apks"

  if [ "$package_failed" -ne 0 ]; then
    scan_failed=1
  elif [ "$found" -ne 0 ]; then
    echo "$package" >> "$TMP/found"
  fi
done < "$TMP/packages"

[ "$scan_failed" -eq 0 ] || fail_scan "one or more APKs could not be scanned"
sort -u "$TMP/found" > "$TMP/result" || fail_scan "cannot sort scan result"
# Create the replacement inode inside the protected state directory. A
# cross-directory rename from /data/local/tmp can retain the wrong SELinux
# context on some Android/provider combinations.
PUBLISH_TMP="$OUTPUT.tmp.$$"
rm -f "$PUBLISH_TMP" || fail_scan "cannot replace temporary scan result"
cat "$TMP/result" > "$PUBLISH_TMP" || fail_scan "cannot copy scan result"
chmod 0600 "$PUBLISH_TMP" || fail_scan "cannot secure scan result"
chown 0:0 "$PUBLISH_TMP" || fail_scan "cannot set scan result ownership"
mv -f "$PUBLISH_TMP" "$OUTPUT" || fail_scan "cannot publish scan result"
PUBLISH_TMP=

count=$(wc -l < "$OUTPUT" | tr -d ' ')
{
  echo "scan_time=$(date '+%Y-%m-%dT%H:%M:%S%z')"
  if [ "$scan_incomplete" -eq 0 ]; then
    echo "status=ok"
  else
    echo "status=ok_with_skips"
    skipped_count=$(wc -l < "$TMP/skipped" | tr -d ' ')
    skipped_large=$(grep -c '^apk_skipped_large=' "$TMP/skipped" 2>/dev/null || true)
    skipped_fast=$(grep -c -E '^(apk_deep_scan_disabled|package_fast_scan_no_marker)=' \
      "$TMP/skipped" 2>/dev/null || true)
    skipped_component=$(grep -c '^package_fast_scan_no_marker=' "$TMP/skipped" 2>/dev/null || true)
    echo "skipped_total=$skipped_count"
    echo "skipped_fast=$skipped_fast"
    echo "skipped_component=$skipped_component"
    echo "skipped_large=$skipped_large"
    sed 's/^/skipped=/' "$TMP/skipped"
  fi
  echo "detected=$count"
  sed 's/^/package=/' "$OUTPUT"
} > "$LOG.tmp.$$"
if ! chmod 0600 "$LOG.tmp.$$" || ! mv -f "$LOG.tmp.$$" "$LOG"; then
  rm -f "$LOG.tmp.$$"
  echo "Warning: rules were updated, but the scan log could not be published." >&2
fi

echo "Detected $count app(s) containing MiPush SDK markers:"
if [ "$count" -gt 0 ]; then
  sed 's/^/  - /' "$OUTPUT"
else
  echo "  (none)"
fi
echo "Restart listed apps after editing rules. A reboot is not required for rule changes."
if [ "$scan_incomplete" -ne 0 ]; then
  echo "Some APKs were skipped by the fast/size policy; inspect $LOG or add them manually." >&2
fi
