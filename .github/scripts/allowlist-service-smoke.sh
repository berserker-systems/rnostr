#!/usr/bin/env bash
# Requires root on a disposable Linux host running systemd.
set -euo pipefail

test "$(id -u)" -eq 0
systemctl is-system-running --quiet || test "$(systemctl is-system-running)" = degraded
probe=$1
unit="rnostr-allowlist-smoke-$$"
fixture=$(mktemp -d /opt/rnostr-allowlist-smoke.XXXXXX)
state="/var/lib/$unit"
unit_file="/run/systemd/system/$unit.service"
cleanup() {
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    rm -f -- "$unit_file"
    rm -rf -- "$fixture" "$state"
    systemctl daemon-reload
}
trap cleanup EXIT

getent group rnostr-policy >/dev/null || groupadd --system rnostr-policy
for account in allowlist-sync rnostr-policy-reader; do
    id "$account" >/dev/null 2>&1 || useradd --system --no-create-home --gid rnostr-policy "$account"
done

chmod 0755 "$fixture"
install -m 0755 "$probe" "$fixture/probe"
printf '%064d\n' 4 > "$fixture/recipient.nsec"
chown allowlist-sync:rnostr-policy "$fixture/recipient.nsec"
chmod 0600 "$fixture/recipient.nsec"
cp allowlist-sync.service "$unit_file"
cat >> "$unit_file" <<EOF

[Service]
Type=oneshot
Restart=no
TimeoutStartSec=30s
EnvironmentFile=
Environment=ALLOWLIST_RECIPIENT_NSEC_FILE=$fixture/recipient.nsec
ExecStart=
ExecStart=$fixture/probe --exact tests::systemd_policy_publication --ignored
StateDirectory=
StateDirectory=$unit
ReadWritePaths=
ReadWritePaths=$state
EOF
systemd-analyze verify "$unit_file"
systemctl daemon-reload
systemctl start "$unit" || { journalctl -u "$unit" --no-pager; exit 1; }

test "$(stat -c '%U:%G:%a' "$state/allowlist.json")" = allowlist-sync:rnostr-policy:640
runuser -u rnostr-policy-reader -- sh -s -- "$state/allowlist.json" "$fixture/recipient.nsec" "$state" <<'READER'
set -eu
cat "$1" >/dev/null
test ! -w "$1"
test ! -w "$3"
! cat "$2" >/dev/null 2>&1
READER
echo 'Service publication and policy/key isolation passed.'
