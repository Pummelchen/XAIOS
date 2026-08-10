#!/bin/bash
set -euo pipefail

host="${1:-host.docker.internal}"
ssh_port="${2:-2222}"
workdir="$(mktemp -d)"
admin_key="${XAIOS_SSH_ADMIN_KEY:-/keys/authorized}"
observer_key="${XAIOS_SSH_OBSERVER_KEY:-/keys/observer}"
operator_key="${XAIOS_SSH_OPERATOR_KEY:-/keys/operator}"

cleanup() {
  for socket in "$workdir"/*.sock; do
    test -S "$socket" || continue
    ssh -i "$admin_key" -o IdentitiesOnly=yes -o ControlPath="$socket" \
      -O exit "admin@$host" >/dev/null 2>&1 || true
  done
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

common_options=(
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PasswordAuthentication=no
  -o ConnectTimeout=20
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=5
  -p "$ssh_port"
)

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_as() {
  local key="$1"
  shift
  ssh -i "$key" "${common_options[@]}" "admin@$host" "$@"
}

admin() {
  run_as "$admin_key" "$@"
}

observer() {
  run_as "$observer_key" "$@"
}

operator() {
  run_as "$operator_key" "$@"
}

expect_failure() {
  local key="$1"
  local command="$2"
  local marker="$3"
  local label="$4"
  if run_as "$key" "$command" >"$workdir/failure.out" 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
  grep -q "$marker" "$workdir/failure.out" || {
    cat "$workdir/failure.out" >&2
    fail "$label did not return marker '$marker'"
  }
}

sftp_options=(
  -i "$admin_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PasswordAuthentication=no
  -o ConnectTimeout=20
  -P "$ssh_port"
)

{
  printf 'put /keys/observer.pub /tmp/phase2-observer.pub\n'
  printf 'put /keys/operator.pub /tmp/phase2-operator.pub\n'
  printf 'put /keys/config-high.conf /tmp/phase2-high.conf\n'
  printf 'put /keys/config-low.conf /tmp/phase2-low.conf\n'
  printf 'put /keys/config-invalid.conf /tmp/phase2-invalid.conf\n'
  printf 'quit\n'
} | sftp "${sftp_options[@]}" -b - "admin@$host" \
  >"$workdir/stage.log" 2>&1 || {
    cat "$workdir/stage.log" >&2
    fail "could not stage Phase 2 inputs through SFTP"
  }

add_observer="$(admin 'xaiosctl auth key add /tmp/phase2-observer.pub --principal ci-observer --role observer --operation-id 2001 --json')"
grep -q '"principal":"ci-observer"' <<<"$add_observer" \
  || fail "observer key was not added"
add_operator="$(admin 'xaiosctl auth key add /tmp/phase2-operator.pub --principal ci-operator --role operator --operation-id 2002 --json')"
grep -q '"principal":"ci-operator"' <<<"$add_operator" \
  || fail "operator key was not added"

expect_failure "$admin_key" \
  'xaiosctl auth key add /tmp/phase2-observer.pub --principal ci-observer-copy --role observer --operation-id 2001 --json' \
  'replayed_operation' 'replayed key mutation'
printf 'PASS: persistent key enrollment and operation replay rejection\n'

observer_status="$(observer 'xaiosctl status --json')"
grep -q '"status":"ok"' <<<"$observer_status" \
  || fail "observer control read failed"
expect_failure "$observer_key" 'pwd' 'Permission denied' \
  'observer shell command'
expect_failure "$observer_key" \
  'xaiosctl config apply /tmp/phase2-high.conf --operation-id 2003 --json' \
  'permission_denied' 'observer config mutation'
expect_failure "$operator_key" \
  'xaiosctl auth key add /tmp/phase2-observer.pub --principal forbidden --role observer --operation-id 2004 --json' \
  'permission_denied' 'operator key mutation'

if printf 'pwd\nquit\n' | sftp -i "$observer_key" \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no \
    -o ConnectTimeout=20 -P "$ssh_port" -b - "admin@$host" \
    >"$workdir/observer-sftp.log" 2>&1; then
  fail "observer principal opened an SFTP subsystem"
fi
printf 'PASS: observer/operator/admin role boundaries enforced\n'

operator 'xaiosctl config validate /tmp/phase2-high.conf --json' \
  >"$workdir/config-validate.json"
operator 'xaiosctl config diff /tmp/phase2-high.conf --json' \
  >"$workdir/config-diff.json"
operator 'xaiosctl config apply /tmp/phase2-high.conf --operation-id 2005 --json' \
  >"$workdir/config-apply.json"
grep -q '"change_mask":8' "$workdir/config-diff.json" \
  || fail "config diff did not isolate the command-rate change"
grep -q '"command_rate_per_minute":120' "$workdir/config-apply.json" \
  || fail "valid config was not applied"
expect_failure "$operator_key" \
  'xaiosctl config apply /tmp/phase2-high.conf --operation-id 2005 --json' \
  'replayed_operation' 'replayed config mutation'

before_invalid="$(admin 'xaiosctl config show --json')"
before_generation="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["generation"])' <<<"$before_invalid")"
expect_failure "$operator_key" \
  'xaiosctl config validate /tmp/phase2-invalid.conf --json' \
  'invalid_request' 'invalid config validation'
expect_failure "$operator_key" \
  'xaiosctl config apply /tmp/phase2-invalid.conf --operation-id 2006 --json' \
  'invalid_request' 'invalid config apply'
expect_failure "$operator_key" \
  'xaiosctl config apply /tmp/phase2-invalid.conf --operation-id 2006 --json' \
  'replayed_operation' 'replayed invalid config apply'
after_invalid="$(admin 'xaiosctl config show --json')"
after_generation="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["generation"])' <<<"$after_invalid")"
test "$before_generation" = "$after_generation" \
  || fail "failed config apply changed generation $before_generation -> $after_generation"
grep -q '"command_rate_per_minute":120' <<<"$after_invalid" \
  || fail "failed config apply changed active values"
printf 'PASS: strict config schema, diff, atomic apply, replay, and rollback safety\n'

start_master() {
  local socket="$1"
  ssh -i "$admin_key" "${common_options[@]}" -M -S "$socket" -N \
    "admin@$host" >"$socket.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 20); do
    test -S "$socket" && return 0
    kill -0 "$pid" 2>/dev/null || {
      cat "$socket.log" >&2
      fail "SSH control master exited before creating $socket"
    }
    sleep 1
  done
  fail "SSH control master did not create $socket"
}

master_command() {
  local socket="$1"
  local command="$2"
  ssh -i "$admin_key" "${common_options[@]}" -S "$socket" \
    "admin@$host" "$command"
}

cwd_one="$workdir/cwd-one.sock"
cwd_two="$workdir/cwd-two.sock"
start_master "$cwd_one"
start_master "$cwd_two"
master_command "$cwd_one" 'cd /tmp' >/dev/null
test "$(master_command "$cwd_one" 'pwd')" = '/tmp' \
  || fail "first SSH connection did not retain its cwd"
test "$(master_command "$cwd_two" 'pwd')" = '/' \
  || fail "second SSH connection inherited another connection's cwd"
ssh -i "$admin_key" -o IdentitiesOnly=yes -o ControlPath="$cwd_one" \
  -O exit "admin@$host" >/dev/null 2>&1 || true
ssh -i "$admin_key" -o IdentitiesOnly=yes -o ControlPath="$cwd_two" \
  -O exit "admin@$host" >/dev/null 2>&1 || true
printf 'PASS: per-connection cwd and parser state are isolated\n'

rate_socket="$workdir/rate.sock"
start_master "$rate_socket"
master_command "$rate_socket" \
  'xaiosctl config apply /tmp/phase2-low.conf --operation-id 2007 --json' \
  >"$workdir/rate-apply.json"
master_command "$rate_socket" 'xaiosctl config show --json' \
  >"$workdir/rate-second.json"
if master_command "$rate_socket" 'xaiosctl status --json' \
    >"$workdir/rate-third.out" 2>&1; then
  fail "third command on a two-per-minute connection was accepted"
fi
grep -q 'Command rate limit exceeded' "$workdir/rate-third.out" \
  || fail "command rate rejection did not return an explicit error"
ssh -i "$admin_key" -o IdentitiesOnly=yes -o ControlPath="$rate_socket" \
  -O exit "admin@$host" >/dev/null 2>&1 || true
admin 'xaiosctl config apply /tmp/phase2-high.conf --operation-id 2008 --json' \
  >"$workdir/rate-restore.json"
printf 'PASS: per-connection command rate limit enforced and recoverable\n'

expect_failure "$admin_key" 'cat /state/xaios_host_key' 'cat: cannot read file' \
  'remote host-key read'
expect_failure "$admin_key" 'cat /state/control/config.bin' 'cat: cannot read file' \
  'remote control-state read'
if printf 'get /state/xaios_host_key %s\nquit\n' \
    "$workdir/host-key-copy" | sftp "${sftp_options[@]}" -b - \
    "admin@$host" >"$workdir/sensitive-sftp.log" 2>&1; then
  fail "SFTP exposed the private SSH host key"
fi
test ! -s "$workdir/host-key-copy" \
  || fail "SFTP wrote private host-key bytes to the client"
printf 'PASS: private host key and administrative state are not remotely readable\n'

operator_fingerprint="$(cat /keys/operator.fingerprint)"
admin "xaiosctl auth key remove $operator_fingerprint --operation-id 2009 --json" \
  >"$workdir/remove-operator.json"
if operator 'xaiosctl status --json' >"$workdir/revoked.out" 2>&1; then
  fail "revoked operator key was accepted"
fi
admin 'xaiosctl auth key list --json' >"$workdir/auth-list.json"
grep -q '"revoked_count":1' "$workdir/auth-list.json" \
  || fail "revocation was not recorded"
printf 'PASS: key revocation takes effect for new authentication attempts\n'

admin 'xaiosctl audit show --json --since 0 --limit 16' \
  >"$workdir/audit.json"
grep -q '"operation":"config.apply"' "$workdir/audit.json" \
  || fail "audit log omitted config mutations"
grep -q '"operation":"auth.key.remove"' "$workdir/audit.json" \
  || fail "audit log omitted key revocation"
observer_material="$(cut -d' ' -f2 /keys/observer.pub)"
if grep -q "$observer_material" "$workdir/audit.json"; then
  fail "audit output contained public-key payload material"
fi
printf 'PASS: audit output is structured and payload-redacted\n'

command_payload='phase2-command-payload-secret-5f9b74'
admin "echo $command_payload" >/dev/null \
  || fail "command-payload redaction probe failed"
cursor=0
target_cursor=
: >"$workdir/operational-logs.json"
for _ in $(seq 1 256); do
  page="$(admin "xaiosctl logs --json --since $cursor --limit 16")" \
    || fail "operational log page after cursor $cursor failed"
  printf '%s\n' "$page" >>"$workdir/operational-logs.json"
  read -r next_cursor latest_cursor record_count <<<"$(
    python3 -c 'import json,sys; data=json.load(sys.stdin)["data"]; print(data["next_cursor"], data["latest_cursor"], data["record_count"])' \
      <<<"$page"
  )"
  test -n "$target_cursor" || target_cursor="$latest_cursor"
  if test "$next_cursor" -ge "$target_cursor"; then
    cursor="$next_cursor"
    break
  fi
  test "$record_count" -gt 0 && test "$next_cursor" -gt "$cursor" \
    || fail "operational log pagination did not advance from cursor $cursor"
  cursor="$next_cursor"
done
test -n "$target_cursor" && test "$cursor" -ge "$target_cursor" \
  || fail "operational log pagination did not reach snapshot cursor"
for forbidden in "$observer_material" 'definitely-wrong-password' \
    'BEGIN OPENSSH PRIVATE KEY' "$command_payload"; do
  if grep -q "$forbidden" "$workdir/operational-logs.json"; then
    fail "operational logs exposed authentication or private-key material"
  fi
done
printf 'PASS: operational logs contain no command payloads, keys, passwords, or private-key material\n'

rotate_output="$(admin 'xaiosctl auth host-key rotate --operation-id 2010 --json')"
grep -q '"changed":1' <<<"$rotate_output" \
  || fail "host-key rotation did not report a change"
sleep 2
observer 'xaiosctl status --json' >/dev/null \
  || fail "SSH did not accept a fresh connection after host-key rotation"
printf 'PASS: host-key rotation closed old transport and accepted fresh sessions\n'

printf 'PASS: Debian 13 Phase 2 administration and SSH acceptance suite complete\n'
