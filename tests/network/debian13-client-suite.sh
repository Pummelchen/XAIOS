#!/bin/bash
set -euo pipefail

host="${1:-host.docker.internal}"
ssh_port="${2:-2222}"
udp_port="${3:-2223}"
expected_arch="${4:-aarch64}"
password="${XAIOS_SSH_PASSWORD:-admin}"
authorized_key="${XAIOS_SSH_AUTHORIZED_KEY:-/keys/authorized}"
unauthorized_key="${XAIOS_SSH_UNAUTHORIZED_KEY:-/keys/unauthorized}"
workdir="$(mktemp -d)"
holder_pids=()

cleanup() {
  for pid in "${holder_pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

ssh_options=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=36
  -p "$ssh_port"
)
key_ssh_options=(
  -i "$authorized_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=publickey
  -o PasswordAuthentication=no
  -o ConnectTimeout=20
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=5
  -p "$ssh_port"
)
sftp_options=(
  -i "$authorized_key"
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=publickey
  -o PasswordAuthentication=no
  -o ConnectTimeout=20
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=5
  -P "$ssh_port"
)

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

run_ssh() {
  ssh "${key_ssh_options[@]}" "admin@$host" "$@"
}

run_password_ssh() {
  sshpass -p "$password" ssh "${ssh_options[@]}" "admin@$host" "$@"
}

printf 'Debian client: '
. /etc/os-release
printf '%s %s (%s)\n' "$PRETTY_NAME" "$(dpkg --print-architecture)" "$(ssh -V 2>&1)"

public_key_output="$(ssh \
  -i "$authorized_key" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o ConnectTimeout=20 \
  -p "$ssh_port" \
  "admin@$host" 'echo public-key-auth-ok')"
test "$public_key_output" = "public-key-auth-ok" \
  || fail "authorized Ed25519 key returned '$public_key_output'"
printf 'PASS: standard OpenSSH Ed25519 public-key authentication\n'

if ssh \
    -i "$unauthorized_key" \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o ConnectTimeout=20 \
    -p "$ssh_port" \
    "admin@$host" 'echo unauthorized-key-must-not-run' \
    >"$workdir/unauthorized-key.stdout" \
    2>"$workdir/unauthorized-key.stderr"; then
  fail "unauthorized Ed25519 key was accepted"
fi
printf 'PASS: unauthorized Ed25519 key rejected\n'

auth_output="$(run_password_ssh 'echo docker-auth-ok')"
test "$auth_output" = "docker-auth-ok" || fail "correct-password SSH command returned '$auth_output'"
printf 'PASS: correct SSH password accepted\n'

if sshpass -p 'definitely-wrong-password' ssh "${ssh_options[@]}" \
    "admin@$host" 'echo authentication-must-not-run' \
    >"$workdir/wrong-password.stdout" 2>"$workdir/wrong-password.stderr"; then
  fail "wrong SSH password was accepted"
fi
if grep -q 'authentication-must-not-run' "$workdir/wrong-password.stdout"; then
  fail "wrong-password command reached the server"
fi
printf 'PASS: wrong SSH password rejected\n'

if ! printf 'pwd\rcd /tmp\rpwd\rexit\r' | \
    ssh -tt "${key_ssh_options[@]}" "admin@$host" \
      >"$workdir/interactive-shell.ansi" 2>"$workdir/interactive-shell.err"; then
  cat "$workdir/interactive-shell.err" >&2
  fail "interactive SSH shell failed"
fi
python3 - "$workdir/interactive-shell.ansi" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_bytes()
visible = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", text).replace(b"\r", b"")
if b"admin@xaios:/$ " not in visible or b"admin@xaios:/tmp$ " not in visible:
    raise SystemExit(f"cwd-aware prompts missing from interactive shell: {visible!r}")
PY
printf 'PASS: interactive SSH shell line editing and cwd-aware prompt\n'

run_ssh 'mkdir /tmp/tree-source'
run_ssh 'mkdir /tmp/tree-source/nested'
run_ssh 'write /tmp/tree-source/nested/value.txt recursive-tree-ok'
run_ssh 'mv /tmp/tree-source /tmp/tree-renamed'
test "$(run_ssh 'cat /tmp/tree-renamed/nested/value.txt')" = "recursive-tree-ok" \
  || fail "renamed directory tree lost file content"
run_ssh 'rm -r /tmp/tree-renamed'
if run_ssh 'stat /tmp/tree-renamed' >"$workdir/tree-stat.out" 2>&1; then
  fail "recursive removal left the directory tree present"
fi
printf 'PASS: recursive directory rename and removal\n'

if ! printf 'first\r\nsecond\033[H\033[3~\033[F!\017\030' | \
    ssh -tt "${key_ssh_options[@]}" "admin@$host" \
      'nano /tmp/interactive-nano.txt' \
      >"$workdir/nano.ansi" 2>"$workdir/nano.err"; then
  cat "$workdir/nano.err" >&2
  fail "interactive nano session failed"
fi
grep -Fq $'\033[?1049h' "$workdir/nano.ansi" \
  || fail "nano did not enter the alternate terminal screen"
test "$(run_ssh 'cat /tmp/interactive-nano.txt')" = "first
econd!" || fail "nano did not preserve CRLF or Home/Delete/End editing"
run_ssh 'rm /tmp/interactive-nano.txt'
printf 'PASS: interactive nano edit, save, and exit\n'

if run_ssh 'definitely-not-an-app' >"$workdir/not-found.out" 2>&1; then
  fail "unknown command returned success"
fi
grep -q '^xaios: definitely-not-an-app: command not found$' \
  "$workdir/not-found.out" || fail "unknown command error is not Unix-like"
printf 'PASS: unknown command reports command-not-found and nonzero status\n'

run_ssh 'xaiosctl version --json --node local --timeout 5s' \
  >"$workdir/xaiosctl-version.json"
run_ssh 'xaiosctl status --json' >"$workdir/xaiosctl-status.json"
run_ssh 'xaiosctl capabilities --json' \
  >"$workdir/xaiosctl-capabilities.json"
run_ssh 'xaiosctl hardware --json' >"$workdir/xaiosctl-hardware.json"
run_ssh 'xaiosctl metrics --json' >"$workdir/xaiosctl-metrics.json"
run_ssh 'xaiosctl logs --json --since 0 --limit 2' \
  >"$workdir/xaiosctl-logs.json"
run_ssh 'xaiosctl storage device list --json' \
  >"$workdir/xaiosctl-storage-devices.json"
run_ssh 'xaiosctl storage device show /dev/vblk4 --json' \
  >"$workdir/xaiosctl-storage-device.json"
run_ssh 'xaiosctl storage filesystem list --json' \
  >"$workdir/xaiosctl-storage-filesystems.json"
run_ssh 'xaiosctl storage usage /models --json' \
  >"$workdir/xaiosctl-storage-usage.json"
if run_ssh 'xaiosctl health --json' >"$workdir/xaiosctl-health.json"; then
  fail "xaiosctl health reported ready before production inference exists"
else
  health_status=$?
fi
test "$health_status" -eq 1 \
  || fail "xaiosctl health returned SSH status $health_status instead of 1"
if run_ssh 'xaiosctl unsupported --json' \
    >"$workdir/xaiosctl-error.json"; then
  fail "unsupported xaiosctl operation returned success"
fi

python3 - "$workdir" "$expected_arch" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected_arch = sys.argv[2]


def load(name):
    value = json.loads((root / f"xaiosctl-{name}.json").read_text())
    if list(value) != ["schema_version", "request_id", "status", "data"]:
        raise SystemExit(f"{name}: unstable JSON envelope keys: {list(value)}")
    if value["schema_version"] != 1 or value["status"] != "ok":
        raise SystemExit(f"{name}: invalid JSON envelope: {value}")
    if not value["request_id"].isdigit():
        raise SystemExit(f"{name}: request ID is not a decimal string")
    return value["data"]


version = load("version")
if version["control_protocol_version"] != 1:
    raise SystemExit("version: unexpected control protocol version")
if version["kernel_abi_version"] != 1 or version["model_package_version"] != 2:
    raise SystemExit("version: unexpected kernel/model ABI versions")
if len(version["git_commit"]) != 40:
    raise SystemExit(
        f"version: expected 40-character source revision, got "
        f"{version['git_commit']!r}"
    )
if version["architecture"] != expected_arch:
    raise SystemExit(
        f"version: expected {expected_arch} image, got {version['architecture']}"
    )
if version["build_identifier"] not in (
    "xaios-admin-control", "xaios-admin-control-dirty"
):
    raise SystemExit("version: build identifier does not disclose source state")
if version["model_volume_version"] != 1:
    raise SystemExit("version: ModelFS volume version must be 1")

status = load("status")
for field in ("uptime_ns", "online_cpus", "physical_pages", "managed_pages", "free_pages"):
    if not isinstance(status[field], int) or status[field] <= 0:
        raise SystemExit(f"status: {field} is not measured")
if status["queue_depth"] is not None or status["active_requests"] is not None:
    raise SystemExit("status: unavailable inference queue values must be null")
if status["readiness"] != "degraded" or status["model"] != "fixture-only":
    raise SystemExit("status: fixture-only readiness was overstated")

capabilities = load("capabilities")
if capabilities["ssh"] != "available" or capabilities["sftp"] != "available":
    raise SystemExit("capabilities: SSH/SFTP not reported available")
if capabilities["model_v2"] != "interface-only":
    raise SystemExit("capabilities: model-v2 status was overstated")
if capabilities["real_model_inference"] != "unsupported":
    raise SystemExit("capabilities: real inference status was overstated")

hardware = load("hardware")
if hardware["core_count"] <= 0 or hardware["free_pages"] <= 0:
    raise SystemExit("hardware: discovered CPU/memory values are invalid")
if hardware["cpu_vendor"] != "unknown" or hardware["avx2"] != "unknown":
    raise SystemExit("hardware: undiscovered CPU/ISA values must be unknown")

metrics = load("metrics")
if metrics["control_requests"] <= 0 or metrics["network_rx_packets"] <= 0:
    raise SystemExit("metrics: measured control/network counters are invalid")
if metrics["tokens_generated"] is not None:
    raise SystemExit("metrics: unavailable token count must be null")

logs = load("logs")
if logs["record_count"] > 2 or logs["next_cursor"] < logs["start_cursor"]:
    raise SystemExit("logs: cursor or limit contract violated")
if not isinstance(logs["records"], str):
    raise SystemExit("logs: records must be a bounded string")

devices = load("storage-devices")
if devices["record_count"] > devices["total_count"] or devices["truncated"] not in (0, 1):
    raise SystemExit("storage devices: invalid bounded-list metadata")
model_devices = [
    device for device in devices["devices"]
    if device["identifier"] == "/dev/vblk4"
]
if len(model_devices) != 1:
    raise SystemExit("storage devices: /dev/vblk4 is absent or duplicated")

device = load("storage-device")
if len(device["devices"]) != 1:
    raise SystemExit("storage device: exact lookup did not return one record")
device = device["devices"][0]
if (device["identifier"] != "/dev/vblk4" or
        device["logical_sector_size"] != 512 or
        device["capacity_bytes"] <= 0 or
        device["capacity_logical_sectors"] * 512 != device["capacity_bytes"] or
        device["read_only"] != 0):
    raise SystemExit("storage device: invalid ModelFS device geometry")

filesystems = load("storage-filesystems")
mounts = {record["mount_path"]: record for record in filesystems["filesystems"]}
if mounts.get("/", {}).get("filesystem") != "MutableFS":
    raise SystemExit("storage filesystems: MutableFS root is absent")
if (mounts.get("/models", {}).get("filesystem") != "ModelFS" or
        mounts["/models"]["device_identifier"] != "/dev/vblk4" or
        mounts["/models"]["staging_writable"] != 1):
    raise SystemExit("storage filesystems: ModelFS mount identity/policy is invalid")

usage = load("storage-usage")
if len(usage["filesystems"]) != 1:
    raise SystemExit("storage usage: exact lookup did not return one record")
usage = usage["filesystems"][0]
if (usage["mount_path"] != "/models" or usage["format_version"] != 1 or
        usage["allocated_bytes"] > usage["total_bytes"] or
        usage["free_bytes"] > usage["total_bytes"]):
    raise SystemExit("storage usage: invalid ModelFS accounting")

health = load("health")
if health["overall"] != "degraded" or health["fatal"] != 0:
    raise SystemExit("health: nonfatal fixture-only state must be degraded")

error = json.loads((root / "xaiosctl-error.json").read_text())
if list(error) != ["schema_version", "request_id", "status", "data", "error"]:
    raise SystemExit("error: unstable JSON envelope")
if (error["status"] != "error" or error["data"] is not None or
        error["error"]["code"] != "unknown_operation"):
    raise SystemExit("error: unsupported operation did not return stable code")
PY
printf 'PASS: xaiosctl typed control and storage inventory over SSH\n'

python3 - "$workdir/sftp-source.bin" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_bytes(bytes((index * 37 + 11) & 0xff for index in range(8170)))
PY

if ! {
  {
    printf 'put %s /tmp/docker-sftp.bin\n' "$workdir/sftp-source.bin"
    printf 'ls -l /tmp/docker-sftp.bin\n'
    printf 'get /tmp/docker-sftp.bin %s\n' "$workdir/sftp-result.bin"
    printf 'rm /tmp/docker-sftp.bin\n'
    printf 'mkdir /tmp/docker-sftp-dir\n'
    printf 'put %s /tmp/docker-sftp-dir/original.bin\n' "$workdir/sftp-source.bin"
    printf 'ls -l /tmp/docker-sftp-dir\n'
    printf 'rename /tmp/docker-sftp-dir/original.bin /tmp/docker-sftp-dir/renamed.bin\n'
    printf 'get /tmp/docker-sftp-dir/renamed.bin %s\n' "$workdir/sftp-renamed.bin"
    printf 'rm /tmp/docker-sftp-dir/renamed.bin\n'
    printf 'rmdir /tmp/docker-sftp-dir\n'
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - "admin@$host" \
      >"$workdir/sftp.log" 2>&1
}; then
  cat "$workdir/sftp.log" >&2
  fail "SFTP client exited unsuccessfully"
fi
cmp "$workdir/sftp-source.bin" "$workdir/sftp-result.bin" \
  || fail "SFTP round-trip payload differs"
cmp "$workdir/sftp-source.bin" "$workdir/sftp-renamed.bin" \
  || fail "SFTP renamed file payload differs"
grep -Eq -- '[[:space:]]8170[[:space:]]+.*/tmp/docker-sftp.bin' "$workdir/sftp.log" \
  || fail "SFTP stat output did not report the 8170-byte file"
grep -q 'original.bin' "$workdir/sftp.log" \
  || fail "SFTP directory listing omitted the uploaded file"
printf 'PASS: SFTP file and directory read/write/stat/list/rename/remove round trip\n'

if ! {
  {
    printf 'put %s /tmp/docker-sftp-rekey.bin\n' "$workdir/sftp-source.bin"
    printf 'get /tmp/docker-sftp-rekey.bin %s\n' "$workdir/sftp-rekey.bin"
    printf 'rm /tmp/docker-sftp-rekey.bin\n'
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - -o RekeyLimit=4K "admin@$host" \
      >"$workdir/sftp-rekey.log" 2>&1
}; then
  cat "$workdir/sftp-rekey.log" >&2
  fail "SFTP transfer across an OpenSSH-forced rekey failed"
fi
cmp "$workdir/sftp-source.bin" "$workdir/sftp-rekey.bin" \
  || fail "SFTP payload changed across rekey"
printf 'PASS: client-initiated SSH rekey preserved SFTP transfer\n'

python3 - "$workdir" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for index, size in ((1, 2049), (2, 3073)):
    (root / f"parallel-{index}.bin").write_bytes(
        bytes((offset * (index + 17) + index) & 0xff for offset in range(size))
    )
PY
for index in 1 2; do
  (
    {
      printf 'put %s /tmp/docker-sftp-%s.bin\n' \
        "$workdir/parallel-$index.bin" "$index"
      sleep 6
      printf 'ls -l /tmp/docker-sftp-%s.bin\n' "$index"
      printf 'get /tmp/docker-sftp-%s.bin %s\n' \
        "$index" "$workdir/parallel-result-$index.bin"
      printf 'rm /tmp/docker-sftp-%s.bin\n' "$index"
      printf 'quit\n'
    } | sftp "${sftp_options[@]}" -b - "admin@$host" \
        >"$workdir/parallel-sftp-$index.log" 2>&1
  ) &
  holder_pids+=("$!")
done
sleep 3
for pid in "${holder_pids[@]}"; do
  kill -0 "$pid" 2>/dev/null || fail "parallel SFTP session exited early"
done
parallel_output="$(run_ssh 'echo parallel-sftp-isolated')"
test "$parallel_output" = "parallel-sftp-isolated" \
  || fail "SSH command failed while two SFTP sessions were active"
for pid in "${holder_pids[@]}"; do
  if ! wait "$pid"; then
    cat "$workdir"/parallel-sftp-*.log >&2
    fail "parallel SFTP client failed"
  fi
done
holder_pids=()
for index in 1 2; do
  cmp "$workdir/parallel-$index.bin" \
      "$workdir/parallel-result-$index.bin" \
    || fail "parallel SFTP payload $index differs"
done
printf 'PASS: two overlapping SFTP sessions retained isolated handles\n'

control_socket="$workdir/control-master.sock"
ssh "${key_ssh_options[@]}" -M -S "$control_socket" -N "admin@$host" \
  >"$workdir/control-master.log" 2>&1 &
master_pid="$!"
for _ in $(seq 1 60); do
  test -S "$control_socket" && break
  kill -0 "$master_pid" 2>/dev/null || fail "SSH control master exited early"
  sleep 1
done
test -S "$control_socket" || fail "SSH control socket was not created"
{
  {
    printf 'pwd\n'
    sleep 6
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - -o ControlPath="$control_socket" \
      "admin@$host" >"$workdir/control-sftp.log" 2>&1
} &
control_sftp_pid="$!"
sleep 2
control_output="$(ssh "${key_ssh_options[@]}" \
  -o ControlPath="$control_socket" "admin@$host" \
  'echo shared-transport-ok')"
test "$control_output" = "shared-transport-ok" \
  || fail "second channel on shared SSH transport failed"
wait "$control_sftp_pid" || {
  cat "$workdir/control-sftp.log" >&2
  fail "SFTP channel on shared SSH transport failed"
}
ssh "${key_ssh_options[@]}" -S "$control_socket" -O exit \
  "admin@$host" >/dev/null 2>&1 || true
wait "$master_pid" 2>/dev/null || true
printf 'PASS: exec and SFTP channels shared one SSH transport\n'

for index in 1 2 3; do
  ssh "${key_ssh_options[@]}" -N "admin@$host" \
    >"$workdir/holder-$index.log" 2>&1 &
  holder_pids+=("$!")
done
sleep 8
for pid in "${holder_pids[@]}"; do
  kill -0 "$pid" 2>/dev/null || fail "concurrent SSH holder exited early"
done
concurrent_output="$(run_ssh 'echo four-sessions-ok')"
test "$concurrent_output" = "four-sessions-ok" \
  || fail "fourth simultaneous SSH session failed"
printf 'PASS: four simultaneous SSH connections\n'
for pid in "${holder_pids[@]}"; do
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done
holder_pids=()
sleep 2

for index in $(seq 1 20); do
  if ! reconnect_output="$(ssh -vvv \
      "${key_ssh_options[@]}" "admin@$host" \
      "echo reconnect-$index" 2>"$workdir/reconnect-$index.log")"; then
    cat "$workdir/reconnect-$index.log" >&2
    fail "SSH reconnect $index failed"
  fi
  test "$reconnect_output" = "reconnect-$index" \
    || fail "SSH reconnect $index returned '$reconnect_output'"
done
printf 'PASS: 20 sequential SSH reconnects recycled connection state\n'

python3 - "$host" "$udp_port" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
payload = b"xaios-docker-udp-payload"
address = socket.gethostbyname(host)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(10.0)
    client.sendto(payload, (address, port))
    response, peer = client.recvfrom(4096)
if response != payload:
    raise SystemExit(f"UDP payload mismatch from {peer}: {response!r}")
print(f"PASS: UDP echo payload bytes={len(payload)} peer={peer[0]}:{peer[1]}")
PY

printf 'PASS: Debian 13 SSH, SFTP, concurrency, reconnect, and UDP suite complete\n'
