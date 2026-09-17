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
  -o "ConnectTimeout=$connect_timeout" \
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
    -o "ConnectTimeout=$connect_timeout" \
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

run_ssh 'rm -rf /tmp/utility-migration'
run_ssh 'mkdir -p /tmp/utility-migration/tree'
run_ssh 'write /tmp/utility-migration/input.txt alpha beta'
run_ssh 'touch /tmp/utility-migration/empty'
run_ssh 'cp /tmp/utility-migration/input.txt /tmp/utility-migration/copy.txt'
run_ssh 'mv /tmp/utility-migration/copy.txt /tmp/utility-migration/moved.txt'
run_ssh 'stat /tmp/utility-migration/moved.txt' \
  | grep -q 'Type: file' || fail 'stat utility did not inspect a regular file'
test "$(run_ssh 'cat /tmp/utility-migration/moved.txt')" = 'alpha beta' \
  || fail 'cat utility returned unexpected content'
test "$(run_ssh 'head -n 1 /tmp/utility-migration/moved.txt')" = 'alpha beta' \
  || fail 'head utility returned unexpected content'
test "$(run_ssh 'tail -n 1 /tmp/utility-migration/moved.txt')" = 'alpha beta' \
  || fail 'tail utility returned unexpected content'
run_ssh "sed 's/alpha/omega/g' /tmp/utility-migration/moved.txt" >/dev/null
run_ssh 'grep -n omega /tmp/utility-migration/moved.txt' \
  | grep -q '1:omega beta' || fail 'grep/sed utility result mismatch'
run_ssh "grep '^omega.*beta$' /tmp/utility-migration/moved.txt" \
  | grep -q '^omega beta$' || fail 'grep basic-regex compatibility regressed'
run_ssh 'find /tmp/utility-migration -name moved.txt' \
  | grep -q '/tmp/utility-migration/moved.txt' \
  || fail 'find utility omitted the migrated file'
run_ssh 'll /tmp/utility-migration' | grep -q 'moved.txt' \
  || fail 'ls alias did not dispatch to /bin/ls'

# B-10: a command that fails has to say why. The shell used to discard the
# output buffer the kernel writes its reason into and print "command failed"
# -- two words that hid a genuine cross-platform divergence until someone
# thought to look past them. Two failures are checked, because they arrive by
# different routes: one the shell refuses to dispatch at all, and one that
# dispatches and fails inside the utility. `|| true` because both are expected
# to exit non-zero; what is asserted is what they said on the way out.
unknown_output="$(run_ssh 'definitely-not-a-real-command' 2>/dev/null || true)"
printf '%s' "$unknown_output" | grep -q 'command not found' \
  || fail "an unknown command gave no reason: ${unknown_output:-<nothing>}"
denied_output="$(run_ssh 'cat /etc/shadow' 2>/dev/null || true)"
printf '%s' "$denied_output" | grep -q 'cannot read file' \
  || fail "a refused read gave no reason: ${denied_output:-<nothing>}"
for output in "$unknown_output" "$denied_output"; do
  test "$(printf '%s' "$output" | tr -d '[:space:]')" != 'commandfailed' \
    || fail 'a failure reported only "command failed", which is B-10'
done
printf 'PASS: failing commands report why they failed\n'
run_ssh 'mkdir -p /tmp/utility-migration/tar-out'
run_ssh 'tar -cf /tmp/utility-migration/files.tar /tmp/utility-migration/moved.txt'
run_ssh 'tar -tf /tmp/utility-migration/files.tar' | grep -q 'moved.txt' \
  || fail 'tar list omitted archived file'
run_ssh 'tar -xf /tmp/utility-migration/files.tar -C /tmp/utility-migration/tar-out'
test "$(run_ssh 'cat /tmp/utility-migration/tar-out/moved.txt')" = 'omega beta' \
  || fail 'tar extraction content mismatch'
run_ssh 'cpio -o -O /tmp/utility-migration/files.cpio /tmp/utility-migration/moved.txt'
run_ssh 'cpio -it -I /tmp/utility-migration/files.cpio' | grep -q 'moved.txt' \
  || fail 'cpio list omitted archived file'
run_ssh 'mkdir -p /tmp/utility-migration/cpio-out'
run_ssh 'cpio -i -I /tmp/utility-migration/files.cpio -D /tmp/utility-migration/cpio-out'
test "$(run_ssh 'cat /tmp/utility-migration/cpio-out/moved.txt')" = 'omega beta' \
  || fail 'cpio extraction content mismatch'
run_ssh 'zip -r /tmp/utility-migration/files.zip /tmp/utility-migration/tree'
run_ssh 'unzip -l /tmp/utility-migration/files.zip' | grep -q 'tree/' \
  || fail 'ZIP list omitted archived directory'
run_ssh 'mkdir -p /tmp/utility-migration/zip-out'
run_ssh 'unzip /tmp/utility-migration/files.zip -d /tmp/utility-migration/zip-out'
run_ssh 'ps -a' | grep -q 'PID PPID' || fail 'ps utility header missing'
run_ssh 'df' | grep -q 'Filesystem Size Used' || fail 'df utility header missing'
run_ssh 'df -h' | grep -q 'Filesystem Size Used' || fail 'df -h compatibility missing'
run_ssh 'du -s /tmp/utility-migration' | grep -q '/tmp/utility-migration' \
  || fail 'du utility omitted requested path'
run_ssh 'sshtest' | grep -q '^sshtest: complete$' \
  || fail 'nested standalone utility invocation failed'

mkdir -p "$workdir/archive-source"
printf 'debian archive payload\n' >"$workdir/archive-source/external.txt"
tar -cf "$workdir/debian.tar" -C "$workdir/archive-source" external.txt
gzip -c "$workdir/debian.tar" >"$workdir/debian.tar.gz"
(cd "$workdir/archive-source" && \
  printf 'external.txt\n' | cpio -o -H newc >"$workdir/debian.cpio" 2>/dev/null)
(cd "$workdir/archive-source" && zip -q "$workdir/debian.zip" external.txt)

if ! {
  {
    printf 'get /tmp/utility-migration/files.tar %s\n' "$workdir/xaios.tar"
    printf 'get /tmp/utility-migration/files.cpio %s\n' "$workdir/xaios.cpio"
    printf 'get /tmp/utility-migration/files.zip %s\n' "$workdir/xaios.zip"
    printf 'put %s /tmp/utility-migration/debian.tar\n' "$workdir/debian.tar"
    printf 'put %s /tmp/utility-migration/debian.tar.gz\n' "$workdir/debian.tar.gz"
    printf 'put %s /tmp/utility-migration/debian.cpio\n' "$workdir/debian.cpio"
    printf 'put %s /tmp/utility-migration/debian.zip\n' "$workdir/debian.zip"
    printf 'quit\n'
  } | sftp "${sftp_options[@]}" -b - "admin@$host" \
      >"$workdir/archive-sftp.log" 2>&1
}; then
  cat "$workdir/archive-sftp.log" >&2
  fail 'archive interoperability SFTP transfer failed'
fi

tar -tf "$workdir/xaios.tar" | grep -q 'moved.txt' \
  || fail 'Debian tar rejected the XAIOS ustar archive'
cpio -it <"$workdir/xaios.cpio" 2>/dev/null | grep -q 'moved.txt' \
  || fail 'Debian cpio rejected the XAIOS newc archive'
unzip -tq "$workdir/xaios.zip" >/dev/null \
  || fail 'Debian unzip rejected the XAIOS ZIP archive'

run_ssh 'mkdir -p /tmp/utility-migration/debian-tar /tmp/utility-migration/debian-gzip /tmp/utility-migration/debian-cpio /tmp/utility-migration/debian-zip'
run_ssh 'tar -xf /tmp/utility-migration/debian.tar -C /tmp/utility-migration/debian-tar'
run_ssh 'tar -xf /tmp/utility-migration/debian.tar.gz -C /tmp/utility-migration/debian-gzip'
run_ssh 'cpio -i -I /tmp/utility-migration/debian.cpio -D /tmp/utility-migration/debian-cpio'
run_ssh 'unzip /tmp/utility-migration/debian.zip -d /tmp/utility-migration/debian-zip'
for directory in debian-tar debian-gzip debian-cpio debian-zip; do
  test "$(run_ssh "cat /tmp/utility-migration/$directory/external.txt")" = \
    'debian archive payload' \
    || fail "XAIOS could not extract the Debian $directory archive"
done
printf 'PASS: Debian and XAIOS tar, gzip-tar, newc, and ZIP interoperability\n'

run_ssh 'rm -rf /tmp/utility-migration'
printf 'PASS: 23 standalone file, text, archive, and observability utilities\n'

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
if version["control_protocol_version"] != 2:
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
if version["xai_fs_version"] != 1:
    raise SystemExit("version: xaiFS volume version must be 1")

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
    raise SystemExit("storage device: invalid xaiFS device geometry")

filesystems = load("storage-filesystems")
mounts = {record["mount_path"]: record for record in filesystems["filesystems"]}
if mounts.get("/", {}).get("filesystem") != "xaibootFS":
    raise SystemExit("storage filesystems: xaibootFS root is absent")
if (mounts.get("/models", {}).get("filesystem") != "xaiFS" or
        mounts["/models"]["device_identifier"] != "/dev/vblk4" or
        mounts["/models"]["staging_writable"] != 1):
    raise SystemExit("storage filesystems: xaiFS mount identity/policy is invalid")

usage = load("storage-usage")
if len(usage["filesystems"]) != 1:
    raise SystemExit("storage usage: exact lookup did not return one record")
usage = usage["filesystems"][0]
if (usage["mount_path"] != "/models" or usage["format_version"] != 1 or
        usage["allocated_bytes"] > usage["total_bytes"] or
        usage["free_bytes"] > usage["total_bytes"]):
    raise SystemExit("storage usage: invalid xaiFS accounting")

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

