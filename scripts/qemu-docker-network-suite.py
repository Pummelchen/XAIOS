#!/usr/bin/env python3
"""Run the Linux/OpenSSH cross-client gate from Debian 13 against XAIOS."""

from __future__ import annotations

import json
import os
from pathlib import Path
import base64
import hashlib
import re
import shutil
import socket
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
IMAGE = "xaios-debian13-network-client:13"
TARGET_ARCH = os.environ.get("XAIOS_QEMU_NETWORK_ARCH", "aarch64")
if TARGET_ARCH not in ("aarch64", "x86_64"):
    raise SystemExit("error: XAIOS_QEMU_NETWORK_ARCH must be aarch64 or x86_64")
BUILD_TARGET = "image" if TARGET_ARCH == "aarch64" else "image-x86_64"
QEMU_RUNNER = (
    "run-qemu-aarch64.sh"
    if TARGET_ARCH == "aarch64"
    else "run-qemu-x86_64.sh"
)
ARTIFACT_SUFFIX = "" if TARGET_ARCH == "aarch64" else "-x86_64"
SSH_READY_MARKER = "SSH server: up and running (tcp/22)"
BOOT_TIMEOUT_SECONDS = 150.0
CLIENT_TIMEOUT_SECONDS = 600.0
FATAL_BOOT_MARKERS = (
    "CYAN SCREEN OF DEATH",
    "System halted. Manual reset required",
    "kernel panic",
    "assertion failed",
)


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        # QEMU user-mode host forwarding binds all host interfaces. Check the
        # same address scope so a port used outside loopback is not selected.
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])


def wait_for_marker(log_path: Path, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            log_text = log_path.read_text(errors="replace")
            if marker in log_text:
                return
            lower_log = log_text.lower()
            fatal = next(
                (item for item in FATAL_BOOT_MARKERS
                 if item.lower() in lower_log),
                None,
            )
            if fatal is not None:
                tail = "\n".join(log_text.splitlines()[-40:])
                raise RuntimeError(f"fatal guest boot marker {fatal!r}\n{tail}")
        time.sleep(0.25)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-40:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


def stop_qemu(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def start_qemu(
    name: str,
    extra_env: dict[str, str],
    persistent_path: Path | None = None,
    reset_persistent: bool = True,
) -> tuple[subprocess.Popen[bytes], object, Path, Path]:
    log_path = BUILD / f"{name}.log"
    if persistent_path is None:
        persistent_path = BUILD / f"{name}-persistent.img"
    if reset_persistent:
        persistent_path.unlink(missing_ok=True)
    log_file = log_path.open("wb")
    env = os.environ.copy()
    if TARGET_ARCH == "aarch64":
        env.update(
            {
                "XAIOS_QEMU_ACCEL": "tcg",
                "XAIOS_QEMU_SMP": "4",
                "XAIOS_PERSISTENT_IMAGE": str(persistent_path),
            }
        )
    else:
        env.update(
            {
                "XAIOS_QEMU_X86_ACCEL": "tcg",
                "XAIOS_QEMU_X86_SMP": "4",
                "XAIOS_X86_PERSISTENT_IMAGE": str(persistent_path),
            }
        )
    env.update(extra_env)
    process = subprocess.Popen(
        [str(ROOT / "scripts" / QEMU_RUNNER)],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    return process, log_file, log_path, persistent_path


def start_qemu_ready(
    name: str,
    extra_env: dict[str, str],
    marker: str,
    persistent_path: Path | None = None,
    reset_persistent: bool = True,
) -> tuple[subprocess.Popen[bytes], object, Path, Path]:
    last_error: TimeoutError | None = None
    for attempt in range(3):
        process, log_file, log_path, selected_persistent = start_qemu(
            name,
            extra_env,
            persistent_path=persistent_path,
            reset_persistent=reset_persistent and attempt == 0,
        )
        try:
            wait_for_marker(log_path, marker, BOOT_TIMEOUT_SECONDS)
            return process, log_file, log_path, selected_persistent
        except RuntimeError:
            stop_qemu(process)
            log_file.close()
            raise
        except TimeoutError as error:
            last_error = error
            stop_qemu(process)
            log_file.close()
            log_text = log_path.read_text(errors="replace")
            lower_log = log_text.lower()
            if any(marker.lower() in lower_log for marker in FATAL_BOOT_MARKERS):
                raise
            if attempt == 2:
                raise
            entered_guest = (
                "XAIOS loader starting" in log_text
                or "Loading: hardware handoff" in log_text
                or "boot-ui: progress=25" in log_text
            )
            stage = "boot-timeout" if entered_guest else "firmware"
            attempt_log = BUILD / f"{name}-{stage}-attempt-{attempt + 1}.log"
            log_path.replace(attempt_log)
            print(
                f"RETRY: QEMU did not reach {marker!r}; "
                f"saved {attempt_log}",
                flush=True,
            )
            time.sleep(1.0)
    assert last_error is not None
    raise last_error


def run_checked(
    command: list[str], timeout: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def docker_command(key_dir: Path, *command: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--interactive",
        "--add-host",
        "host.docker.internal:host-gateway",
        "--volume",
        f"{key_dir}:/keys:ro",
        IMAGE,
        *command,
    ]


def scan_host_key(key_dir: Path, port: int) -> tuple[str, str]:
    completed = subprocess.run(
        docker_command(
            key_dir,
            "ssh-keyscan",
            "-T",
            "20",
            "-t",
            "ed25519",
            "-p",
            str(port),
            "host.docker.internal",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] == "ssh-ed25519":
            return fields[1], fields[2]
    raise RuntimeError("ssh-keyscan did not return an Ed25519 host key")


def ed25519_raw_fingerprint(public_key_path: Path) -> str:
    fields = public_key_path.read_text(encoding="ascii").split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise RuntimeError(f"invalid Ed25519 public key: {public_key_path}")
    blob = base64.b64decode(fields[1], validate=True)
    if len(blob) != 51 or blob[:4] != b"\x00\x00\x00\x0b" or blob[4:15] != b"ssh-ed25519":
        raise RuntimeError(f"invalid Ed25519 key blob: {public_key_path}")
    if blob[15:19] != b"\x00\x00\x00\x20":
        raise RuntimeError(f"invalid Ed25519 key width: {public_key_path}")
    return hashlib.sha256(blob[19:51]).hexdigest()


def fnv1a64(data: bytes | bytearray) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def create_mutable_fs_v3_fixture(path: Path) -> bytes:
    sector_size = 512
    start_sector = 3072
    metadata_sectors = 32
    data_sectors = 256
    node_size = 232
    payload = (b"XAIOS MutableFS v3 migration payload\n" * 40)[:1400]
    block_count = (len(payload) + sector_size - 1) // sector_size
    metadata = bytearray(metadata_sectors * sector_size)
    struct_header = (
        b"XAIOSMFS"
        + (3).to_bytes(4, "little")
        + sector_size.to_bytes(4, "little")
        + metadata_sectors.to_bytes(4, "little")
        + (64).to_bytes(4, "little")
        + start_sector.to_bytes(8, "little")
        + (start_sector + metadata_sectors).to_bytes(8, "little")
        + (start_sector + metadata_sectors + 1).to_bytes(8, "little")
        + (start_sector + metadata_sectors + 2).to_bytes(8, "little")
        + data_sectors.to_bytes(8, "little")
        + (4).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
    )
    if len(struct_header) != 88:
        raise RuntimeError("MutableFS v3 fixture header layout drifted")
    metadata[:len(struct_header)] = struct_header
    metadata[88:88 + block_count] = b"\x01" * block_count
    nodes_offset = 88 + data_sectors

    def add_node(index: int, node_type: int, generation: int, node_path: str,
                 content: bytes = b"") -> None:
        encoded_path = node_path.encode("ascii")
        if len(encoded_path) >= 96:
            raise RuntimeError("MutableFS v3 fixture path is too long")
        node = bytearray(node_size)
        node[0:4] = (1).to_bytes(4, "little")
        node[8:12] = node_type.to_bytes(4, "little")
        node[16:24] = len(content).to_bytes(8, "little")
        node[24:32] = (fnv1a64(content) if content else 0).to_bytes(8, "little")
        node[32:40] = generation.to_bytes(8, "little")
        count = ((len(content) + sector_size - 1) // sector_size
                 if node_type == 2 else 0)
        node[64:66] = count.to_bytes(2, "little")
        for block in range(count):
            node[68 + block * 2:70 + block * 2] = block.to_bytes(2, "little")
        node[132:132 + len(encoded_path)] = encoded_path
        offset = nodes_offset + index * node_size
        metadata[offset:offset + node_size] = node

    add_node(0, 1, 1, "/")
    add_node(1, 1, 2, "/tmp")
    add_node(2, 2, 3, "/tmp/migration.txt", payload)
    checksum_data = bytearray(metadata)
    checksum_data[80:88] = b"\x00" * 8
    metadata[80:88] = fnv1a64(checksum_data).to_bytes(8, "little")

    image = bytearray(8192 * sector_size)
    metadata_offset = start_sector * sector_size
    image[metadata_offset:metadata_offset + len(metadata)] = metadata
    data_offset = (start_sector + metadata_sectors + 2) * sector_size
    image[data_offset:data_offset + len(payload)] = payload
    path.write_bytes(image)
    return payload


def verify_native_htop_pty(key_dir: Path, port: int) -> None:
    ssh_base = [
        "ssh",
        "-i", "/keys/authorized",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PasswordAuthentication=no",
        "-p", str(port),
        "admin@host.docker.internal",
    ]

    def run_guest(command: str, timeout: int = 60) -> bytes:
        completed = subprocess.run(
            docker_command(key_dir, *ssh_base, command),
            cwd=ROOT,
            capture_output=True,
            timeout=timeout,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"native command failed: {command!r}: "
                + (completed.stdout + completed.stderr).decode(errors="replace")
            )
        return completed.stdout

    transient_paths = (
        b"/bin/hello",
        b"/bin/sysinfo",
        b"/bin/lstm-xor",
        b"/bin/app-fail",
    )
    initial_processes = run_guest("htop --plain --sample-ms 10")
    unexpected = [path for path in transient_paths if path in initial_processes]
    if unexpected:
        raise RuntimeError(
            f"normal boot pre-ran transient applications: {unexpected!r}"
        )

    for command, marker in (
        ("hello", b"hello: complete"),
        ("sysinfo", b"sysinfo: complete"),
        ("lstm-xor", b"lstm-xor: complete"),
    ):
        app_output = run_guest(command, 120)
        if marker not in app_output:
            raise RuntimeError(
                f"on-demand application {command!r} lacked marker: "
                + app_output.decode(errors="replace")
            )

    failed_app = subprocess.run(
        docker_command(key_dir, *ssh_base, "app-fail"),
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    if (failed_app.returncode != 1 or
            b"app-fail: exit status 42" not in failed_app.stdout):
        raise RuntimeError(
            "intentional application failure was not reported and reaped: "
            + (failed_app.stdout + failed_app.stderr).decode(errors="replace")
        )

    final_processes = run_guest("htop --plain --sample-ms 10")
    unreaped = [path for path in transient_paths if path in final_processes]
    if unreaped:
        raise RuntimeError(f"transient applications were not reaped: {unreaped!r}")

    colored = subprocess.Popen(
        docker_command(
            key_dir,
            *ssh_base[:1],
            "-tt",
            *ssh_base[1:],
            "htop",
        ),
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    colored_stdout = bytearray()
    colored_stderr = bytearray()
    dashboard_ready = threading.Event()

    def drain(stream: object, output: bytearray, ready: bool = False) -> None:
        while True:
            chunk = stream.read1(4096)  # type: ignore[union-attr]
            if not chunk:
                return
            output.extend(chunk)
            if ready and b"[Main]" in output:
                dashboard_ready.set()

    stdout_thread = threading.Thread(
        target=drain, args=(colored.stdout, colored_stdout, True), daemon=True
    )
    stderr_thread = threading.Thread(
        target=drain, args=(colored.stderr, colored_stderr), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()
    if not dashboard_ready.wait(30):
        colored.kill()
        colored.wait(timeout=5)
        raise RuntimeError("native htop PTY did not render its initial dashboard")
    assert colored.stdin is not None
    for keys in (b"M", b"/sshd\n", b"h", b"h", b"q"):
        colored.stdin.write(keys)
        colored.stdin.flush()
        time.sleep(0.075)
    colored.stdin.close()
    returncode = colored.wait(timeout=60)
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if returncode != 0:
        raise RuntimeError(
            "native htop PTY command failed: "
            + bytes(colored_stderr).decode(errors="replace")
        )
    required = (
        b"\x1b[?1049h",
        b"\x1b[2J\x1b[H",
        b"\x1b[42;30m",
        b"Tasks:",
        b"Load average:",
        b"Uptime:",
        b"Mem",
        b"[Main]",
        b"View: ",
        b"live",
        b"Sort: ",
        b"mem",
        b"Filter: ",
        b"sshd",
        b"XAIOS htop help",
        b"60 frames/s",
        b"F10",
        b"Quit",
        b"\x1b[?25h",
        b"\x1b[?1049l",
    )
    missing = [marker for marker in required if marker not in colored_stdout]
    if missing:
        raise RuntimeError(f"native htop PTY output missing markers: {missing!r}")

    visible_output = re.sub(
        rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", bytes(colored_stdout)
    ).replace(b"\r", b"")
    if b"0 failed" not in visible_output:
        raise RuntimeError("native htop visible task status did not report zero failures")
    visible_lines = visible_output.splitlines()
    cpu_line = next(
        (line for line in visible_lines if line.lstrip().startswith(b"0[")), None
    )
    cpu_one_line = next(
        (line for line in visible_lines if line.lstrip().startswith(b"1[")), None
    )
    cpu_two_line = next(
        (line for line in visible_lines if line.lstrip().startswith(b"2[")), None
    )
    memory_line = next(
        (line for line in visible_lines if line.lstrip().startswith(b"Mem[")), None
    )
    swap_line = next(
        (line for line in visible_lines if line.lstrip().startswith(b"Swp[")), None
    )
    if (cpu_line is None or cpu_one_line is None or cpu_two_line is None or
            memory_line is None or swap_line is None):
        raise RuntimeError("native htop output lacked aligned CPU/memory/swap meters")
    bracket_columns = {
        cpu_line.index(b"["), memory_line.index(b"["), swap_line.index(b"[")
    }
    if len(bracket_columns) != 1:
        raise RuntimeError(
            f"native htop meter brackets were not aligned: {bracket_columns!r}"
        )
    left_cell_width = len(cpu_line) // 2
    if (cpu_line.find(b"Tasks:") != left_cell_width or
            cpu_one_line.find(b"Load average:") != left_cell_width or
            cpu_two_line.find(b"Uptime:") != left_cell_width):
        raise RuntimeError(
            "native htop Debian-style status rows were not in the right column"
        )
    if (len(memory_line) != len(cpu_line) or len(swap_line) != len(cpu_line) or
            memory_line[left_cell_width:].strip() or
            swap_line[left_cell_width:].strip()):
        raise RuntimeError(
            "native htop memory/swap content escaped the left CPU column: "
            f"cpu={len(cpu_line)} mem={len(memory_line)} swap={len(swap_line)}"
        )
    if b"F1Help" not in visible_output or b"F10Quit" not in visible_output:
        raise RuntimeError("native htop footer did not use segmented key labels")

    plain = subprocess.run(
        docker_command(
            key_dir,
            *ssh_base,
            "htop --all --sample-ms 10 --cpu-count 2 --plain",
        ),
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    if plain.returncode != 0:
        raise RuntimeError(
            "native htop plain command failed: "
            + plain.stderr.decode(errors="replace")
        )
    if b"\x1b[" in plain.stdout or b"CPU CPU% BUSY_MS" not in plain.stdout:
        raise RuntimeError("native htop non-PTY output did not remain plain text")
    cpu_zero = re.search(rb"(?m)^0 ([0-9]+\.[0-9])% ", plain.stdout)
    if cpu_zero is None:
        raise RuntimeError("native htop plain output lacked CPU 0 utilization")
    cpu_zero_tenths = int(cpu_zero.group(1).replace(b".", b""))
    if cpu_zero_tenths >= 1000:
        raise RuntimeError(
            "native htop sampling saturated housekeeping CPU 0: "
            + cpu_zero.group(1).decode()
            + "%"
        )

    invalid = subprocess.run(
        docker_command(
            key_dir,
            *ssh_base[:1],
            "-tt",
            *ssh_base[1:],
            "htop --sort invalid",
        ),
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    invalid_output = invalid.stdout + invalid.stderr
    if invalid.returncode == 0 or b"htop: invalid --sort key" not in invalid_output:
        raise RuntimeError("native htop PTY accepted an invalid sort key")


def require_rejected_build(env: dict[str, str], marker: str) -> None:
    completed = subprocess.run(
        ["make", BUILD_TARGET],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode == 0 or marker not in output:
        raise RuntimeError(
            f"build profile was not rejected as expected: rc={completed.returncode}\n{output}"
        )


def main() -> int:
    if shutil.which("docker") is None:
        raise SystemExit("error: Docker CLI is required")
    run_checked(["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"], 30)
    run_checked(
        [
            "docker",
            "build",
            "--pull",
            "--file",
            "tests/network/Dockerfile.debian13",
            "--tag",
            IMAGE,
            ".",
        ],
        300,
    )
    version = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "sh", "-c", ". /etc/os-release; printf '%s' \"$VERSION_ID\""],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    if not version.startswith("13"):
        raise RuntimeError(f"expected Debian 13 container, got VERSION_ID={version!r}")

    BUILD.mkdir(parents=True, exist_ok=True)
    key_dir = BUILD / "qemu-network-keys"
    if key_dir.exists():
        shutil.rmtree(key_dir)
    key_dir.mkdir(mode=0o700)
    for name in ("authorized", "unauthorized", "observer", "operator"):
        run_checked(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"xaios-{name}-fixture",
                "-f",
                str(key_dir / name),
            ],
            30,
        )
    (key_dir / "operator.fingerprint").write_text(
        ed25519_raw_fingerprint(key_dir / "operator.pub") + "\n",
        encoding="ascii",
    )
    (key_dir / "config-high.conf").write_text(
        "schema=xaios.config.v1\n"
        "ssh.max_connections=4\n"
        "ssh.max_channels_per_connection=2\n"
        "ssh.max_auth_attempts=5\n"
        "ssh.command_rate_per_minute=120\n"
        "ssh.password_auth=development\n",
        encoding="ascii",
    )
    (key_dir / "config-low.conf").write_text(
        "schema=xaios.config.v1\n"
        "ssh.max_connections=4\n"
        "ssh.max_channels_per_connection=2\n"
        "ssh.max_auth_attempts=5\n"
        "ssh.command_rate_per_minute=2\n"
        "ssh.password_auth=development\n",
        encoding="ascii",
    )
    (key_dir / "config-invalid.conf").write_text(
        "schema=xaios.config.v1\n"
        "ssh.max_connections=5\n"
        "ssh.max_channels_per_connection=2\n"
        "ssh.max_auth_attempts=5\n"
        "ssh.command_rate_per_minute=120\n"
        "ssh.password_auth=development\n",
        encoding="ascii",
    )
    password_file = key_dir / "password"
    password_file.write_text("admin\n", encoding="ascii")
    password_file.chmod(0o600)
    users_file = key_dir / "sshd-users"
    run_checked(
        [
            sys.executable,
            "scripts/create-sshd-user-config.py",
            "--password-file",
            str(password_file),
            "--output",
            str(users_file),
            "--iterations",
            "100000",
        ],
        30,
    )
    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    build_env["XAIOS_SSH_USERS_FILE"] = str(users_file)
    build_env["XAIOS_SSH_PASSWORD_AUTH"] = "1"
    build_env["XAIOS_FAILURE_TEST_APP"] = "1"
    build_env["XAIOS_BOOT_VERBOSE"] = "1"
    missing_opt_in_env = build_env.copy()
    missing_opt_in_env.pop("XAIOS_SSH_PASSWORD_AUTH")
    require_rejected_build(
        missing_opt_in_env,
        "password credentials require XAIOS_SSH_PASSWORD_AUTH=1",
    )
    release_env = build_env.copy()
    release_env["XAIOS_BUILD_MODE"] = "release"
    require_rejected_build(
        release_env, "password authentication is forbidden in release builds"
    )
    run_checked(["make", BUILD_TARGET], 180, build_env)

    results: dict[str, object] = {
        "architecture": TARGET_ARCH,
        "debian_version": version,
        "image": IMAGE,
    }

    migration_path = BUILD / f"qemu-mutable-fs-v3-migration{ARTIFACT_SUFFIX}.img"
    migration_payload = create_mutable_fs_v3_fixture(migration_path)
    migration_port = reserve_port(socket.SOCK_STREAM)
    migration_qemu, migration_log, _, _ = start_qemu_ready(
        "qemu-mutable-fs-v3-migration" + ARTIFACT_SUFFIX,
        {"XAIOS_QEMU_HOSTFWD_PORT": str(migration_port)},
        SSH_READY_MARKER,
        persistent_path=migration_path,
        reset_persistent=False,
    )
    try:
        migrated = subprocess.run(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/authorized",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PasswordAuthentication=no",
                "-p", str(migration_port),
                "admin@host.docker.internal",
                "cat /tmp/migration.txt",
            ),
            cwd=ROOT,
            capture_output=True,
            timeout=60,
        )
        if migrated.returncode != 0 or migrated.stdout != migration_payload:
            raise RuntimeError(
                "MutableFS v3 migration did not preserve file data: "
                + (migrated.stdout + migrated.stderr).decode(errors="replace")
            )
    finally:
        stop_qemu(migration_qemu)
        migration_log.close()
    with migration_path.open("rb") as fixture:
        fixture.seek(3072 * 512 + 8)
        migrated_version = int.from_bytes(fixture.read(4), "little")
    if migrated_version != 4:
        raise RuntimeError(
            f"MutableFS migration did not publish v4 metadata: {migrated_version}"
        )
    migration_path.unlink(missing_ok=True)
    results["mutable_fs_v3_to_v4_migration"] = "passed"

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    packet_capture = BUILD / f"qemu-docker-network-suite{ARTIFACT_SUFFIX}.pcap"
    packet_capture.unlink(missing_ok=True)
    qemu, log_file, log_path, persistent_path = start_qemu_ready(
        "qemu-docker-network-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port),
            "XAIOS_QEMU_HOSTFWD_UDP_PORT": str(udp_port),
            "XAIOS_QEMU_NET_DUMP": str(packet_capture),
        },
        SSH_READY_MARKER,
    )
    try:
        initial_host_key = scan_host_key(key_dir, ssh_port)
        run_checked(
            docker_command(
                key_dir,
                "/usr/local/bin/xaios-network-client-suite",
                "host.docker.internal",
                str(ssh_port),
                str(udp_port),
                TARGET_ARCH,
            ),
            CLIENT_TIMEOUT_SECONDS,
        )
        verify_native_htop_pty(key_dir, ssh_port)
        run_checked(
            docker_command(
                key_dir,
                "/usr/local/bin/xaios-phase2-client-suite",
                "host.docker.internal",
                str(ssh_port),
            ),
            CLIENT_TIMEOUT_SECONDS,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv4_ssh_sftp_udp"] = "passed"
        results["xaiosctl_control_surface"] = "passed"
        results["sftp_file_directory_operations"] = "passed"
        results["ssh_rekey"] = "passed"
        results["ssh_shared_transport_channels"] = "passed"
        results["native_htop_pty_ansi"] = "passed"
        results["native_htop_non_pty_plain"] = "passed"
        results["native_htop_invalid_option_rejected"] = "passed"
        results["native_transient_apps_on_demand"] = "passed"
        results["ssh_port"] = ssh_port
        results["udp_port"] = udp_port
        results["packet_capture"] = str(packet_capture)
        rotated_host_key = scan_host_key(key_dir, ssh_port)
        if initial_host_key == rotated_host_key:
            raise RuntimeError("SSH host-key rotation did not change the public key")
        results["public_key_auth"] = "passed"
        results["phase2_admin_control"] = "passed"
        results["role_authorization"] = "passed"
        results["config_transaction_rollback"] = "passed"
        results["key_revocation"] = "passed"
        results["host_key_rotation"] = "passed"
        results["sensitive_state_remote_denial"] = "passed"
        results["log_secret_redaction"] = "passed"
        results["password_build_profiles"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()

    reboot_qemu, reboot_log_file, reboot_log_path, _ = start_qemu_ready(
        "qemu-docker-network-reboot",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port)},
        SSH_READY_MARKER,
        persistent_path=persistent_path,
        reset_persistent=False,
    )
    try:
        second_host_key = scan_host_key(key_dir, ssh_port)
        if rotated_host_key != second_host_key:
            raise RuntimeError("rotated SSH host key changed across persistent reboot")
        run_checked(
            docker_command(
                key_dir,
                "ssh",
                "-i",
                "/keys/authorized",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                str(ssh_port),
                "admin@host.docker.internal",
                "echo host-key-persisted",
            ),
            60,
        )
        observer_config = subprocess.run(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/observer",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PasswordAuthentication=no",
                "-p", str(ssh_port),
                "admin@host.docker.internal",
                "xaiosctl config show --json",
            ),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout
        config_data = json.loads(observer_config)["data"]
        if config_data["command_rate_per_minute"] != 120:
            raise RuntimeError("applied config did not persist across reboot")
        revoked_attempt = subprocess.run(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/operator",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PasswordAuthentication=no",
                "-o", "BatchMode=yes",
                "-p", str(ssh_port),
                "admin@host.docker.internal",
                "xaiosctl status --json",
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if revoked_attempt.returncode == 0:
            raise RuntimeError("revoked operator key became valid after reboot")
        results["host_key_persistence"] = "passed"
        results["admin_state_persistence"] = "passed"
    finally:
        stop_qemu(reboot_qemu)
        reboot_log_file.close()
        persistent_path.unlink(missing_ok=True)

    socket_port = reserve_port(socket.SOCK_STREAM)
    ipv6_ssh_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, ipv6_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-ipv6-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(ipv6_ssh_port),
            "XAIOS_QEMU_NET_SOCKET_HOST": "0.0.0.0",
            "XAIOS_QEMU_NET_SOCKET_PORT": str(socket_port),
        },
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "python3",
                "/usr/local/bin/xaios-ipv6-tcp-client",
                "--host",
                "host.docker.internal",
                "--port",
                str(socket_port),
                "--timeout",
                "30",
            ),
            60,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"IPv6 QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv6_tcp"] = "passed"
        results["tcp_invalid_reset_rejection"] = "passed"
        results["socket_port"] = socket_port
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    no_rng_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, no_rng_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-no-rng-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(no_rng_port),
            "XAIOS_QEMU_RNG": "none",
        },
        "SSH server: not running error=2001",
    )
    try:
        banner = b""
        try:
            with socket.create_connection(
                ("127.0.0.1", no_rng_port), timeout=5
            ) as client:
                client.settimeout(3)
                banner = client.recv(128)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            pass
        if banner.startswith(b"SSH-"):
            raise RuntimeError("sshd exposed an SSH banner without secure entropy")
        results["entropy_fail_closed"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    key_only_env = os.environ.copy()
    key_only_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    key_only_env["XAIOS_BOOT_VERBOSE"] = "1"
    key_only_env.pop("XAIOS_SSH_USERS_FILE", None)
    run_checked(["make", BUILD_TARGET], 180, key_only_env)
    key_only_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, key_only_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-key-only-suite",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(key_only_port)},
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/authorized",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(key_only_port),
                "admin@host.docker.internal",
                "echo key-only-auth-ok",
            ),
            60,
        )
        password_attempt = subprocess.run(
            docker_command(
                key_dir,
                "sshpass", "-p", "admin",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-p", str(key_only_port),
                "admin@host.docker.internal",
                "true",
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if password_attempt.returncode == 0:
            raise RuntimeError("default image accepted an unprovisioned password")
        results["password_default_disabled"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    invalid_users = key_dir / "invalid-sshd-users"
    invalid_users.write_text("admin:plaintext:admin\n", encoding="ascii")
    invalid_env = key_only_env.copy()
    invalid_env["XAIOS_SSH_USERS_FILE"] = str(invalid_users)
    invalid_env["XAIOS_SSH_PASSWORD_AUTH"] = "1"
    run_checked(["make", BUILD_TARGET], 180, invalid_env)
    invalid_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, invalid_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-invalid-users-suite",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(invalid_port)},
        "SSH server: not running error=2202",
    )
    try:
        banner = b""
        try:
            with socket.create_connection(("127.0.0.1", invalid_port), timeout=5) as client:
                client.settimeout(3)
                banner = client.recv(128)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            pass
        if banner.startswith(b"SSH-"):
            raise RuntimeError("sshd exposed a banner with malformed credentials")
        results["malformed_credentials_fail_closed"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    report_path = BUILD / f"qemu-docker-network-suite{ARTIFACT_SUFFIX}.json"
    report_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(key_dir)
    print(f"PASS: Docker network suite report: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
