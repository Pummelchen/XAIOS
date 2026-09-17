#!/usr/bin/env python3
"""Docker and QEMU harness helpers for the Debian 13 cross-client gate.

Moved verbatim out of `qemu-docker-network-suite.py`, which keeps the run order
and the report. `prepare_docker_client` was lifted out of `main` unchanged, so
Docker and the Debian release are still checked before any fixture is touched.
"""

from __future__ import annotations

import base64, hashlib, os, shutil, subprocess, sys, time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
IMAGE = "xaios-debian13-network-client:13"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (QEMU_ARCHES, qemu_boot_environment, qemu_runner,
                           render_terminal, smoke_timeout, translate_qemu_env)

TARGET_ARCH = os.environ.get("XAIOS_QEMU_NETWORK_ARCH", "aarch64")
for _index, _argument in enumerate(sys.argv):
    if _argument == "--arch" and _index + 1 < len(sys.argv):
        TARGET_ARCH = sys.argv[_index + 1]
    elif _argument.startswith("--arch="):
        TARGET_ARCH = _argument.split("=", 1)[1]
if TARGET_ARCH not in QEMU_ARCHES:
    raise SystemExit(
        f"error: architecture must be one of {', '.join(QEMU_ARCHES)}")
BUILD_COMMANDS = {
    "aarch64": [["make", "image"]],
    "x86_64": [["make", "image-x86_64"]],
    "riscv64": [["./scripts/build-riscv64.sh"],
                ["./scripts/build-riscv64-image.sh"]],
}[TARGET_ARCH]
ARTIFACT_SUFFIX = "" if TARGET_ARCH == "aarch64" else f"-{TARGET_ARCH}"
SSH_READY_MARKER = "SSH server: up and running (tcp/22)"
BOOT_TIMEOUT_SECONDS = float(os.environ.get("XAIOS_TEST_BOOT_TIMEOUT", "150"))
CLIENT_TIMEOUT_SECONDS = float(os.environ.get("XAIOS_TEST_SUITE_TIMEOUT", "600"))
CONNECT_TIMEOUT_SECONDS = os.environ.get("XAIOS_TEST_CONNECT_TIMEOUT", "60")
XTOP_TIMEOUT_SECONDS = 180
FATAL_BOOT_MARKERS = (
    "CYAN SCREEN OF DEATH",
    "System halted. Manual reset required",
    "kernel panic",
    "assertion failed",
)


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


def build_image(timeout: int, env: dict[str, str] | None = None) -> None:
    """Rebuild the guest image for whichever machine this run is loading.

    In the release configuration, deliberately. `make image` means that on the
    other two architectures; the RISC-V builders default to the boot-test
    configuration instead, where the shell's commands are kernel built-ins and
    no application is launched as a process. A suite that asks an external
    client to run /bin/stat over SSH would then be answered by a built-in that
    does not exist, which is how this port found that the RISC-V image was
    carrying none of the file utilities at all.
    """
    merged = dict(env) if env else dict(os.environ)
    if TARGET_ARCH == "riscv64":
        merged.setdefault("XAIOS_BOOT_TEST_APPS", "0")
    for command in BUILD_COMMANDS:
        run_checked(command, smoke_timeout(TARGET_ARCH, timeout), merged)


def stop_qemu(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def wait_for_log_quiescence(log_path: Path, stable_seconds: float = 1.0,
                            timeout_seconds: float = 10.0) -> None:
    """Let completed SSH disconnect logging and synchronous metadata I/O settle."""
    deadline = time.monotonic() + timeout_seconds
    stable_since = time.monotonic()
    previous_size = log_path.stat().st_size if log_path.exists() else -1
    while time.monotonic() < deadline:
        time.sleep(0.1)
        current_size = log_path.stat().st_size if log_path.exists() else -1
        if current_size != previous_size:
            previous_size = current_size
            stable_since = time.monotonic()
            continue
        if time.monotonic() - stable_since >= stable_seconds:
            return
    raise TimeoutError(f"guest log did not quiesce before reboot: {log_path}")


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
    env = qemu_boot_environment(
        TARGET_ARCH, os.environ.copy(), accel="tcg", smp=4,
        persistent=persistent_path,
        state_dir=BUILD / f"{name}-state",
        # The console is redirected into log_path; the RISC-V runner writes it
        # to a file of its own unless told otherwise.
        serial_to_stdout=True)
    # The scenarios below set XAIOS_QEMU_* names directly at a dozen call
    # sites. Translating them here is smaller than rewriting all of them, and
    # keeps the scenarios readable as what they are asking for.
    env.update(translate_qemu_env(TARGET_ARCH, extra_env))
    process = subprocess.Popen(
        [str(ROOT / qemu_runner(TARGET_ARCH))],
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


def docker_command(
    key_dir: Path, *command: str, writable_keys: bool = False
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--interactive",
        "--add-host",
        "host.docker.internal:host-gateway",
        "--env",
        f"XAIOS_TEST_CONNECT_TIMEOUT={CONNECT_TIMEOUT_SECONDS}",
        "--volume",
        f"{key_dir}:/keys:{'rw' if writable_keys else 'ro'}",
        IMAGE,
        *command,
    ]


def run_scale_sftp(
    key_dir: Path, port: int, commands: str, *, expect_success: bool = True
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        docker_command(
            key_dir,
            "sftp", "-b", "-", "-i", "/keys/authorized",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PasswordAuthentication=no",
            "-P", str(port), "admin@host.docker.internal",
            writable_keys=True,
        ),
        cwd=ROOT,
        input=commands.encode("ascii"),
        capture_output=True,
        timeout=300,
    )
    if (result.returncode == 0) != expect_success:
        raise RuntimeError(
            "xaibootFS v5 SFTP result did not match expectation: "
            + (result.stdout + result.stderr).decode(errors="replace")
        )
    return result


def prepare_xaiboot_fs_v5_scale(key_dir: Path, port: int) -> dict[str, object]:
    payload = key_dir / "mutablefs-v5-limit.bin"
    overflow = key_dir / "mutablefs-v5-overflow.bin"
    downloaded = key_dir / "mutablefs-v5-download.bin"
    pattern = bytes((index * 29 + 17) & 0xFF for index in range(4096))
    payload.write_bytes(pattern * 64)
    overflow.write_bytes(payload.read_bytes() + b"X")
    downloaded.unlink(missing_ok=True)

    node_root = "/tmp/mutablefs-v5-nodes"
    directory_count = 180
    commands = [
        "put /keys/mutablefs-v5-limit.bin /tmp/mutablefs-v5-limit.bin",
        "get /tmp/mutablefs-v5-limit.bin /keys/mutablefs-v5-download.bin",
        f"mkdir {node_root}",
    ]
    commands.extend(
        f"mkdir {node_root}/d{index:03d}" for index in range(directory_count)
    )
    commands.extend([f"ls -1 {node_root}", "quit", ""])
    listing = run_scale_sftp(key_dir, port, "\n".join(commands))
    if downloaded.read_bytes() != payload.read_bytes():
        raise RuntimeError("xaibootFS v5 256 KiB SFTP round trip changed payload bytes")
    listing_text = (listing.stdout + listing.stderr).decode(errors="replace")
    if sum(f"d{index:03d}" in listing_text for index in range(directory_count)) \
            != directory_count:
        raise RuntimeError("xaibootFS v5 directory-pressure listing was incomplete")

    run_scale_sftp(
        key_dir,
        port,
        "put /keys/mutablefs-v5-overflow.bin /tmp/mutablefs-v5-overflow.bin\nquit\n",
        expect_success=False,
    )
    return {
        "file_bytes": payload.stat().st_size,
        "overflow_bytes_rejected": overflow.stat().st_size,
        "pressure_directories": directory_count,
        "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
    }


def verify_xaiboot_fs_v5_scale_after_reboot(
    key_dir: Path, port: int, expected: dict[str, object]
) -> None:
    downloaded = key_dir / "mutablefs-v5-reboot.bin"
    downloaded.unlink(missing_ok=True)
    node_root = "/tmp/mutablefs-v5-nodes"
    directory_count = int(expected["pressure_directories"])
    commands = [
        "get /tmp/mutablefs-v5-limit.bin /keys/mutablefs-v5-reboot.bin",
        f"ls -1 {node_root}",
    ]
    commands.extend(
        f"rmdir {node_root}/d{index:03d}" for index in range(directory_count)
    )
    commands.extend([
        f"rmdir {node_root}",
        "rm /tmp/mutablefs-v5-limit.bin",
        "rm /tmp/mutablefs-v5-overflow.bin",
        "quit",
        "",
    ])
    listing = run_scale_sftp(key_dir, port, "\n".join(commands))
    digest = hashlib.sha256(downloaded.read_bytes()).hexdigest()
    if digest != expected["sha256"]:
        raise RuntimeError("xaibootFS v5 persisted payload changed after reboot")
    listing_text = (listing.stdout + listing.stderr).decode(errors="replace")
    if sum(f"d{index:03d}" in listing_text for index in range(directory_count)) \
            != directory_count:
        raise RuntimeError("xaibootFS v5 pressure directories did not persist")


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


def create_xaiboot_fs_fixture(path: Path, version: int) -> bytes:
    sector_size = 512
    start_sector = 3072
    if version == 3:
        metadata_sectors = 32
        data_sectors = 256
        max_nodes = 64
        file_max_blocks = 16
        path_bytes = 96
    elif version == 4:
        metadata_sectors = 384
        data_sectors = 4096
        max_nodes = 128
        file_max_blocks = 256
        path_bytes = 256
    else:
        raise ValueError(f"unsupported xaibootFS fixture version: {version}")
    node_size = (68 + file_max_blocks * 4 + path_bytes + 7) & ~7
    payload = (f"XAIOS xaibootFS v{version} migration payload\n".encode() * 40)[:1400]
    block_count = (len(payload) + sector_size - 1) // sector_size
    metadata = bytearray(metadata_sectors * sector_size)
    struct_header = (
        b"XAIOSMFS"
        + version.to_bytes(4, "little")
        + sector_size.to_bytes(4, "little")
        + metadata_sectors.to_bytes(4, "little")
        + max_nodes.to_bytes(4, "little")
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
        raise RuntimeError(f"xaibootFS v{version} fixture header layout drifted")
    metadata[:len(struct_header)] = struct_header
    metadata[88:88 + block_count] = b"\x01" * block_count
    nodes_offset = 88 + data_sectors

    def add_node(index: int, node_type: int, generation: int, node_path: str,
                 content: bytes = b"") -> None:
        encoded_path = node_path.encode("ascii")
        if len(encoded_path) >= path_bytes:
            raise RuntimeError(f"xaibootFS v{version} fixture path is too long")
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
        path_offset = 68 + file_max_blocks * 4
        node[path_offset:path_offset + len(encoded_path)] = encoded_path
        offset = nodes_offset + index * node_size
        metadata[offset:offset + node_size] = node

    add_node(0, 1, 1, "/")
    add_node(1, 1, 2, "/tmp")
    add_node(2, 2, 3, "/tmp/migration.txt", payload)
    checksum_data = bytearray(metadata)
    checksum_data[80:88] = b"\x00" * 8
    metadata[80:88] = fnv1a64(checksum_data).to_bytes(8, "little")

    image = bytearray(32768 * sector_size)
    metadata_offset = start_sector * sector_size
    image[metadata_offset:metadata_offset + len(metadata)] = metadata
    data_offset = (start_sector + metadata_sectors + 2) * sector_size
    image[data_offset:data_offset + len(payload)] = payload
    path.write_bytes(image)
    return payload


def require_rejected_build(env: dict[str, str], marker: str) -> None:
    """The build that must refuse, and the reason it must give.

    The credential policy lives in the image builder rather than the kernel
    one, so on a machine whose build is two steps this is the last of them.
    """
    completed = subprocess.run(
        BUILD_COMMANDS[-1],
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


def build_debian_client_image() -> None:
    command = [
        "docker", "build", "--pull",
        "--file", "tests/network/Dockerfile.debian13",
        "--tag", IMAGE, ".",
    ]
    try:
        run_checked(command, 300)
    except subprocess.CalledProcessError:
        cached = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        if cached.returncode != 0:
            raise
        print(
            "warning: registry refresh failed; using the existing local "
            f"{IMAGE} image",
            flush=True,
        )


def prepare_docker_client() -> str:
    """Check Docker, build the client image, and assert its Debian release."""
    if shutil.which("docker") is None:
        raise SystemExit("error: Docker CLI is required")
    run_checked(["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"], 30)
    build_debian_client_image()
    version = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "sh", "-c", ". /etc/os-release; printf '%s' \"$VERSION_ID\""],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    if not version.startswith("13"):
        raise RuntimeError(f"expected Debian 13 container, got VERSION_ID={version!r}")
    return version

