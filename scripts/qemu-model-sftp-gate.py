#!/usr/bin/env python3
"""Exercise resumable ModelFS SFTP against one real XAIOS QEMU guest."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
READY_MARKER = "SSH server: up and running (tcp/22)"
MODEL_CHUNK_SIZE = 2 * 1024 * 1024
sys.path.insert(0, str(ROOT / "tools"))

from xaios_model_volume import manifest_for_file


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_marker(
    log_path: Path,
    marker: str,
    timeout: float,
    process: subprocess.Popen[bytes],
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            log = log_path.read_text(errors="replace")
            if marker in log:
                return
            if "System halted. Manual reset required." in log:
                raise RuntimeError("XAIOS halted before the SSH service became ready")
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before readiness rc={process.returncode}")
        time.sleep(0.25)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-60:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=10)


def wait_for_ssh(port: int, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no SSH probe attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"QEMU exited before SSH key exchange rc={process.returncode}"
            )
        try:
            result = subprocess.run(
                [
                    "ssh-keyscan",
                    "-T",
                    "5",
                    "-p",
                    str(port),
                    "127.0.0.1",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            last_error = "ssh-keyscan timed out"
        else:
            if result.returncode == 0 and "ssh-ed25519" in result.stdout:
                return
            last_error = (
                f"ssh-keyscan rc={result.returncode} stdout={result.stdout!r} "
                f"stderr={result.stderr!r}"
            )
        time.sleep(1.0)
    raise TimeoutError(f"timed out waiting for SSH key exchange: {last_error}")


def start_qemu_ready(
    log_path: Path, environment: dict[str, str]
) -> tuple[subprocess.Popen[bytes], object]:
    last_error: TimeoutError | None = None
    for attempt in range(2):
        log_file = log_path.open("wb")
        process = subprocess.Popen(
            [str(ROOT / "scripts" / "run-qemu-aarch64.sh")],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        try:
            wait_for_marker(log_path, READY_MARKER, 150.0, process)
            return process, log_file
        except BaseException as error:
            stop_process(process)
            log_file.close()
            log_text = log_path.read_text(errors="replace")
            if isinstance(error, TimeoutError):
                last_error = error
            if (
                not isinstance(error, TimeoutError)
                or "XAIOS loader starting" in log_text
                or attempt != 0
            ):
                raise
            log_path.replace(BUILD / "qemu-model-sftp-firmware-attempt-1.log")
            time.sleep(1.0)
    assert last_error is not None
    raise last_error


def write_fixture(
    path: Path, size: int = 2 * 1024 * 1024 + 64 * 1024, seed: int = 11
) -> None:
    block = bytes((index * 13 + seed) & 0xFF for index in range(4096))
    with path.open("wb") as stream:
        remaining = size
        while remaining:
            data = block[: min(remaining, len(block))]
            stream.write(data)
            remaining -= len(data)


def staging_path(source: Path) -> str:
    manifest = manifest_for_file(
        source,
        bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        hashlib.sha256(b"c-sftp-staging-fixture").digest(),
        "sftp-staging-test",
        "portable",
        MODEL_CHUNK_SIZE,
        bytes((index * 3 + 1) & 0xFF for index in range(32)),
    )
    return f"/models/.staging/{manifest.package_id.hex()}"


def dynamic_manifest(source: Path, identity: str, seed: int):
    return manifest_for_file(
        source,
        hashlib.sha256(f"{identity}-uuid".encode()).digest()[:16],
        hashlib.sha256(f"{identity}-revision".encode()).digest(),
        "storage-stress-test",
        "portable",
        MODEL_CHUNK_SIZE,
        bytes((index * 5 + seed) & 0xFF for index in range(32)),
    )


def register_command(manifest, operation_id: int) -> str:
    return (
        f"xaiosctl model register {manifest.package_id.hex()} "
        f"--model-uuid {manifest.model_uuid.hex()} "
        f"--signer-key {manifest.signer_public_key.hex()} "
        f"--signature {manifest.signature.hex()} "
        f"--source-revision {manifest.source_revision.hex()} "
        f"--architecture {manifest.architecture_id} "
        f"--target {manifest.target_id} --size {manifest.logical_size} "
        f"--operation-id {operation_id} --json"
    )


def sftp_arguments(key: Path, port: int, host: str) -> list[str]:
    return [
        "sftp",
        "-b",
        "-",
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "ConnectTimeout=20",
        "-P",
        str(port),
        f"admin@{host}",
    ]


def run_parallel_sftp(
    gate_dir: Path,
    key: Path,
    port: int,
    mac_commands: str,
    debian_commands: str,
) -> None:
    mac = subprocess.Popen(
        sftp_arguments(key, port, "127.0.0.1"),
        cwd=ROOT,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    docker_args = sftp_arguments(Path("/work/admin"), port,
                                  "host.docker.internal")
    debian = subprocess.Popen(
        [
            "docker",
            "run",
            "--interactive",
            "--rm",
            "--add-host",
            "host.docker.internal:host-gateway",
            "--volume",
            f"{gate_dir}:/work",
            "xaios-debian13-network-client:13",
            *docker_args,
        ],
        cwd=ROOT,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    host_name = "macOS" if platform.system() == "Darwin" else platform.system()
    clients = ((host_name, mac, mac_commands), ("Debian", debian, debian_commands))
    failures: list[str] = []
    for name, process, commands in clients:
        try:
            stdout, stderr = process.communicate(commands, timeout=600)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            failures.append(f"{name} SFTP timed out\n{stdout}\n{stderr}")
            continue
        if process.returncode != 0:
            failures.append(
                f"{name} SFTP failed rc={process.returncode}\n"
                f"commands={commands}\n{stdout}\n{stderr}"
            )
    if failures:
        raise RuntimeError("\n".join(failures))


def run_sftp(key: Path, port: int, commands: str) -> str:
    result = subprocess.run(
        sftp_arguments(key, port, "127.0.0.1"),
        cwd=ROOT,
        text=True,
        input=commands,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"sftp batch failed rc={result.returncode}\n"
            f"commands={commands}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout + result.stderr


def run_ssh(key: Path, port: int, command: str) -> str:
    result = subprocess.run(
        [
            "ssh",
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-p",
            str(port),
            "admin@127.0.0.1",
            command,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ssh command failed rc={result.returncode} command={command}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout


def run_ssh_json(key: Path, port: int, command: str) -> dict[str, object]:
    output = run_ssh(key, port, command)
    try:
        envelope = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"ssh command returned invalid JSON command={command}: {output!r}"
        ) from error
    if envelope.get("schema_version") != 1 or envelope.get("status") != "ok":
        raise RuntimeError(
            f"ssh command returned invalid envelope command={command}: {envelope!r}"
        )
    data = envelope.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(
            f"ssh command returned non-object data command={command}: {envelope!r}"
        )
    return data


def main() -> int:
    for tool in ("docker", "ssh-keygen", "ssh-keyscan", "sftp"):
        if shutil.which(tool) is None:
            raise SystemExit(f"error: required client tool not found: {tool}")

    subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"],
        cwd=ROOT,
        check=True,
        timeout=30,
    )
    subprocess.run(
        [
            "docker",
            "build",
            "--file",
            "tests/network/Dockerfile.debian13",
            "--tag",
            "xaios-debian13-network-client:13",
            ".",
        ],
        cwd=ROOT,
        check=True,
        timeout=300,
    )
    debian_version = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "xaios-debian13-network-client:13",
            "sh",
            "-c",
            ". /etc/os-release; printf '%s' \"$VERSION_ID\"",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        timeout=30,
    ).stdout
    if not debian_version.startswith("13"):
        raise RuntimeError(f"expected Debian 13 client, got {debian_version!r}")

    BUILD.mkdir(parents=True, exist_ok=True)
    gate_dir = BUILD / "qemu-model-sftp"
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(mode=0o700)
    key = gate_dir / "admin"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "xaios-model-sftp-gate",
            "-f",
            str(key),
        ],
        cwd=ROOT,
        check=True,
        timeout=30,
    )

    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key.with_suffix(".pub"))
    subprocess.run(
        ["make", "image"], cwd=ROOT, env=build_env, check=True, timeout=180
    )

    source = gate_dir / "model.package"
    partial = gate_dir / "model.partial"
    downloaded = gate_dir / "model.downloaded"
    active_download = gate_dir / "model.active-download"
    write_fixture(source)
    with source.open("rb") as stream:
        partial.write_bytes(stream.read(2 * 1024 * 1024))
    remote_path = staging_path(source)
    source_arg = source.relative_to(ROOT)
    partial_arg = partial.relative_to(ROOT)
    downloaded_arg = downloaded.relative_to(ROOT)
    active_download_arg = active_download.relative_to(ROOT)

    mac_source = gate_dir / "dynamic-macos.package"
    debian_source = gate_dir / "dynamic-debian.package"
    cleanup_source = gate_dir / "dynamic-cleanup.package"
    reuse_source = gate_dir / "dynamic-reuse.package"
    mac_download = gate_dir / "dynamic-macos.download"
    debian_download = gate_dir / "dynamic-debian.download"
    # Each concurrent transfer crosses a verification-chunk boundary without
    # turning TCG throughput into the acceptance criterion.
    write_fixture(mac_source, MODEL_CHUNK_SIZE + 64 * 1024, 17)
    write_fixture(debian_source, MODEL_CHUNK_SIZE + 128 * 1024, 23)
    write_fixture(cleanup_source, 4 * 1024 * 1024 + 64 * 1024, 29)
    write_fixture(reuse_source, cleanup_source.stat().st_size, 31)
    cleanup_partial = gate_dir / "dynamic-cleanup.partial"
    with cleanup_source.open("rb") as stream:
        cleanup_partial.write_bytes(stream.read(1024 * 1024))
    mac_manifest = dynamic_manifest(mac_source, "macos", 7)
    debian_manifest = dynamic_manifest(debian_source, "debian", 13)
    cleanup_manifest = dynamic_manifest(cleanup_source, "cleanup", 19)
    reuse_manifest = dynamic_manifest(reuse_source, "reuse", 23)

    port = reserve_port()
    persistent = gate_dir / "persistent.img"
    log_path = BUILD / "qemu-model-sftp-gate.log"
    qemu_env = os.environ.copy()
    qemu_env.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_QEMU_HOSTFWD_PORT": str(port),
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
            "XAIOS_QEMU_MODEL_DISCARD": "unmap",
        }
    )
    qemu, log_file = start_qemu_ready(log_path, qemu_env)
    try:
        wait_for_ssh(port, qemu, 120.0)
        first = run_sftp(
            key,
            port,
            f"put {partial_arg} {remote_path}\nls -l {remote_path}\n",
        )
        if not re.search(r"(?:^|\s)2097152(?:\s|$)", first):
            raise RuntimeError(
                f"staging prefix was not committed at 2 MiB: {first!r}"
            )

        devices = run_ssh_json(
            key, port, "xaiosctl storage device list --json"
        )
        model_devices = [
            device
            for device in devices.get("devices", [])
            if device.get("identifier") == "/dev/vblk4"
        ]
        if len(model_devices) != 1:
            raise RuntimeError(
                f"storage inventory does not identify ModelFS device: {devices!r}"
            )
        model_device = run_ssh_json(
            key, port, "xaiosctl storage device show /dev/vblk4 --json"
        )
        records = model_device.get("devices", [])
        if (
            len(records) != 1
            or records[0].get("logical_sector_size") != 512
            or records[0].get("capacity_bytes", 0) <= source.stat().st_size
            or records[0].get("read_only") != 0
            or records[0].get("discard_supported") != 1
        ):
            raise RuntimeError(
                f"ModelFS block geometry/capabilities are invalid: {model_device!r}"
            )
        filesystems = run_ssh_json(
            key, port, "xaiosctl storage filesystem list --json"
        )
        mounts = {
            record.get("mount_path"): record
            for record in filesystems.get("filesystems", [])
        }
        if (
            mounts.get("/", {}).get("filesystem") != "MutableFS"
            or mounts.get("/models", {}).get("filesystem") != "ModelFS"
            or mounts.get("/models", {}).get("device_identifier")
            != "/dev/vblk4"
            or mounts.get("/models", {}).get("staging_writable") != 1
        ):
            raise RuntimeError(
                f"storage mount inventory is inconsistent: {filesystems!r}"
            )
        initial_models = mounts["/models"]

        resumed = run_sftp(
            key,
            port,
            f"reput {source_arg} {remote_path}\n"
            f"ls -l {remote_path}\n"
            f"get {remote_path} {downloaded_arg}\n",
        )
        if not re.search(r"(?:^|\s)2162688(?:\s|$)", resumed):
            raise RuntimeError(
                f"resumed staging package has wrong size: {resumed!r}"
            )
        if source.read_bytes() != downloaded.read_bytes():
            raise RuntimeError("resumed ModelFS SFTP payload mismatch")

        package_id = remote_path.rsplit("/", 1)[1]
        verified = run_ssh(
            key, port, f"xaiosctl model verify {package_id}"
        )
        if "generation=10" not in verified or "changed=0" not in verified:
            raise RuntimeError(f"unexpected model verify response: {verified!r}")
        activated = run_ssh(
            key,
            port,
            f"xaiosctl model activate {package_id} --operation-id 9001",
        )
        if "generation=11" not in activated or "changed=1" not in activated:
            raise RuntimeError(
                f"unexpected model activation response: {activated!r}"
            )
        audit = run_ssh(key, port, "xaiosctl audit show --since 0 --limit 16")
        if "operation=model.package.activate" not in audit:
            raise RuntimeError("model activation is absent from the audit log")
        active_path = f"/models/{package_id}"
        active = run_sftp(
            key,
            port,
            f"ls -l {active_path}\n"
            f"get {active_path} {active_download_arg}\n",
        )
        if not re.search(r"(?:^|\s)2162688(?:\s|$)", active):
            raise RuntimeError(f"active package has wrong size: {active!r}")
        if source.read_bytes() != active_download.read_bytes():
            raise RuntimeError("activated ModelFS payload mismatch")
        usage = run_ssh_json(
            key, port, "xaiosctl storage usage /models --json"
        )
        usage_records = usage.get("filesystems", [])
        if (
            len(usage_records) != 1
            or usage_records[0].get("mount_path") != "/models"
            or usage_records[0].get("format_version") != 1
            or usage_records[0].get("active_packages")
            != initial_models.get("active_packages", 0) + 1
            or usage_records[0].get("staging_packages", 0) + 1
            != initial_models.get("staging_packages")
            or usage_records[0].get("package_count")
            != initial_models.get("package_count")
            or usage_records[0].get("allocated_bytes", 0)
            > usage_records[0].get("total_bytes", 0)
        ):
            raise RuntimeError(f"activated ModelFS usage is invalid: {usage!r}")

        for manifest, operation_id in (
            (mac_manifest, 9101),
            (debian_manifest, 9102),
        ):
            registered = run_ssh_json(
                key, port, register_command(manifest, operation_id)
            )
            if registered.get("changed") != 1:
                raise RuntimeError(f"dynamic registration failed: {registered!r}")

        mac_remote = f"/models/.staging/{mac_manifest.package_id.hex()}"
        debian_remote = f"/models/.staging/{debian_manifest.package_id.hex()}"
        run_parallel_sftp(
            gate_dir,
            key,
            port,
            f"put {mac_source.relative_to(ROOT)} {mac_remote}\n",
            f"put /work/{debian_source.name} {debian_remote}\n",
        )
        for manifest, operation_id in (
            (mac_manifest, 9201),
            (debian_manifest, 9202),
        ):
            package = manifest.package_id.hex()
            verified_dynamic = run_ssh_json(
                key, port, f"xaiosctl model verify {package} --json"
            )
            if not isinstance(verified_dynamic.get("generation"), int):
                raise RuntimeError(
                    f"dynamic package verification failed: {verified_dynamic!r}"
                )
            activated_dynamic = run_ssh_json(
                key,
                port,
                f"xaiosctl model activate {package} "
                f"--operation-id {operation_id} --json",
            )
            if activated_dynamic.get("changed") != 1:
                raise RuntimeError(
                    f"dynamic package activation failed: {activated_dynamic!r}"
                )

        run_parallel_sftp(
            gate_dir,
            key,
            port,
            f"get /models/{mac_manifest.package_id.hex()} "
            f"{mac_download.relative_to(ROOT)}\n",
            f"get /models/{debian_manifest.package_id.hex()} "
            f"/work/{debian_download.name}\n",
        )
        if mac_source.read_bytes() != mac_download.read_bytes():
            raise RuntimeError("concurrent macOS ModelFS download mismatch")
        if debian_source.read_bytes() != debian_download.read_bytes():
            raise RuntimeError("concurrent Debian ModelFS download mismatch")

        cleanup_registered = run_ssh_json(
            key, port, register_command(cleanup_manifest, 9301)
        )
        if cleanup_registered.get("changed") != 1:
            raise RuntimeError(f"cleanup fixture registration failed: {cleanup_registered!r}")
        cleanup_remote = (
            f"/models/.staging/{cleanup_manifest.package_id.hex()}"
        )
        run_sftp(
            key,
            port,
            f"put {cleanup_partial.relative_to(ROOT)} {cleanup_remote}\n",
        )
        cleaned = run_ssh_json(
            key,
            port,
            f"xaiosctl model cleanup {cleanup_manifest.package_id.hex()} "
            "--operation-id 9302 --json",
        )
        if (
            cleaned.get("changed") != 1
            or cleaned.get("reclaimed_bytes") != cleanup_source.stat().st_size
        ):
            raise RuntimeError(f"staging cleanup did not reclaim its extent: {cleaned!r}")

        reused = run_ssh_json(key, port, register_command(reuse_manifest, 9303))
        if reused.get("changed") != 1:
            raise RuntimeError(f"free-extent reuse registration failed: {reused!r}")
        reused_cleanup = run_ssh_json(
            key,
            port,
            f"xaiosctl model cleanup {reuse_manifest.package_id.hex()} "
            "--operation-id 9304 --json",
        )
        if reused_cleanup.get("reclaimed_bytes") != reuse_source.stat().st_size:
            raise RuntimeError(f"reused extent cleanup failed: {reused_cleanup!r}")

        scrub = run_ssh_json(
            key,
            port,
            "xaiosctl storage scrub /models --start "
            "--operation-id 9401 --json",
        )
        for _ in range(128):
            if scrub.get("state") == "complete":
                break
            if scrub.get("state") == "failed":
                raise RuntimeError(f"ModelFS scrub failed: {scrub!r}")
            scrub = run_ssh_json(
                key, port, "xaiosctl storage scrub /models --status --json"
            )
        else:
            raise RuntimeError(f"ModelFS scrub did not complete: {scrub!r}")
        if scrub.get("checked_bytes") != scrub.get("total_bytes"):
            raise RuntimeError(f"ModelFS scrub byte accounting is invalid: {scrub!r}")

        trim = run_ssh_json(
            key,
            port,
            "xaiosctl storage trim /models --dry-run --json",
        )
        for _ in range(128):
            if trim.get("state") == "complete":
                break
            if trim.get("state") == "failed":
                raise RuntimeError(f"ModelFS trim dry-run failed: {trim!r}")
            trim = run_ssh_json(
                key, port, "xaiosctl storage trim-status /models --json"
            )
        else:
            raise RuntimeError(f"ModelFS trim dry-run did not complete: {trim!r}")
        if trim.get("dry_run") != 1 or trim.get("processed_bytes", 0) == 0:
            raise RuntimeError(f"ModelFS trim dry-run reported no work: {trim!r}")

        trim = run_ssh_json(
            key,
            port,
            "xaiosctl storage trim /models --all-free "
            "--operation-id 9501 --json",
        )
        for _ in range(128):
            if trim.get("state") == "complete":
                break
            if trim.get("state") == "failed":
                raise RuntimeError(f"ModelFS trim failed: {trim!r}")
            trim = run_ssh_json(
                key, port, "xaiosctl storage trim-status /models --json"
            )
        else:
            raise RuntimeError(f"ModelFS trim did not complete: {trim!r}")
        if trim.get("processed_bytes") != trim.get("eligible_bytes"):
            raise RuntimeError(f"ModelFS trim byte accounting is invalid: {trim!r}")
        post_trim_device = run_ssh_json(
            key, port, "xaiosctl storage device show /dev/vblk4 --json"
        )["devices"][0]
        if post_trim_device.get("discarded_bytes", 0) == 0:
            raise RuntimeError(
                f"VirtIO discard accounting did not advance: {post_trim_device!r}"
            )

        audit = run_ssh(key, port, "xaiosctl audit show --since 0 --limit 16")
        for operation in (
            "model.package.stage",
            "model.package.cleanup",
            "storage.scrub.start",
            "storage.trim.start",
        ):
            if f"operation={operation}" not in audit:
                raise RuntimeError(f"audit log lacks {operation}: {audit!r}")
        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited unexpectedly rc={qemu.returncode}")
    finally:
        stop_process(qemu)
        log_file.close()

    log = log_path.read_text(errors="replace")
    if (
        "staging fsync record=3" not in log
        or "modelfs: activated package=" not in log
        or "modelfs: registered dynamic staging package" not in log
        or "modelfs: cleaned staging package=" not in log
    ):
        raise RuntimeError("guest log lacks ModelFS commit/activation evidence")
    print(
        "qemu-model-sftp: one XAIOS VM passed concurrent "
        f"{'macOS' if platform.system() == 'Darwin' else platform.system()}/Debian 13 "
        "dynamic SFTP upload/download, resume, verify, activate, scrub, "
        "staging cleanup/reuse, audited trim, and VirtIO discard accounting"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
