#!/usr/bin/env python3
"""Install and execute a signed test-only XAIOS package through xapt in QEMU."""

from __future__ import annotations

import argparse
import functools
import http.server
import os
from pathlib import Path
import signal
import shutil
import socket
import ssl
import subprocess
import threading
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
READY = "SSH server: up and running (tcp/22)"


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Http11Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass


def wait_marker(path: Path, marker: str, timeout: float = 180.0) -> None:
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace") if path.exists() else ""
        if marker in text:
            return
        time.sleep(0.25)
    raise TimeoutError(f"missing marker {marker!r}\n" + "\n".join(text.splitlines()[-80:]))


def ssh_base(key: Path, port: int) -> list[str]:
    return [
        "ssh", "-F", "/dev/null", "-i", str(key), "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=5", "-p", str(port), "admin@127.0.0.1",
    ]


def ssh(key: Path, port: int, command: str, timeout: int = 90) -> str:
    result = subprocess.run(
        ssh_base(key, port) + [command], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"SSH command failed rc={result.returncode}: {command}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout


def ssh_fails(key: Path, port: int, command: str, timeout: int = 90) -> str:
    result = subprocess.run(
        ssh_base(key, port) + [command], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
    )
    if result.returncode == 0:
        raise RuntimeError(f"SSH command unexpectedly succeeded: {command}\n{result.stdout}")
    return result.stdout


def wait_ssh(key: Path, port: int) -> None:
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            if ssh(key, port, "echo xapt-ready", 10).strip() == "xapt-ready":
                return
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.25)
    raise TimeoutError("SSH did not become ready")


def upload_config(key: Path, port: int, content: str) -> None:
    with tempfile.NamedTemporaryFile("w", prefix="xaios-xapt-config.") as source:
        source.write(content)
        source.flush()
        result = subprocess.run(
            ["scp", "-F", "/dev/null", "-i", str(key), "-o",
             "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o",
             "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-P",
             str(port), source.name, "admin@127.0.0.1:/state/xapt/config"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30)
        if result.returncode != 0:
            raise RuntimeError(f"xapt config upload failed: {result.stderr}")


def build_repository(arch: str, repository: Path) -> None:
    shutil.rmtree(repository, ignore_errors=True)
    elf = BUILD / "xapt" / arch / "xapt-test-app.elf"
    subprocess.run(
        [str(ROOT / "scripts/build-user-app.sh"), "--arch", arch,
         "tests/fixtures/xapt-test-app.c", str(elf)], cwd=ROOT, check=True,
    )
    common = [
        "python3", "tools/xaios_xapt_repo.py", "package",
        "--repository", str(repository), "--elf", str(elf),
        "--name", "xapt-test-app", "--version", "1.0.0", "--arch", arch,
        "--capabilities", "1073741826", "--description",
        "Test-only package lifecycle fixture",
    ]
    subprocess.run(common, cwd=ROOT, check=True)
    kernel = BUILD / ("kernel/kernel.elf" if arch == "aarch64" else
                      "kernel-x86_64/kernel.elf")
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "system",
         "--repository", str(repository), "--image", str(kernel),
         "--version", "2", "--generation", "100", "--arch", arch],
        cwd=ROOT, check=True,
    )
    system_record = repository / "os" / arch / "2" / "record.json"
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "catalog", "--repository",
         str(repository), "--arch", arch, "--generation", "1",
         "--generated", "qemu-gate-1", "--os-record", str(system_record)],
        cwd=ROOT, check=True,
    )
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "verify", "--repository",
         str(repository)], cwd=ROOT, check=True,
    )


def publish_test_app(arch: str, repository: Path, version: str,
                     generation: int, key_name: str = "v1") -> None:
    elf = BUILD / "xapt" / arch / "xapt-test-app.elf"
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "package",
         "--repository", str(repository), "--elf", str(elf),
         "--name", "xapt-test-app", "--version", version, "--arch", arch,
         "--capabilities", "1073741826", "--description",
         "Test-only package lifecycle fixture", "--key", key_name],
        cwd=ROOT, check=True,
    )
    kernel = BUILD / ("kernel/kernel.elf" if arch == "aarch64" else
                      "kernel-x86_64/kernel.elf")
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "system",
         "--repository", str(repository), "--image", str(kernel),
         "--version", "2", "--generation", "100", "--arch", arch,
         "--key", key_name], cwd=ROOT, check=True,
    )
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "catalog", "--repository",
         str(repository), "--arch", arch, "--generation", str(generation),
         "--generated", f"qemu-gate-{generation}", "--os-record",
         str(repository / "os" / arch / "2" / "record.json"),
         "--key", key_name],
        cwd=ROOT, check=True,
    )
    subprocess.run(
        ["python3", "tools/xaios_xapt_repo.py", "verify", "--repository",
         str(repository)], cwd=ROOT, check=True,
    )


def start_guest(arch: str, port: int, persistent: Path, log: Path) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["XAIOS_QEMU_HOSTFWD_PORT"] = str(port)
    if arch == "aarch64":
        env.update({"XAIOS_QEMU_ACCEL": "tcg", "XAIOS_QEMU_SMP": "4",
                    "XAIOS_PERSISTENT_IMAGE": str(persistent)})
        runner = ROOT / "platform/qemu/run-qemu-aarch64.sh"
    else:
        env.update({"XAIOS_QEMU_X86_ACCEL": "tcg", "XAIOS_QEMU_X86_SMP": "4",
                    "XAIOS_X86_PERSISTENT_IMAGE": str(persistent)})
        runner = ROOT / "platform/qemu/run-qemu-x86_64.sh"
    handle = log.open("wb")
    process = subprocess.Popen(
        [str(runner)], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
        stdout=handle, stderr=subprocess.STDOUT, start_new_session=True,
    )
    process._log_handle = handle  # type: ignore[attr-defined]
    return process


def stop_guest(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
    process._log_handle.close()  # type: ignore[attr-defined]


def exercise(arch: str, key: Path) -> None:
    repository = BUILD / "xapt" / f"repository-{arch}"
    build_repository(arch, repository)
    handler = functools.partial(Http11Handler, directory=str(repository))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.maximum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(ROOT / "tests/fixtures/xapt-tls-cert.pem",
                        ROOT / "tests/fixtures/xapt-tls-key.pem")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    ssh_port = reserve_port()
    persistent = BUILD / f"xapt-{arch}-persistent.img"
    persistent.unlink(missing_ok=True)
    log = BUILD / f"qemu-xapt-{arch}.log"
    try:
        guest = start_guest(arch, ssh_port, persistent, log)
        try:
            wait_marker(log, READY)
            wait_ssh(key, ssh_port)
            upload_config(
                key, ssh_port,
                f"host=10.0.2.2\nport={server.server_port}\nbase=/\n"
                "tls=required\n"
                "tls_rsa_modulus="
                "b4cef411efa36fc7f79c728c9a792dd206a2c72a5eeeedca708ac7afa743c1cac9bf6fea56782ee92bc359861381f40b0db41968e5490ca2f214b5f29ab4c6144d8e24f453c2ed415d95b8789b71fd1fd33b8c491212d5865d31f135f2736f38cdef3aa13ad64ec7af59f2795f0ff944d3ea70018c8ec874e684dbc1c640123ea060a52e8101f9d87713e91ba77635f1e83321010dd56e01b652623b9dd9cd56ac516541640f3b9ef0e6ab84c98e4f667d75c5e7c547a584155eddba0d0e7ffe712a23b44f14166f4fe859473c2fc8f3c7ab25151e86ae53169f2aa8f8ef784d9c4a0251c3a5e54b2a3083f722c26df97f31c9b364bd840eef503029d91e00df\n")
            htop = ssh(
                key, ssh_port,
                "htop --plain --no-cpus --sample-ms 1 --filter htop",
            )
            if "XAIOS htop sample_ms=1" not in htop or "/bin/htop" not in htop:
                raise RuntimeError(f"dedicated htop binary did not execute: {htop!r}")
            pong = ssh_fails(key, ssh_port, "pong")
            if "pong: interactive terminal required" not in pong:
                raise RuntimeError(f"dedicated pong binary did not reject non-PTY use: {pong!r}")
            update = ssh(key, ssh_port, "xapt update")
            if "catalog verified and activated" not in update:
                raise RuntimeError(f"catalog activation failed: {update!r}")
            listing = ssh(key, ssh_port, "xapt list")
            if "xapt-test-app 1.0.0 [available]" not in listing:
                raise RuntimeError(f"new app not offered: {listing!r}")
            if "xaios 2 [OS upgrade; reboot required]" not in listing:
                raise RuntimeError(f"OS update not offered: {listing!r}")
            install = ssh(key, ssh_port, "xapt install xapt-test-app", 180)
            if "activated xapt-test-app 1.0.0 without reboot" not in install:
                raise RuntimeError(f"install failed: {install!r}")
            probe = ssh(key, ssh_port, "xapt-test-app argv works")
            if not probe.startswith("xapt-test-app argv works\n"):
                raise RuntimeError(f"installed app/argv failed: {probe!r}")
            installed = ssh(key, ssh_port, "xapt list")
            if "xapt-test-app 1.0.0 [installed]" not in installed:
                raise RuntimeError(f"installed state missing: {installed!r}")
            publish_test_app(arch, repository, "1.0.1", 2, "v1")
            ssh(key, ssh_port, "xapt update")
            upgrade = ssh(key, ssh_port, "xapt upgrade xapt-test-app", 180)
            if "activated xapt-test-app 1.0.1 without reboot" not in upgrade:
                raise RuntimeError(f"pre-rotation upgrade failed: {upgrade!r}")
            ssh(key, ssh_port, "xapt rollback xapt-test-app")
            if "xapt-test-app 1.0.1 [upgradable]" not in ssh(
                    key, ssh_port, "xapt list"):
                raise RuntimeError("one-step rollback did not restore version 1.0.0")

            subprocess.run(
                ["python3", "tools/xaios_xapt_repo.py", "trust",
                 "--repository", str(repository), "--generation", "2",
                 "--mode", "rotate", "--active", "v2", "--revoke", "v1",
                 "--signer", "v1"], cwd=ROOT, check=True,
            )
            publish_test_app(arch, repository, "1.1.0", 3, "v2")
            ssh(key, ssh_port, "xapt update")
            upgrade = ssh(key, ssh_port, "xapt upgrade xapt-test-app", 180)
            if "activated xapt-test-app 1.1.0 without reboot" not in upgrade:
                raise RuntimeError(f"upgrade failed: {upgrade!r}")
            if "xapt-test-app 1.1.0 [installed]" not in ssh(key, ssh_port, "xapt list"):
                raise RuntimeError("upgraded version is not active")
            revoked_rollback = ssh_fails(
                key, ssh_port, "xapt rollback xapt-test-app"
            )
            if "rollback failed" not in revoked_rollback:
                raise RuntimeError(
                    f"revoked package rollback was not rejected: {revoked_rollback!r}"
                )

            publish_test_app(arch, repository, "1.2.0", 4, "v1")
            old_root_rejected = ssh_fails(key, ssh_port, "xapt update")
            if "catalog update failed" not in old_root_rejected:
                raise RuntimeError(
                    f"revoked release root was not rejected: {old_root_rejected!r}"
                )
            publish_test_app(arch, repository, "1.2.0", 4, "v2")
            ssh(key, ssh_port, "xapt update")
            payload = repository / "apps" / arch / "xapt-test-app" / "1.2.0" / "xapt-test-app.elf"
            payload.write_bytes(payload.read_bytes() + b"tampered")
            rejected = ssh_fails(key, ssh_port, "xapt upgrade xapt-test-app", 180)
            if "package rejected" not in rejected:
                raise RuntimeError(f"corrupted package was not rejected: {rejected!r}")
            if not ssh(key, ssh_port, "xapt-test-app still active").startswith(
                    "xapt-test-app still active\n"):
                raise RuntimeError("corrupted upgrade changed the active app")
            subprocess.run(
                ["python3", "tools/xaios_xapt_repo.py", "trust",
                 "--repository", str(repository), "--generation", "3",
                 "--mode", "recovery", "--active", "v1", "--revoke", "v2",
                 "--signer", "recovery", "--append"], cwd=ROOT, check=True,
            )
            publish_test_app(arch, repository, "1.2.0", 5, "v1")
            recovered = ssh(key, ssh_port, "xapt update")
            if "catalog verified and activated" not in recovered:
                raise RuntimeError(f"recovery-root transition failed: {recovered!r}")
            recovered_upgrade = ssh(
                key, ssh_port, "xapt upgrade xapt-test-app", 180
            )
            if "activated xapt-test-app 1.2.0 without reboot" not in recovered_upgrade:
                raise RuntimeError(
                    f"recovered root could not reactivate app: {recovered_upgrade!r}"
                )
            os_update = ssh(key, ssh_port, "xapt os-upgrade", 300)
            if "OS update staged and verified" not in os_update:
                raise RuntimeError(f"OS update failed: {os_update!r}")
        finally:
            stop_guest(guest)

        guest = start_guest(arch, ssh_port, persistent, log)
        try:
            wait_marker(log, READY)
            wait_ssh(key, ssh_port)
            if "xapt-test-app 1.2.0 [installed]" not in ssh(key, ssh_port, "xapt list"):
                raise RuntimeError("catalog or recovered version did not persist across reboot")
            if not ssh(key, ssh_port, "xapt-test-app reboot persisted").startswith(
                    "xapt-test-app reboot persisted\n"):
                raise RuntimeError("installed application did not persist across reboot")
            ssh(key, ssh_port, "xapt remove xapt-test-app")
            removed = ssh_fails(key, ssh_port, "xapt-test-app removed")
            if "not found" not in removed:
                raise RuntimeError(f"removed application remained executable: {removed!r}")
            print(f"qemu-xapt-gate: {arch}: PASS")
        finally:
            stop_guest(guest)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("aarch64", "x86_64", "all"), default="all")
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    key = BUILD / "xapt-gate-key"
    key.unlink(missing_ok=True)
    Path(f"{key}.pub").unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = f"{key}.pub"
    arches = ("aarch64", "x86_64") if args.arch == "all" else (args.arch,)
    for arch in arches:
        subprocess.run(
            ["make", "image" if arch == "aarch64" else "image-x86_64"],
            cwd=ROOT, env=env, check=True,
        )
        exercise(arch, key)
    print("qemu-xapt-gate: PASS: signed test package lifecycle on all requested architectures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
