#!/usr/bin/env python3
"""Verify source fragmentation on AArch64 and x86_64 QEMU guests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
READY = "SSH server: up and running (tcp/22)"
REPORT = BUILD / "qemu-outbound-fragmentation-report.json"


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_marker(path: Path, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and marker in path.read_text(errors="replace"):
            return
        time.sleep(0.25)
    tail = ""
    if path.exists():
        tail = "\n".join(path.read_text(errors="replace").splitlines()[-80:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def run_architecture(architecture: str) -> dict[str, object]:
    socket_port = reserve_port()
    ssh_port = reserve_port()
    log_path = BUILD / f"qemu-outbound-fragmentation-{architecture}.log"
    persistent = BUILD / f"qemu-outbound-fragmentation-{architecture}.img"
    persistent.unlink(missing_ok=True)
    runner = (
        ROOT / "scripts" / "run-qemu-aarch64.sh"
        if architecture == "aarch64"
        else ROOT / "scripts" / "run-qemu-x86_64.sh"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port),
            "XAIOS_QEMU_NET_SOCKET_HOST": "127.0.0.1",
            "XAIOS_QEMU_NET_SOCKET_PORT": str(socket_port),
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
        }
    )
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(runner)],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_marker(log_path, READY, 180.0)
            command = [
                sys.executable,
                str(ROOT / "tests" / "network" / "qemu-ipv6-tcp-client.py"),
                "--host",
                "127.0.0.1",
                "--port",
                str(socket_port),
                "--timeout",
                "60",
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    f"{architecture} raw client failed\n"
                    f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
                )
            for marker in (
                "outbound_ipv4_fragments=2",
                "outbound_ipv6_fragments=2",
            ):
                if marker not in completed.stdout:
                    raise RuntimeError(
                        f"{architecture} client omitted {marker!r}: "
                        f"{completed.stdout}"
                    )
            return {
                "status": "pass",
                "ipv4_fragments": 2,
                "ipv6_fragments": 2,
                "guest_log": str(log_path),
                "client_output": completed.stdout.strip(),
            }
        finally:
            stop(process)
            persistent.unlink(missing_ok=True)


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    results: dict[str, object] = {}
    try:
        for architecture in ("aarch64", "x86_64"):
            print(f"qemu-outbound-fragmentation: testing {architecture}", flush=True)
            results[architecture] = run_architecture(architecture)
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        results["error"] = str(error)
        REPORT.write_text(
            json.dumps(
                {
                    "schema": "xaios.qemu.outbound_fragmentation.v1",
                    "status": "fail",
                    "results": results,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"FAIL: {error}; report={REPORT}", file=sys.stderr)
        return 1

    REPORT.write_text(
        json.dumps(
            {
                "schema": "xaios.qemu.outbound_fragmentation.v1",
                "status": "pass",
                "qemu_correctness_only": True,
                "architectures": results,
                "duration_seconds": round(time.monotonic() - started, 3),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"PASS: AArch64/x86_64 outbound fragmentation report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
