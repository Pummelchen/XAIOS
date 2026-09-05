#!/usr/bin/env python3
"""Verify source fragmentation on every QEMU guest this project builds.

The guest is asked for more than a link's worth of data over IPv6 and has to
break it up itself. What differs per architecture is the driver underneath --
the descriptor chain a fragment is handed to, and whether the queue is
serviced by an interrupt or a poll -- so the same exchange run on three
machines is three tests, not one repeated.
"""

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
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (QEMU_ARCHES, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

READY = "SSH server: up and running (tcp/22)"
REPORT = BUILD / "qemu-outbound-fragmentation-report.json"


def requested_architectures(argv: list[str]) -> tuple[str, ...]:
    """--arch NAME selects one; without it, every machine this builds for."""
    for index, argument in enumerate(argv):
        name = None
        if argument == "--arch" and index + 1 < len(argv):
            name = argv[index + 1]
        elif argument.startswith("--arch="):
            name = argument.split("=", 1)[1]
        if name is not None:
            if name not in QEMU_ARCHES:
                raise SystemExit(f"unsupported --arch {name!r}")
            return (name,)
    return QEMU_ARCHES


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
    runner = ROOT / qemu_runner(architecture)
    environment = qemu_boot_environment(
        architecture, os.environ.copy(),
        accel="tcg", smp=4, hostfwd_port=ssh_port,
        net_socket_host="127.0.0.1", net_socket_port=socket_port,
        persistent=persistent,
        state_dir=BUILD / f"qemu-outbound-fragmentation-{architecture}-state",
        # The console goes into log_path below, and the RISC-V runner would
        # otherwise write it to a file of its own and leave that empty.
        serial_to_stdout=True)
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
            wait_for_marker(log_path, READY,
                            float(smoke_timeout(architecture, 180)))
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
    architectures = requested_architectures(sys.argv[1:])
    try:
        for architecture in architectures:
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
    print(f"PASS: outbound fragmentation on "
          f"{', '.join(architectures)}; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
