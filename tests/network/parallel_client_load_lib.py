#!/usr/bin/env python3
"""Client transport primitives for the parallel network load driver.

Moved verbatim out of `parallel-client-load.py`. This half is everything that
knows how to build and run one client exchange and nothing about which mode is
running: the required-tool lookup, the shared key options, the ssh, password
and sftp command wrappers, the deterministic payload and the UDP echo loop
with its three retries. Every name below is imported by the driver, which
keeps the preflight, the control master, the mode runners and the command
line, and remains the only entry point.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess


COMMAND_TIMEOUT = 90.0


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required client tool is unavailable: {name}")


def key_options(args: argparse.Namespace) -> list[str]:
    return [
        "-F", "/dev/null",
        "-i", str(args.authorized_key),
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "ConnectTimeout=60",
        "-o", "ServerAliveInterval=2",
        "-o", "ServerAliveCountMax=15",
        "-o", "LogLevel=ERROR",
    ]


def run_command(
    command: list[str],
    *,
    timeout: float = COMMAND_TIMEOUT,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def ssh_command(
    args: argparse.Namespace,
    remote_command: str,
    *,
    key: Path | None = None,
    control_path: Path | None = None,
    check: bool = True,
    timeout: float = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    options = key_options(args)
    if key is not None:
        key_index = options.index(str(args.authorized_key))
        options[key_index] = str(key)
    if control_path is not None:
        options.extend(
            ["-S", str(control_path), "-o", "ControlMaster=auto"]
        )
    return run_command(
        [
            "ssh", *options, "-p", str(args.ssh_port),
            f"admin@{args.host}", remote_command,
        ],
        check=check,
        timeout=timeout,
    )


def password_command(
    args: argparse.Namespace, workdir: Path, password: str
) -> subprocess.CompletedProcess[str]:
    askpass = workdir / "askpass.sh"
    askpass.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$XAIOS_TEST_PASSWORD\"\n",
        encoding="ascii",
    )
    askpass.chmod(0o700)
    env = os.environ.copy()
    env.update(
        {
            "DISPLAY": "xaios-test:0",
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            "XAIOS_TEST_PASSWORD": password,
        }
    )
    command = [
        "ssh", "-F", "/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "ConnectTimeout=60",
        "-o", "LogLevel=ERROR",
        "-p", str(args.ssh_port),
        f"admin@{args.host}",
        f"echo password-{args.client_id}-ok",
    ]
    return run_command(command, env=env, check=False)


def sftp_command(
    args: argparse.Namespace,
    batch: str,
    *,
    control_path: Path | None = None,
    timeout: float = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    options = key_options(args)
    if control_path is not None:
        options.extend(
            ["-o", f"ControlPath={control_path}",
             "-o", "ControlMaster=auto"]
        )
    return subprocess.run(
        [
            "sftp", *options, "-b", "-", "-P", str(args.ssh_port),
            f"admin@{args.host}",
        ],
        input=batch,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def payload_bytes(client_id: str, worker: int) -> bytes:
    seed = sum(client_id.encode("utf-8")) + worker * 29
    return bytes((index * 37 + seed) & 0xFF for index in range(8170))


def udp_echo(args: argparse.Namespace, count: int, label: str) -> None:
    address = socket.gethostbyname(args.host)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(10.0)
        for index in range(count):
            payload = f"xaios-{args.client_id}-{label}-{index:04d}".encode("ascii")
            for attempt in range(3):
                client.sendto(payload, (address, args.udp_port))
                try:
                    response, _ = client.recvfrom(4096)
                except socket.timeout:
                    if attempt == 2:
                        raise
                    continue
                if response != payload:
                    raise RuntimeError(
                        f"UDP payload mismatch index={index}: {response!r}"
                    )
                break
