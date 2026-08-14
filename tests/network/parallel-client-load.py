#!/usr/bin/env python3
"""Drive OpenSSH, SFTP, and UDP load from one host environment."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time


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


def run_preflight(args: argparse.Namespace, workdir: Path) -> None:
    expected = f"key-{args.client_id}-ok"
    result = ssh_command(args, f"echo {expected}")
    if result.stdout.strip() != expected:
        raise RuntimeError(f"authorized key output mismatch: {result.stdout!r}")

    unauthorized = ssh_command(
        args,
        "echo unauthorized-key-must-not-run",
        key=args.unauthorized_key,
        check=False,
    )
    if unauthorized.returncode == 0:
        raise RuntimeError("unauthorized Ed25519 key was accepted")

    password = args.password_file.read_text(encoding="ascii").rstrip("\r\n")
    accepted = password_command(args, workdir, password)
    expected_password = f"password-{args.client_id}-ok"
    if accepted.returncode != 0 or accepted.stdout.strip() != expected_password:
        raise RuntimeError(
            "correct password was rejected: "
            f"status={accepted.returncode} stderr={accepted.stderr!r}"
        )
    rejected = password_command(args, workdir, "definitely-wrong-password")
    if rejected.returncode == 0:
        raise RuntimeError("wrong password was accepted")

    source = workdir / "preflight-source.bin"
    result_path = workdir / "preflight-result.bin"
    source.write_bytes(payload_bytes(args.client_id, 0))
    remote_dir = f"/tmp/load-{args.client_id}-preflight"
    batch = "\n".join(
        [
            f"mkdir {remote_dir}",
            f"put {source} {remote_dir}/original.bin",
            f"ls -l {remote_dir}/original.bin",
            f"rename {remote_dir}/original.bin {remote_dir}/renamed.bin",
            f"get {remote_dir}/renamed.bin {result_path}",
            f"rm {remote_dir}/renamed.bin",
            f"rmdir {remote_dir}",
            "quit",
            "",
        ]
    )
    sftp = sftp_command(args, batch)
    if sftp.returncode != 0:
        raise RuntimeError(f"SFTP preflight failed: {sftp.stderr or sftp.stdout}")
    if result_path.read_bytes() != source.read_bytes():
        raise RuntimeError("SFTP preflight payload mismatch")
    udp_echo(args, args.udp_count, "preflight")
    print(
        f"PASS: {args.client_id} auth rejection SFTP stat/rename and "
        f"UDP preflight count={args.udp_count}",
        flush=True,
    )


class ControlMaster:
    def __init__(
        self, args: argparse.Namespace, workdir: Path, worker: int
    ) -> None:
        self.args = args
        self.socket_path = workdir / f"cm-{worker}.sock"
        self.log_path = workdir / f"cm-{worker}.log"
        self.log_file = self.log_path.open("wb")
        self.process = subprocess.Popen(
            [
                "ssh", *key_options(args),
                "-M", "-S", str(self.socket_path),
                "-o", "ControlMaster=yes",
                "-o", "ControlPersist=no",
                "-o", "RekeyLimit=4K",
                "-N", "-p", str(args.ssh_port),
                f"admin@{args.host}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline:
            if self.socket_path.exists():
                check = subprocess.run(
                    [
                        "ssh", "-F", "/dev/null", "-S",
                        str(self.socket_path), "-O", "check",
                        f"admin@{self.args.host}",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                if check.returncode != 0:
                    time.sleep(0.05)
                    continue
                return
            if self.process.poll() is not None:
                self.log_file.flush()
                detail = self.log_path.read_text(errors="replace")
                raise RuntimeError(f"control master exited early: {detail}")
            time.sleep(0.05)
        self.close()
        raise TimeoutError("control master socket was not created")

    def close(self) -> None:
        if self.process.poll() is None:
            subprocess.run(
                [
                    "ssh", "-F", "/dev/null", "-S", str(self.socket_path),
                    "-O", "exit", f"admin@{self.args.host}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        self.log_file.close()


def stress_worker(
    args: argparse.Namespace,
    workdir: Path,
    worker: int,
    master: ControlMaster,
) -> None:
    source = workdir / f"source-{worker}.bin"
    source.write_bytes(payload_bytes(args.client_id, worker))
    remote_dir = f"/tmp/load-{args.client_id}-{worker}"
    batch_lines = [f"mkdir {remote_dir}"]
    result_paths: list[Path] = []
    for cycle in range(args.cycles):
        first = workdir / f"result-{worker}-{cycle}.bin"
        second = workdir / f"renamed-{worker}-{cycle}.bin"
        result_paths.extend([first, second])
        batch_lines.extend(
            [
                f"put {source} {remote_dir}/payload.bin",
                f"ls -l {remote_dir}/payload.bin",
                f"get {remote_dir}/payload.bin {first}",
                f"rename {remote_dir}/payload.bin {remote_dir}/renamed.bin",
                f"get {remote_dir}/renamed.bin {second}",
                f"rm {remote_dir}/renamed.bin",
            ]
        )
    batch_lines.extend([f"rmdir {remote_dir}", "quit", ""])

    def transfer() -> None:
        result = sftp_command(
            args,
            "\n".join(batch_lines),
            control_path=master.socket_path,
            timeout=max(COMMAND_TIMEOUT, args.timeout),
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"worker {worker} SFTP failed: {result.stderr or result.stdout}"
            )

    def execute() -> None:
        for cycle in range(args.cycles * 2):
            marker = f"exec-{args.client_id}-{worker}-{cycle}"
            result = ssh_command(
                args,
                f"echo {marker}",
                control_path=master.socket_path,
                timeout=max(COMMAND_TIMEOUT, args.timeout),
            )
            if result.stdout.strip() != marker:
                raise RuntimeError(
                    f"worker {worker} exec output mismatch: {result.stdout!r}"
                )

    with ThreadPoolExecutor(max_workers=2) as pool:
        transfer_future = pool.submit(transfer)
        execute_future = pool.submit(execute)
        transfer_future.result()
        execute_future.result()

    expected = source.read_bytes()
    for path in result_paths:
        if path.read_bytes() != expected:
            raise RuntimeError(f"worker {worker} payload mismatch: {path.name}")


def wait_for_start(
    path: Path,
    timeout: float,
    args: argparse.Namespace,
    master: ControlMaster,
) -> None:
    deadline = time.monotonic() + timeout
    audit_captured = False
    while time.monotonic() < deadline:
        if (
            not audit_captured
            and args.audit_request_file is not None
            and args.audit_output_file is not None
            and args.audit_request_file.exists()
        ):
            result = ssh_command(
                args,
                "cat /state/sshd.log",
                control_path=master.socket_path,
            )
            args.audit_output_file.write_text(result.stdout, encoding="utf-8")
            audit_captured = True
        if path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for start signal {path}")


def run_stress(args: argparse.Namespace, workdir: Path) -> None:
    if args.ready_file is None or args.start_file is None:
        raise RuntimeError("stress mode requires --ready-file and --start-file")
    masters: list[ControlMaster] = []
    try:
        for worker in range(args.workers):
            masters.append(ControlMaster(args, workdir, worker))
        args.ready_file.write_text(f"workers={args.workers}\n", encoding="ascii")
        print(f"READY: {args.client_id} workers={args.workers}", flush=True)
        wait_for_start(args.start_file, args.timeout, args, masters[0])
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=args.workers + 1) as pool:
            futures = [
                pool.submit(stress_worker, args, workdir, worker, masters[worker])
                for worker in range(args.workers)
            ]
            futures.append(
                pool.submit(udp_echo, args, args.udp_count, "stress")
            )
            for future in futures:
                future.result()
        remaining = args.minimum_seconds - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
        print(
            f"PASS: {args.client_id} stress workers={args.workers} "
            f"cycles={args.cycles} udp={args.udp_count}",
            flush=True,
        )
    finally:
        for master in masters:
            master.close()


def run_reconnect(args: argparse.Namespace) -> None:
    for index in range(args.reconnects):
        marker = f"reconnect-{args.client_id}-{index}"
        result = ssh_command(args, f"echo {marker}", check=False)
        if result.returncode != 0:
            detail = " ".join((result.stderr or result.stdout).split())
            raise RuntimeError(
                f"reconnect {index} transport failed rc={result.returncode} "
                f"detail={detail[:240]!r}"
            )
        if result.stdout.strip() != marker:
            raise RuntimeError(f"reconnect {index} output mismatch: {result.stdout!r}")
    print(
        f"PASS: {args.client_id} reconnects={args.reconnects}", flush=True
    )


def run_health(args: argparse.Namespace) -> None:
    marker = f"health-{args.client_id}-ok"
    result = ssh_command(args, f"echo {marker}")
    if result.stdout.strip() != marker:
        raise RuntimeError(f"health output mismatch: {result.stdout!r}")
    udp_echo(args, max(args.udp_count, 1), "health")
    print(f"PASS: {args.client_id} post-load health", flush=True)


def run_expected_rejection(args: argparse.Namespace) -> None:
    started = time.monotonic()
    try:
        result = ssh_command(
            args,
            "echo over-capacity-must-not-run",
            check=False,
            timeout=20.0,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        print(
            f"PASS: {args.client_id} over-capacity connection rejected "
            f"after={elapsed:.2f}s detail='bounded banner timeout'",
            flush=True,
        )
        return
    if result.returncode == 0 or "over-capacity-must-not-run" in result.stdout:
        raise RuntimeError("server admitted a connection above its declared limit")
    elapsed = time.monotonic() - started
    detail = " ".join((result.stderr or result.stdout).split())
    print(
        f"PASS: {args.client_id} over-capacity connection rejected "
        f"after={elapsed:.2f}s detail={detail[:240]!r}",
        flush=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("preflight", "stress", "reconnect", "health", "expect-rejected"),
        required=True,
    )
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--udp-port", type=int, required=True)
    parser.add_argument("--authorized-key", type=Path, required=True)
    parser.add_argument("--unauthorized-key", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--cycles", type=int, default=4)
    parser.add_argument("--udp-count", type=int, default=20)
    parser.add_argument("--reconnects", type=int, default=20)
    parser.add_argument("--minimum-seconds", type=float, default=0.0)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--start-file", type=Path)
    parser.add_argument("--audit-request-file", type=Path)
    parser.add_argument("--audit-output-file", type=Path)
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 16:
        parser.error("--workers must be between 1 and 16")
    if args.cycles < 1 or args.udp_count < 0 or args.reconnects < 1:
        parser.error("counts must be positive (UDP may be zero)")
    return args


def main() -> int:
    args = parse_args()
    for tool in ("ssh", "sftp"):
        require_tool(tool)
    with tempfile.TemporaryDirectory(prefix=f"xaios-{args.client_id}-") as temp:
        workdir = Path(temp)
        if args.mode == "preflight":
            run_preflight(args, workdir)
        elif args.mode == "stress":
            run_stress(args, workdir)
        elif args.mode == "reconnect":
            run_reconnect(args)
        elif args.mode == "health":
            run_health(args)
        else:
            run_expected_rejection(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TimeoutError,
    ) as error:
        print(f"FAIL: {error}", flush=True)
        raise SystemExit(1)
