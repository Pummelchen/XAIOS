#!/usr/bin/env python3
"""Drive the XAIOS outbound SSH/SCP client through an authenticated PTY."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time


PROMPT = b"admin@xaios"
PASSWORD_PROMPT = b"'s password: "
PASSPHRASE_PROMPT = b" key passphrase: "


class PtySession:
    def __init__(self, command: list[str], timeout: float) -> None:
        self.timeout = timeout
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert self.process.stdout is not None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.output = bytearray()
        self.cursor = 0

    def expect(self, marker: bytes, description: str) -> bytes:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            position = self.output.find(marker, self.cursor)
            if position >= 0:
                end = position + len(marker)
                result = bytes(self.output[self.cursor:end])
                self.cursor = end
                return result
            if self.process.poll() is not None:
                self._drain()
                break
            events = self.selector.select(timeout=0.25)
            if events:
                self._drain()
        tail = bytes(self.output[-4096:]).decode(errors="replace")
        raise RuntimeError(f"timed out waiting for {description}\n{tail}")

    def send(self, text: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(text.encode("ascii"))
        self.process.stdin.flush()

    def command(self, command: str, marker: bytes | None = None) -> bytes:
        print(f"XAIOS> {command}", flush=True)
        self.send(command + "\n")
        result = b""
        if marker is not None:
            result += self.expect(marker, repr(marker))
        result += self.expect(PROMPT, "XAIOS shell prompt")
        return result

    def password_command(
        self, command: str, password: str, marker: bytes
    ) -> bytes:
        print(f"XAIOS> {command}", flush=True)
        self.send(command + "\n")
        result = self.expect(PASSWORD_PROMPT, "outbound password prompt")
        self.send(password + "\n")
        result += self.expect(marker, repr(marker))
        result += self.expect(PROMPT, "XAIOS shell prompt")
        return result

    def passphrase_command(
        self, command: str, passphrase: str, marker: bytes
    ) -> bytes:
        print(f"XAIOS> {command}", flush=True)
        self.send(command + "\n")
        result = self.expect(PASSPHRASE_PROMPT, "outbound key passphrase prompt")
        self.send(passphrase + "\n")
        result += self.expect(marker, repr(marker))
        result += self.expect(PROMPT, "XAIOS shell prompt")
        return result

    def close(self) -> None:
        if self.process.poll() is None:
            self.send("exit\n")
        try:
            status = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            status = self.process.wait(timeout=5)
        if status != 0:
            tail = bytes(self.output[-4096:]).decode(errors="replace")
            raise RuntimeError(f"outer XAIOS SSH session failed: {status}\n{tail}")

    def _drain(self) -> None:
        assert self.process.stdout is not None
        while True:
            try:
                chunk = self.process.stdout.read(4096)
            except BlockingIOError:
                return
            if not chunk:
                return
            self.output.extend(chunk)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xaios-host", default="127.0.0.1")
    parser.add_argument("--xaios-port", required=True, type=int)
    parser.add_argument("--xaios-key", required=True, type=Path)
    parser.add_argument("--target-host", default="10.0.2.2")
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--target-user", default="xaios")
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--identity-passphrase-file", type=Path)
    parser.add_argument("--timeout", default=45.0, type=float)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = args.password_file.read_text(encoding="ascii").strip()
    if not password or "\n" in password or "\r" in password:
        raise RuntimeError("password fixture must contain one nonempty line")
    identity_passphrase = ""
    if args.identity_passphrase_file is not None:
        identity_passphrase = args.identity_passphrase_file.read_text(
            encoding="ascii"
        ).strip()
    endpoint = f"{args.target_user}@{args.target_host}"
    ssh = [
        "ssh",
        "-tt",
        "-i",
        str(args.xaios_key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PubkeyAuthentication=yes",
        "-p",
        str(args.xaios_port),
        f"admin@{args.xaios_host}",
    ]
    session = PtySession(ssh, args.timeout)
    failed = False
    try:
        session.expect(PROMPT, "initial XAIOS shell prompt")
        session.command("rm -rf /tmp/freebsd-upload")
        session.command("rm -rf /tmp/freebsd-download")
        session.command("rm -rf /tmp/freebsd-tree-copy")
        session.command("mkdir -p /tmp/freebsd-upload/nested")
        session.command(
            "echo xaios-freebsd-upload > /tmp/freebsd-upload/nested/data.txt"
        )
        remote_exec = (
            f"ssh -p {args.target_port} {endpoint} "
            "printf freebsd-outbound-ssh-ok"
        )
        first = session.password_command(
            remote_exec, password, b"freebsd-outbound-ssh-ok"
        )
        if b"permanently added host key" not in first:
            raise RuntimeError("first FreeBSD contact did not persist a host key")

        second = session.password_command(
            f"ssh -p {args.target_port} {endpoint} printf known-host-ok",
            password,
            b"known-host-ok",
        )
        if b"permanently added host key" in second:
            raise RuntimeError("known FreeBSD host key was added more than once")

        session.password_command(
            f"ssh -p {args.target_port} xaios@[fec0::2] "
            "printf freebsd-ipv6-ok",
            password,
            b"freebsd-ipv6-ok",
        )

        if args.identity_passphrase_file is not None:
            session.passphrase_command(
                f"ssh -i /etc/xaios_ssh_client_identity -p {args.target_port} "
                f"{endpoint} printf freebsd-publickey-ok",
                identity_passphrase,
                b"freebsd-publickey-ok",
            )

        print(f"XAIOS> ssh -p {args.target_port} {endpoint} true [wrong password]", flush=True)
        session.send(f"ssh -p {args.target_port} {endpoint} true\n")
        session.expect(PASSWORD_PROMPT, "outbound password prompt")
        session.send("definitely-wrong-password\n")
        session.expect(
            b"ssh: authentication failed",
            "wrong-password rejection",
        )
        session.expect(PROMPT, "XAIOS shell prompt")

        session.password_command(
            f"scp -r -P {args.target_port} /tmp/freebsd-upload "
            f"{endpoint}:/home/xaios/from-xaios",
            password,
            b"scp: transfer complete",
        )
        session.password_command(
            f"ssh -p {args.target_port} {endpoint} "
            "cat /home/xaios/from-xaios/nested/data.txt",
            password,
            b"xaios-freebsd-upload",
        )
        session.password_command(
            f"scp -r -P {args.target_port} "
            f"{endpoint}:/home/xaios/fixture /tmp/freebsd-download",
            password,
            b"scp: transfer complete",
        )
        session.command(
            "cat /tmp/freebsd-download/nested/source.txt",
            b"freebsd-to-xaios-scp",
        )
        session.password_command(
            f"scp -r -P {args.target_port} "
            f"{endpoint}:/home/xaios/from-xaios /tmp/freebsd-tree-copy",
            password,
            b"scp: transfer complete",
        )
        session.command(
            "cat /tmp/freebsd-tree-copy/nested/data.txt",
            b"xaios-freebsd-upload",
        )
    except BaseException:
        failed = True
        raise
    finally:
        try:
            session.close()
        except RuntimeError:
            if not failed:
                raise
    print("XAIOS_OUTBOUND_FREEBSD: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"XAIOS_OUTBOUND_FREEBSD: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
