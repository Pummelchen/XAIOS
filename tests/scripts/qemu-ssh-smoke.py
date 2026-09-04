#!/usr/bin/env python3
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SMOKE_PORT = "2299"


def wait_for_port(port: int, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        probe = subprocess.run(
            ["sh", "-c", f"lsof -nP -iTCP:{port} -sTCP:LISTEN >/dev/null 2>&1"],
            cwd=ROOT,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError(f"port {port} did not open")


def run_ssh(command: str) -> str:
    result = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            # See qemu-model-sftp-gate: a ~/.ssh/config that disables public
            # key authentication for this host would otherwise stop the key
            # being offered at all, on that machine only.
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "PreferredAuthentications=none,publickey",
            "-p",
            SMOKE_PORT,
            "admin@localhost",
            command,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ssh command failed rc={result.returncode}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout


def main() -> int:
    bridge = subprocess.Popen(
        ["./scripts/run-xaios-ssh-bridge.sh"],
        cwd=ROOT,
        env={**os.environ, "XAIOS_SSH_PORT": SMOKE_PORT},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )
    try:
        wait_for_port(int(SMOKE_PORT), 45.0)
        if bridge.poll() is not None:
            output = bridge.stdout.read() if bridge.stdout is not None else ""
            raise RuntimeError(
                f"xaios ssh bridge exited before smoke test rc={bridge.returncode}\n{output}"
            )
        status = run_ssh("status")
        if "legacy status command" not in status:
            raise RuntimeError(f"missing status marker: {status!r}")
        listing = run_ssh("ls /")
        if "bin\n" not in listing or "state\n" not in listing:
            raise RuntimeError(f"missing ls marker: {listing!r}")
        sysinfo = run_ssh("sysinfo")
        if "legacy sysinfo command" not in sysinfo:
            raise RuntimeError(f"missing sysinfo marker: {sysinfo!r}")
        run_ssh("nano /state/ssh-editor.txt --write 'alpha\\nbeta'")
        run_ssh("nano /state/ssh-editor.txt --insert 2 inserted")
        run_ssh("nano /state/ssh-editor.txt --replace 1 first")
        run_ssh("nano /state/ssh-editor.txt --delete 3")
        run_ssh("nano /state/ssh-editor.txt --append tail")
        editor = run_ssh("nano /state/ssh-editor.txt --number")
        if editor != "1  first\n2  inserted\n3  tail\n":
            raise RuntimeError(f"nano edit mismatch: {editor!r}")
        process_table = run_ssh(
            "xtop --all --sample-ms 10 --cpu-start 0 --cpu-count 2"
        )
        if "CPU CPU% BUSY_MS IDLE_MS ACTIVE ROLE" not in process_table:
            raise RuntimeError(f"missing xtop CPU header: {process_table!r}")
        if not re.search(r"^0 [0-9]+\.[0-9]%", process_table, re.MULTILINE):
            raise RuntimeError(f"missing xtop CPU percentage: {process_table!r}")
        if "MEM bridge=" not in process_table:
            raise RuntimeError(f"missing xtop memory percentage: {process_table!r}")
        if "PID PPID S CPU% MEM% TIME_MS RES_KIB CPU SYSCALLS COMMAND" not in process_table:
            raise RuntimeError(f"missing xtop header: {process_table!r}")
        if "/bin/xaios-ssh-bridge" not in process_table:
            raise RuntimeError(f"missing xtop process row: {process_table!r}")
        if "cpu_shown=" not in process_table or "cpu_total=" not in process_table:
            raise RuntimeError(f"missing xtop pagination: {process_table!r}")
        run_ssh("rm /state/ssh-editor.txt")
        print("qemu-ssh-smoke: OpenSSH client reached XAIOS remote login")
        return 0
    finally:
        try:
            os.killpg(os.getpgid(bridge.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = bridge.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(bridge.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = bridge.communicate(timeout=5)
        if bridge.returncode not in (0, -signal.SIGTERM):
            print(output, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
