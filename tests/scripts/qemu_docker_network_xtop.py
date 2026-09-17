#!/usr/bin/env python3
"""Remote host-key and native PTY checks for the Debian 13 network suite.

Moved verbatim out of `qemu-docker-network-suite.py`. Both checks drive the
Debian container's OpenSSH clients at the guest over the forwarded port:
`scan_host_key` reads the advertised Ed25519 key, and `verify_native_xtop_pty`
runs xtop, the shell, and Pong under a PTY and reads the byte stream and the
rebuilt screen.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from pathlib import Path

from qemu_docker_network_harness import (
    ROOT, TARGET_ARCH, XTOP_TIMEOUT_SECONDS, docker_command, render_terminal)


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


def verify_native_xtop_pty(key_dir: Path, port: int) -> None:
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

    def run_guest(command: str, timeout: int = XTOP_TIMEOUT_SECONDS) -> bytes:
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
        b"/bin/helloworldc99",
        b"/bin/sysinfo",
        b"/bin/lstm-xor",
        b"/bin/app-fail",
        b"/bin/app-crash",
    )
    initial_processes = run_guest("xtop --plain --sample-ms 10")
    unexpected = [path for path in transient_paths if path in initial_processes]
    if unexpected:
        raise RuntimeError(
            f"normal boot pre-ran transient applications: {unexpected!r}"
        )

    for command, marker in (
        ("hello", b"hello: complete"),
        ("helloworldc99", b"/bin/helloworldc99: Hello, World!"),
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

    crashed_app = subprocess.run(
        docker_command(key_dir, *ssh_base, "app-crash"),
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    if (crashed_app.returncode != 1 or
            b"app-crash: exit status 128" not in crashed_app.stdout):
        raise RuntimeError(
            "faulting application was not isolated and reaped: "
            + (crashed_app.stdout + crashed_app.stderr).decode(errors="replace")
        )
    if run_guest("pwd").strip() != b"/":
        raise RuntimeError("SSH command engine did not survive a user fault")

    final_processes = run_guest("xtop --plain --sample-ms 10")
    unreaped = [path for path in transient_paths if path in final_processes]
    if unreaped:
        raise RuntimeError(f"transient applications were not reaped: {unreaped!r}")

    colored = subprocess.Popen(
        docker_command(
            key_dir,
            *ssh_base[:1],
            "-tt",
            *ssh_base[1:],
            "xtop",
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
        raise RuntimeError("native xtop PTY did not render its initial dashboard")
    assert colored.stdin is not None
    # A pause between keystrokes, scaled to the machine. Seventy-five
    # milliseconds is a comfortable gap for a program redrawing under one
    # emulator and not for another: on RISC-V the help overlay had not been
    # drawn before the next key arrived, and the gate reported a missing
    # marker as though the overlay did not exist.
    key_delay = 0.075 * (4 if TARGET_ARCH == "riscv64" else 1)
    for keys in (b"M", b"/sshd\n", b"h", b"h", b"q"):
        colored.stdin.write(keys)
        colored.stdin.flush()
        time.sleep(key_delay)
    colored.stdin.close()
    returncode = colored.wait(timeout=XTOP_TIMEOUT_SECONDS)
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if returncode != 0:
        raise RuntimeError(
            "native xtop PTY command failed: "
            + bytes(colored_stderr).decode(errors="replace")
        )
    required = (
        b"\x1b[?1049h",
        b"\x1b[2J\x1b[H",
        # Black on the header's green, which is what \x1b[42;30m used to be.
        #
        # The old marker was the basic-colour form, and it stopped appearing
        # when xtop moved its drawing into the screen framework's cells: the
        # framework emits every colour as 256-colour SGR from the cell it is
        # painting, so the header now arrives as this. The gate went red on
        # every architecture and stayed red because nothing had run it since.
        b"\x1b[0;38;5;0;48;5;70m",
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
        # The help screen, by three of its lines rather than by its title.
        #
        # The title is on the screen -- a person pressing h sees
        # "XAIOS xtop help" in the top rule -- but it is not in the byte
        # stream as one run. The framework sends only the cells that changed,
        # and the rule's leading corner and dashes match the frame underneath,
        # so the title arrives split around cursor moves. Body lines differ
        # from the frame beneath them along their whole width and arrive
        # whole, which is what a grep over a stream can actually check.
        b"Up/Down, j/k   select process",
        b"P/M/T/N/S/C    sort CPU/memory/time/PID/syscalls/command",
        b"Press F1, h, Escape or q to return.",
        b"60 frames/s",
        b"F10",
        b"Quit",
        b"\x1b[?25h",
        b"\x1b[?1049l",
        # Handing the terminal back, in full: show the cursor, leave the
        # alternate screen, reset attributes, show the cursor again, return
        # to column one. xtop sends the restore twice over on purpose, once
        # inside the alternate screen and once after leaving it, and both
        # copies have to arrive -- the second was truncated for a while
        # because its length was written out beside the string as 24 for 29
        # bytes, and nothing noticed because the first copy is enough to make
        # the terminal usable.
        b"\x1b[?25h\x1b[?1049l\x1b[0m\x1b[?25h\r",
    )
    missing = [marker for marker in required if marker not in colored_stdout]
    if missing:
        raise RuntimeError(f"native xtop PTY output missing markers: {missing!r}")

    # The screen, rebuilt from the stream, rather than the stream read as a
    # transcript.
    #
    # This block used to strip the escapes, split on newlines and look at the
    # lines. That worked while xtop printed whole frames; it draws into the
    # screen framework's cells now and only the cells that changed are sent,
    # so there are no lines to split on and a row arrives in pieces. Replaying
    # the stream into a grid is what the terminal on the other end does, and
    # it is the only way to ask what is actually on the screen.
    #
    # The layout being checked is also the current one. The old checks looked
    # for htop-style bracket meters -- `0[`, `Mem[`, `Swp[` in aligned columns
    # -- which xtop has not drawn since it was redrawn after mactop: cores are
    # bars inside a Cores panel, and memory and swap share one panel heading.
    # The properties are the same and are asserted here against what is drawn.
    screen = render_terminal(bytes(colored_stdout))
    core_meter = re.compile(r"\s(\d)\s+[\u2588\u2591]+\s+\d+\.\d%")
    cores = {match.group(1) for line in screen
             for match in [core_meter.search(line)] if match}
    if not {"0", "1", "2", "3"} <= cores:
        raise RuntimeError(
            f"native xtop did not draw a meter for every core: saw {sorted(cores)}")
    memory_panel = next(
        (line for line in screen
         if re.search(r"Mem\s+\S+ / \S+\s+\(Swap \S+ / \S+\)\s+\d+\.\d%", line)),
        None)
    if memory_panel is None:
        raise RuntimeError(
            "native xtop did not report memory and swap with a percentage")
    if not any("Tasks:" in line and "0 failed" in line for line in screen):
        raise RuntimeError(
            "native xtop visible task status did not report zero failures")
    if not any("Load average:" in line for line in screen):
        raise RuntimeError("native xtop did not report a load average")
    if not any("Uptime:" in line for line in screen):
        raise RuntimeError("native xtop did not report an uptime")
    footer = next((line for line in screen if "F10Quit" in line), None)
    if footer is None or "F1Help" not in footer:
        raise RuntimeError("native xtop footer did not use segmented key labels")

    shell = subprocess.Popen(
        docker_command(
            key_dir,
            *ssh_base[:1],
            "-tt",
            *ssh_base[1:],
        ),
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    shell_stdout = bytearray()
    shell_stderr = bytearray()
    shell_prompt_ready = threading.Event()
    shell_dashboard_ready = threading.Event()
    shell_xtop_returned = threading.Event()
    shell_listing_ready = threading.Event()

    def drain_shell(stream: object, output: bytearray,
                    inspect: bool = False) -> None:
        while True:
            chunk = stream.read1(4096)  # type: ignore[union-attr]
            if not chunk:
                return
            output.extend(chunk)
            if not inspect:
                continue
            prompt_count = output.count(b"admin@xaios")
            if prompt_count >= 1:
                shell_prompt_ready.set()
            if b"[Main]" in output:
                shell_dashboard_ready.set()
            if prompt_count >= 2:
                shell_xtop_returned.set()
            if prompt_count >= 3 and b"etc\r\nbin\r\nstate\r\n" in output:
                shell_listing_ready.set()

    shell_stdout_thread = threading.Thread(
        target=drain_shell, args=(shell.stdout, shell_stdout, True), daemon=True
    )
    shell_stderr_thread = threading.Thread(
        target=drain_shell, args=(shell.stderr, shell_stderr), daemon=True
    )
    shell_stdout_thread.start()
    shell_stderr_thread.start()
    assert shell.stdin is not None
    if not shell_prompt_ready.wait(30):
        shell.kill()
        shell.wait(timeout=5)
        raise RuntimeError("interactive shell did not render its initial prompt")
    shell.stdin.write(b"xtop\n")
    shell.stdin.flush()
    if not shell_dashboard_ready.wait(30):
        shell.kill()
        shell.wait(timeout=5)
        raise RuntimeError("shell-launched xtop did not render its dashboard")
    shell.stdin.write(b"q")
    shell.stdin.flush()
    if not shell_xtop_returned.wait(30):
        shell.kill()
        shell.wait(timeout=5)
        raise RuntimeError("xtop did not restore the interactive shell prompt")
    shell.stdin.write(b"ls /\n")
    shell.stdin.flush()
    if not shell_listing_ready.wait(30):
        shell.kill()
        shell.wait(timeout=5)
        raise RuntimeError("post-xtop shell listing was not left aligned")
    shell.stdin.write(b"exit\n")
    shell.stdin.close()
    shell_returncode = shell.wait(timeout=XTOP_TIMEOUT_SECONDS)
    shell_stdout_thread.join(timeout=5)
    shell_stderr_thread.join(timeout=5)
    if shell_returncode != 0:
        raise RuntimeError(
            "post-xtop interactive shell failed: "
            + bytes(shell_stderr).decode(errors="replace")
        )
    # The restore is asserted on xtop's own stream, above, where it is sent.
    #
    # It was asserted here, on a later plain shell session, which never sends
    # it and has nothing to restore: that session does not enter the alternate
    # screen. The check could not have passed, and it never ran, because the
    # meter checks above it were failing first. What it means to assert -- the
    # full-screen program hands the terminal back -- belongs to the program
    # that took it.
    listing_start = shell_stdout.find(b"ls /\r\n")
    listing_end = shell_stdout.find(b"admin@xaios", listing_start + 6)
    if listing_start < 0 or listing_end < 0:
        raise RuntimeError("post-xtop shell listing boundaries were not found")
    listing = shell_stdout[listing_start + 6:listing_end]
    bare_newline = next(
        (index for index, value in enumerate(listing)
         if value == 10 and (index == 0 or listing[index - 1] != 13)),
        None,
    )
    if bare_newline is not None:
        raise RuntimeError(
            f"post-xtop PTY output contained a bare LF at offset {bare_newline}"
        )

    plain = subprocess.run(
        docker_command(
            key_dir,
            *ssh_base,
            "xtop --all --sample-ms 10 --cpu-count 2 --plain",
        ),
        cwd=ROOT,
        capture_output=True,
        timeout=XTOP_TIMEOUT_SECONDS,
    )
    if plain.returncode != 0:
        raise RuntimeError(
            "native xtop plain command failed: "
            + plain.stderr.decode(errors="replace")
        )
    if b"\x1b[" in plain.stdout or b"CPU CPU% BUSY_MS" not in plain.stdout:
        raise RuntimeError("native xtop non-PTY output did not remain plain text")
    cpu_zero = re.search(rb"(?m)^0 ([0-9]+\.[0-9])% ", plain.stdout)
    if cpu_zero is None:
        raise RuntimeError("native xtop plain output lacked CPU 0 utilization")
    cpu_zero_tenths = int(cpu_zero.group(1).replace(b".", b""))
    if cpu_zero_tenths >= 1000:
        raise RuntimeError(
            "native xtop sampling saturated housekeeping CPU 0: "
            + cpu_zero.group(1).decode()
            + "%"
        )

    invalid = subprocess.run(
        docker_command(
            key_dir,
            *ssh_base[:1],
            "-tt",
            *ssh_base[1:],
            "xtop --sort invalid",
        ),
        cwd=ROOT,
        capture_output=True,
        timeout=XTOP_TIMEOUT_SECONDS,
    )
    invalid_output = invalid.stdout + invalid.stderr
    if invalid.returncode == 0 or b"xtop: invalid --sort key" not in invalid_output:
        raise RuntimeError("native xtop PTY accepted an invalid sort key")

    pong = subprocess.Popen(
        docker_command(
            key_dir,
            *ssh_base[:1],
            "-tt",
            *ssh_base[1:],
            "pong",
        ),
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    pong_stdout = bytearray()
    pong_stderr = bytearray()
    pong_ready = threading.Event()

    def drain_pong(stream: object, output: bytearray,
                   inspect: bool = False) -> None:
        while True:
            chunk = stream.read1(4096)  # type: ignore[union-attr]
            if not chunk:
                return
            output.extend(chunk)
            if inspect and b"PONG  Human wins: 0  Computer wins: 0" in output:
                pong_ready.set()

    pong_stdout_thread = threading.Thread(
        target=drain_pong, args=(pong.stdout, pong_stdout, True), daemon=True
    )
    pong_stderr_thread = threading.Thread(
        target=drain_pong, args=(pong.stderr, pong_stderr), daemon=True
    )
    pong_stdout_thread.start()
    pong_stderr_thread.start()
    if not pong_ready.wait(30):
        pong.kill()
        pong.wait(timeout=5)
        raise RuntimeError("native Pong PTY did not render its initial frame")
    assert pong.stdin is not None
    pong.stdin.write(b"wsppq")
    pong.stdin.flush()
    pong.stdin.close()
    pong_returncode = pong.wait(timeout=30)
    pong_stdout_thread.join(timeout=5)
    pong_stderr_thread.join(timeout=5)
    if pong_returncode != 0:
        raise RuntimeError(
            "native Pong PTY command failed: "
            + bytes(pong_stderr).decode(errors="replace")
        )
    pong_required = (
        b"\x1b[?1049h",
        b"PONG  Human wins: 0  Computer wins: 0",
        b"Speed: 100.00%",
        b"W/S move",
        b"Computer wins",
        b"\x1b[?1049l",
        b"\x1b[?25h",
    )
    pong_missing = [marker for marker in pong_required if marker not in pong_stdout]
    if pong_missing:
        raise RuntimeError(
            f"native Pong PTY output missing markers: {pong_missing!r}"
        )

