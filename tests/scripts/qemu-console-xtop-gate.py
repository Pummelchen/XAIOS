#!/usr/bin/env python3
"""Check that xtop draws the same picture locally that it draws over SSH.

The local console and an SSH session run the same program, but they used to
reach the user through very different terminals. The framebuffer terminal had a
sixty-four glyph uppercase font, dropped every byte outside printable ASCII,
read only the three-digit colour codes, and was handed a guessed eighty by
twenty-four screen. A process monitor drawn through it came out uppercase,
without its rules or its gauges, on a magenta field -- because 38;5;45 read one
number at a time ends at "background magenta" -- and clipped to the left half
of the display.

This gate boots a machine with a framebuffer, runs xtop on its console, reads
the screen back out of QEMU as pixels, decodes those pixels through the
kernel's own font tables, and compares the result with what the same program
prints into an SSH session of the same size.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys

from qemu_console_xtop_screen import (
    FIELD_BACKGROUND,
    HEADER_BACKGROUND,
    ROOT,
    Screen,
    parse_font,
)
from qemu_console_xtop_session import (
    ARCH,
    GATE_DIR,
    TITLE,
    Console,
    Qmp,
    check,
    ssh_frame,
    ssh_session_filter_check,
)


# RISC-V under TCG is the slow one to boot; the release gate allows the same.
BOOT_TIMEOUT_SECONDS = 900.0 if ARCH == "riscv64" else 240.0
STEP_TIMEOUT_SECONDS = 60.0


# ----------------------------------------------------------------------- gate

def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def find(lines: list[str], predicate) -> str:
    for line in lines:
        if predicate(line):
            return line
    return ""


def compare(local: list[str], remote: list[str], columns: int) -> None:
    """The lines whose content does not move between two samples."""
    check(TITLE in " ".join(local), f"local console is missing the title line: {local[:3]}")
    check(TITLE in " ".join(remote), "SSH session is missing the title line")

    for name, predicate in (
        ("outer top rule", lambda l: l.startswith("┌─ XAIOS xtop")),
        ("CPU panel rule", lambda l: "┌─ CPU" in l),
        ("panel bottom rule", lambda l: l.startswith("│└─")),
        ("process panel rule", lambda l: "┌─ Process List" in l),
        ("column header", lambda l: l.strip("│ ").startswith("PID") and "COMMAND" in l),
        ("key bar rule", lambda l: l.startswith("└─") and "F1Help" in l),
    ):
        local_line = find(local, predicate)
        remote_line = find(remote, predicate)
        check(local_line != "", f"local console has no {name}")
        check(remote_line != "", f"SSH session has no {name}")
        # The panel names carry live figures -- the CPU load, the memory in
        # use -- sampled at different instants on the two sides. Digits are
        # masked so the comparison is of the layout, which is the claim.
        # A figure that grew a digit between the two samples shortens the
        # rule beside it by one column; runs of digits and runs of rule are
        # each collapsed, so the comparison is of the layout alone.
        def masked(line: str) -> str:
            return re.sub("\u2500+", "\u2500", re.sub(r"[0-9]+", "#", line))
        masked_local = masked(local_line)
        masked_remote = masked(remote_line)
        check(
            masked_local == masked_remote,
            f"{name} differs between the two terminals\n"
            f"  local: {local_line!r}\n  ssh:   {remote_line!r}",
        )
        if name.endswith("rule"):
            check(
                len(local_line) == columns,
                f"{name} is {len(local_line)} cells wide on a {columns} cell console",
            )

    for name, lines in (("local console", local), ("SSH session", remote)):
        joined = "\n".join(lines)
        check("█" in joined, f"{name} drew no filled gauge cells")
        check("░" in joined, f"{name} drew no empty gauge cells")
        check("�" not in joined, f"{name} contains cells no glyph matched")


def main() -> int:
    glyphs, geometry = parse_font()

    if GATE_DIR.exists():
        shutil.rmtree(GATE_DIR)
    GATE_DIR.mkdir(parents=True, mode=0o700)
    persistent = GATE_DIR / "persistent.img"
    qmp_socket = GATE_DIR / "qmp.sock"
    screendump = GATE_DIR / "console.ppm"
    port = reserve_port()

    # The console leg logs in with the default password; the SSH leg needs a
    # key the image knows about, so one is minted for this run.
    key = GATE_DIR / "admin"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
         "xaios-console-xtop-gate", "-f", str(key)],
        cwd=ROOT, check=True, timeout=30,
    )
    env = os.environ.copy()
    env.pop("XAIOS_SSH_USERS_FILE", None)
    env.pop("XAIOS_SSH_PASSWORD_AUTH", None)
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key.with_suffix(".pub"))
    print(f"+ build image ({ARCH})", flush=True)
    if ARCH == "riscv64":
        # The release configuration, which is the one that launches programs
        # as processes; the boot-test gates never do.
        release = dict(env, XAIOS_BOOT_TEST_APPS="0")
        for script in ("build-riscv64.sh", "build-riscv64-image.sh",
                       "build-riscv64-boot-media.sh"):
            subprocess.run([str(ROOT / "scripts" / script)], cwd=ROOT,
                           env=release, check=True, timeout=1800)
    else:
        build = dict(env, XAIOS_TARGET_ARCH=ARCH)
        subprocess.run([str(ROOT / "scripts" / "build-image.sh")], cwd=ROOT,
                       env=build, check=True, timeout=1800)

    if ARCH == "riscv64":
        state = GATE_DIR / "state"
        state.mkdir(exist_ok=True)
        env.update(
            {
                "XAIOS_RISCV64_CPUS": "4",
                "XAIOS_RISCV64_SSH_PORT": str(port),
                "XAIOS_RISCV64_STATE": str(state),
                "XAIOS_RISCV64_LOG": str(GATE_DIR / "serial.log"),
                "XAIOS_RISCV64_SERIAL": "stdio",
                "XAIOS_RISCV64_QMP_SOCKET": str(qmp_socket),
                "XAIOS_RISCV64_EXTRA_ARGS": "-device virtio-gpu-pci",
            }
        )
        runner = ROOT / "platform" / "qemu" / "run-qemu-riscv64.sh"
    else:
        env.update(
            {
                "XAIOS_QEMU_ACCEL": "tcg",
                "XAIOS_QEMU_SMP": "4",
                "XAIOS_QEMU_HOSTFWD_PORT": str(port),
                # The two runners name the persistent disk differently. The
                # disk carries /state, and with it the bootstrap key the
                # image installs on first boot: a shared, stale one refuses
                # every key but the run that created it.
                "XAIOS_PERSISTENT_IMAGE": str(persistent),
                "XAIOS_X86_PERSISTENT_IMAGE": str(persistent),
                "XAIOS_QEMU_QMP_SOCKET": str(qmp_socket),
                "XAIOS_QEMU_EXTRA_ARGS": "-device virtio-gpu-pci",
            }
        )
        runner = ROOT / "platform" / "qemu" / f"run-qemu-{ARCH}.sh"
    process = subprocess.Popen(
        [str(runner)],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    console = Console(process)
    try:
        console.wait_for(b"xaios login: ", BOOT_TIMEOUT_SECONDS)
        mark = console.checkpoint()
        console.send(b"admin\rxaios\r")
        console.wait_for(b"admin@xaios", STEP_TIMEOUT_SECONDS, mark)

        mark = console.checkpoint()
        console.send(b"xtop\r")
        console.wait_for(TITLE.encode(), STEP_TIMEOUT_SECONDS, mark)
        console.drain(3.0)

        # xtop clears the screen and repaints it top-down four times a second,
        # so a dump taken between the clear and the last row is a torn frame:
        # title present, footer not yet. Keep dumping until both are there.
        # That is sampling a whole frame, not hiding a defect -- the SSH leg
        # below is likewise read as a whole frame.
        qmp = Qmp(qmp_socket)
        screen = None
        for attempt in range(20):
            qmp.command("screendump", filename=str(screendump))
            console.drain(0.15)
            candidate = Screen(screendump, glyphs, geometry)
            has_title = any(TITLE in line for line in candidate.lines)
            has_keys = any("F1Help" in line for line in candidate.lines)
            print(f"+ screendump {attempt}: title={has_title} keys={has_keys} "
                  f"rows={sum(1 for l in candidate.lines if l.strip())}", flush=True)
            complete = has_title and has_keys
            if complete:
                screen = candidate
                break
        check(screen is not None, "no screendump caught a complete xtop frame")
        (GATE_DIR / "console.raw").write_bytes(console.snapshot())
        local_lines = screen.lines
        print(f"+ console is {screen.columns}x{screen.rows} cells", flush=True)
        for line in local_lines[:22]:
            print(f"  |{line}")

        remote_lines = ssh_frame(key, port, screen.columns, screen.rows)
        print("+ ssh frame", flush=True)
        for line in remote_lines[:22]:
            print(f"  |{line}")

        compare(local_lines, remote_lines, screen.columns)

        ssh_session_filter_check(key, port, screen.columns, screen.rows)

        # The colours the extended escape sequences ask for. Reading 38;5;45
        # one number at a time lands in the background arm and paints the whole
        # meter block magenta, which is exactly the bug this pins down.
        # A cores row: the shade glyph is only drawn there, and its blanks
        # must sit on the field. (A gauge row's blanks sit on the fill.)
        meter_row = next(
            index for index, line in enumerate(local_lines) if "░" in line
        )
        for column, glyph in enumerate(local_lines[meter_row]):
            if glyph != " ":
                continue
            background = screen.cell_background(column, meter_row)
            check(
                background == FIELD_BACKGROUND,
                f"meter row cell {column} sits on {background}, not the field",
            )
        header_row = next(
            index
            for index, line in enumerate(local_lines)
            if line.strip("│ ").startswith("PID") and "COMMAND" in line
        )
        header_background = screen.cell_background(4, header_row)
        check(
            header_background == HEADER_BACKGROUND,
            f"process header sits on {header_background}, not xterm colour 70",
        )
        title_row = next(index for index, line in enumerate(local_lines) if TITLE in line)
        title_background = screen.cell_background(2, title_row)
        check(
            title_background == FIELD_BACKGROUND,
            f"title rule sits on {title_background}, not the field",
        )
        # A gauge interior: the fill colour or the field, nothing else.
        gauge_row = next(
            index for index, line in enumerate(local_lines) if "┌─ CPU" in line
        ) + 1
        gauge_background = screen.cell_background(2, gauge_row)
        check(
            gauge_background in (FIELD_BACKGROUND, HEADER_BACKGROUND),
            f"gauge interior sits on {gauge_background}, neither field nor fill",
        )
        footer_row = next(
            index for index, line in enumerate(local_lines)
            if line.startswith("└─") and "F1Help" in line
        )
        key_background = screen.cell_background(3, footer_row)
        check(
            key_background == FIELD_BACKGROUND,
            f"key bar sits on {key_background}, not the field",
        )
        console.send(b"q")
    finally:
        # Everything the serial line said, whatever happened: a failure in
        # the SSH leg is diagnosed from the kernel's account of it.
        try:
            console.drain(1.0)
            (GATE_DIR / "console.raw").write_bytes(console.snapshot())
        except Exception:  # noqa: BLE001 - diagnostics must not mask the result
            pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    print(f"PASS: xtop renders the same on the local console and over SSH ({ARCH})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
