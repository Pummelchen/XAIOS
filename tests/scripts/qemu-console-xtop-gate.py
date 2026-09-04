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

import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import termios
import time
import fcntl

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
GATE_DIR = BUILD / "qemu-console-xtop-gate"
BOOT_TIMEOUT_SECONDS = 240.0
STEP_TIMEOUT_SECONDS = 60.0

TITLE = "XAIOS xtop — sampled kernel process monitor"
# term_default_background() in boot_ui.c, and two xterm-256 shades xtop asks
# for by index: 24 behind the title, 238 behind the process table header.
DEFAULT_BACKGROUND = (4, 6, 10)
TITLE_BACKGROUND = (0, 95, 135)
HEADER_BACKGROUND = (68, 68, 68)
# term_sgr_background() for the classic codes the footer uses: 46 and 42.
FOOTER_KEY_BACKGROUND = (0, 150, 165)
FOOTER_LABEL_BACKGROUND = (30, 120, 60)


# ---------------------------------------------------------------- font tables

def parse_font() -> tuple[dict[tuple[int, ...], str], dict[str, int]]:
    """The glyphs and the geometry, read out of the kernel source.

    Copying either into this file would let the two drift apart and leave the
    gate testing its own copy rather than the console.
    """
    source = (ROOT / "kernel" / "core" / "boot_ui.c").read_text()

    table = source[source.index("g_font[UINT32_C("):]
    table = table[: table.index("\n};")]
    glyphs: dict[tuple[int, ...], str] = {}
    rows = re.findall(r"\{((?:0x[0-9a-fA-F]{2},\s*){7}0x[0-9a-fA-F]{2})\}", table)
    if len(rows) != 96:
        raise RuntimeError(f"expected 96 ASCII glyphs, parsed {len(rows)}")
    for index, row in enumerate(rows):
        values = tuple(int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", row))
        glyphs.setdefault(values, chr(0x20 + index))

    extra = source[source.index("g_font_extra[] = {"):]
    extra = extra[: extra.index("\n};")]
    for match in re.finditer(
        r"\{0x([0-9a-fA-F]{4})U,\s*\{((?:0x[0-9a-fA-F]{2},\s*){7}0x[0-9a-fA-F]{2})\}\}",
        extra,
    ):
        values = tuple(
            int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", match.group(2))
        )
        glyphs.setdefault(values, chr(int(match.group(1), 16)))

    def constant(name: str) -> int:
        match = re.search(rf"#define {name} UINT32_C\((\d+)\)", source)
        if match is None:
            raise RuntimeError(f"{name} not found in boot_ui.c")
        return int(match.group(1))

    geometry = {
        "width": constant("FB_GLYPH_WIDTH"),
        "height": constant("FB_GLYPH_HEIGHT"),
        "margin_x": constant("TERM_MARGIN_X"),
        "margin_y": constant("TERM_MARGIN_Y"),
    }
    return glyphs, geometry


def scale_geometry(geometry: dict[str, int], framebuffer_width: int) -> dict[str, int]:
    """Glyph geometry follows the display mode, so it is known only once the
    screen has been read back. The arithmetic is boot_ui.c's own."""
    scale = min(max(framebuffer_width // 1024, 1), 3)
    scaled = dict(geometry)
    scaled["x_scale"] = scale
    scaled["y_scale"] = scale * 2
    scaled["advance"] = (geometry["width"] + 1) * scale
    scaled["line_height"] = geometry["height"] * scaled["y_scale"] + 2
    return scaled


# ------------------------------------------------------------------- decoding

class Screen:
    def __init__(self, path: Path, glyphs, geometry) -> None:
        data = path.read_bytes()
        if not data.startswith(b"P6"):
            raise RuntimeError(f"{path} is not a binary PPM")
        header = data.split(b"\n", 3)
        self.width, self.height = (int(v) for v in header[1].split())
        self.pixels = header[3]
        self.glyphs = glyphs
        geometry = scale_geometry(geometry, self.width)
        self.geometry = geometry
        self.columns = (self.width - 2 * geometry["margin_x"]) // geometry["advance"]
        self.rows = (self.height - 2 * geometry["margin_y"]) // geometry["line_height"]
        self.lines = [self._decode_row(row) for row in range(self.rows)]

    def pixel(self, x: int, y: int) -> tuple[int, int, int]:
        offset = (y * self.width + x) * 3
        return (self.pixels[offset], self.pixels[offset + 1], self.pixels[offset + 2])

    def _cell(self, column: int, row: int) -> list[tuple[int, int, int]]:
        g = self.geometry
        x0 = g["margin_x"] + column * g["advance"]
        y0 = g["margin_y"] + row * g["line_height"]
        return [
            self.pixel(x0 + gx * g["x_scale"], y0 + gy * g["y_scale"])
            for gy in range(g["height"])
            for gx in range(g["width"])
        ]

    def cell_background(self, column: int, row: int) -> tuple[int, int, int]:
        """The colour the cell was cleared to before its glyph was drawn.

        Every cell is cleared first, so whichever colour is furthest from the
        drawn strokes is the background; taking the most common colour is wrong
        for a solid block and right for everything else, so the row's own
        background is used as the tie-breaker.
        """
        colors = self._cell(column, row)
        if len(set(colors)) == 1:
            return colors[0]
        counted: dict[tuple[int, int, int], int] = {}
        for color in colors:
            counted[color] = counted.get(color, 0) + 1
        return max(counted.items(), key=lambda item: item[1])[0]

    def _row_background(self, row: int) -> tuple[int, int, int]:
        """The colour most of the row's blank cells were cleared to.

        A row is usually text on one background, so the commonest colour among
        its uniform cells is that background. Taking the rightmost blank cell
        instead breaks on a title bar that stops one cell short of the edge:
        every painted cell then differs from the "background" and reads as a
        solid block.
        """
        counted: dict[tuple[int, int, int], int] = {}
        for column in range(self.columns):
            colors = self._cell(column, row)
            if len(set(colors)) == 1:
                counted[colors[0]] = counted.get(colors[0], 0) + 1
        if not counted:
            return self.cell_background(self.columns - 1, row)
        return max(counted.items(), key=lambda item: item[1])[0]

    def _bits(self, colors, background) -> tuple[int, ...]:
        g = self.geometry
        bits = []
        for gy in range(g["height"]):
            value = 0
            for gx in range(g["width"]):
                if colors[gy * g["width"] + gx] != background:
                    value |= 1 << gx
            bits.append(value)
        return tuple(bits)

    def _decode_row(self, row: int) -> str:
        """Each cell is a glyph in one colour on a background in another.

        Which of a cell's two colours is the background is not always the
        row's: a footer paints its keys on cyan and their labels on green in
        the same row. So a two-colour cell is read both ways and the reading
        that is a glyph wins; a cell in one colour is blank unless that colour
        is a foreground painted edge to edge, which is what a full block is.
        """
        row_background = self._row_background(row)
        blank = (0,) * self.geometry["height"]
        text = ""
        for column in range(self.columns):
            colors = self._cell(column, row)
            distinct = set(colors)
            if len(distinct) == 1:
                color = colors[0]
                if color in (row_background, DEFAULT_BACKGROUND):
                    text += " "
                else:
                    text += self.glyphs.get(self._bits(colors, None), "�")
                continue
            candidates = [row_background] if row_background in distinct else []
            candidates += [c for c in distinct if c not in candidates]
            glyph = None
            for background in candidates:
                key = self._bits(colors, background)
                if key != blank and key in self.glyphs:
                    glyph = self.glyphs[key]
                    break
            text += glyph if glyph is not None else "�"
        return text.rstrip()


# ------------------------------------------------------------------- QEMU/QMP

class Qmp:
    def __init__(self, path: Path) -> None:
        deadline = time.monotonic() + 60.0
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(str(path))
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        self.buffer = b""
        self._read()                      # greeting
        self.command("qmp_capabilities")

    def _read(self) -> dict:
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("QMP closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def command(self, name: str, **arguments) -> dict:
        payload = {"execute": name}
        if arguments:
            payload["arguments"] = arguments
        self.sock.sendall((json.dumps(payload) + "\n").encode())
        while True:
            message = self._read()
            if "return" in message or "error" in message:
                if "error" in message:
                    raise RuntimeError(f"QMP {name} failed: {message['error']}")
                return message


class Console:
    def __init__(self, process: subprocess.Popen) -> None:
        self.process = process
        self.output = bytearray()

    def send(self, value: bytes) -> None:
        self.process.stdin.write(value)
        self.process.stdin.flush()

    def checkpoint(self) -> int:
        return len(self.output)

    def wait_for(self, marker: bytes, timeout: float, since: int = 0) -> None:
        deadline = time.monotonic() + timeout
        while marker not in self.output[since:]:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited rc={self.process.returncode} waiting for "
                    f"{marker!r}\n{self.tail()}"
                )
            if time.monotonic() > deadline:
                raise TimeoutError(f"timed out waiting for {marker!r}\n{self.tail()}")
            ready, _, _ = select.select([self.process.stdout.fileno()], [], [], 0.25)
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if chunk:
                    self.output.extend(chunk)

    def drain(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.process.stdout.fileno()], [], [], 0.1)
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if chunk:
                    self.output.extend(chunk)

    def tail(self) -> str:
        return bytes(self.output[-8192:]).decode(errors="replace")


# ------------------------------------------------------------------------ SSH

def ssh_frame(key: Path, port: int, columns: int, rows: int) -> list[str]:
    """One xtop frame from an SSH session of the given size."""
    parent, child = pty.openpty()
    fcntl.ioctl(child, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    stderr_path = GATE_DIR / "ssh.stderr"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [
                "ssh", "-tt",
                "-i", str(key),
                "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                # See qemu-model-sftp-gate: a ~/.ssh/config that disables public
                # key authentication for this host would otherwise stop the key
                # being offered at all, on that machine only.
                "-o", "PubkeyAuthentication=yes",
                "-o", "PreferredAuthentications=none,publickey",
                "-p", str(port), "admin@127.0.0.1", "xtop",
            ],
            cwd=ROOT,
            stdin=child,
            stdout=child,
            stderr=stderr,
        )
    os.close(child)
    collected = bytearray()
    deadline = time.monotonic() + 45.0
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([parent], [], [], 0.25)
            if ready:
                try:
                    chunk = os.read(parent, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                collected.extend(chunk)
            if collected.count(b"\x1b[2J") >= 3:
                break
        try:
            os.write(parent, b"q")
            time.sleep(1.0)
        except OSError:
            pass  # the session already ended; the frames are what matter
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        os.close(parent)
    (GATE_DIR / "ssh.raw").write_bytes(collected)
    if TITLE.encode() not in collected:
        raise RuntimeError(
            f"SSH session produced no xtop frame (rc={process.returncode}):\n"
            + collected.decode("utf-8", errors="replace")[-2000:]
            + "\nssh stderr:\n"
            + stderr_path.read_text(errors="replace")[-2000:]
        )
    # Frames begin with a clear; the last piece is a frame still being
    # written, so the one before it is the last complete frame.
    frames = collected.split(b"\x1b[2J")
    frame = frames[-2] if len(frames) > 2 else frames[-1]
    return render_terminal(frame, columns)


# --------------------------------------------------------- terminal model

def render_terminal(data: bytes, columns: int) -> list[str]:
    """What a terminal of this width shows for these bytes.

    An SSH client's terminal wraps at the last column exactly as the
    framebuffer terminal does, so the bytes have to be laid out before they
    can be compared with pixels: a line one column too wide is a line and a
    blank line on both, and stripping the escapes without wrapping would hide
    that on one side only.
    """
    text = data.decode("utf-8", errors="replace")
    lines: list[list[str]] = [[]]
    column = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\x1b":
            match = re.match(r"\x1b\[[0-9;?]*[A-Za-z]", text[index:])
            if match:
                index += len(match.group(0))
                continue
            index += 1
            continue
        index += 1
        if char == "\r":
            column = 0
            continue
        if char == "\n":
            lines.append([])
            column = 0
            continue
        if column >= columns:
            lines.append([])
            column = 0
        row = lines[-1]
        while len(row) <= column:
            row.append(" ")
        row[column] = char
        column += 1
    return ["".join(row).rstrip() for row in lines]


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


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def compare(local: list[str], remote: list[str], columns: int) -> None:
    """The lines whose content does not move between two samples."""
    check(TITLE in " ".join(local), f"local console is missing the title line: {local[:3]}")
    check(TITLE in " ".join(remote), "SSH session is missing the title line")

    for name, predicate in (
        ("CPU panel rule", lambda l: l.startswith("┌─ CPU ")),
        ("panel bottom rule", lambda l: l.startswith("└─")),
        ("process panel rule", lambda l: l.startswith("┌─ Processes ")),
        ("column header", lambda l: l.strip().startswith("PID") and "COMMAND" in l),
        ("footer", lambda l: l.startswith("F1Help")),
    ):
        local_line = find(local, predicate)
        remote_line = find(remote, predicate)
        check(local_line != "", f"local console has no {name}")
        check(remote_line != "", f"SSH session has no {name}")
        check(
            local_line == remote_line,
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
    print("+ build image", flush=True)
    subprocess.run(["make", "image"], cwd=ROOT, env=env, check=True, timeout=1800)

    env.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_QEMU_HOSTFWD_PORT": str(port),
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
            "XAIOS_QEMU_QMP_SOCKET": str(qmp_socket),
            "XAIOS_QEMU_EXTRA_ARGS": "-device virtio-gpu-pci",
        }
    )
    process = subprocess.Popen(
        [str(ROOT / "platform" / "qemu" / "run-qemu-aarch64.sh")],
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
            complete = any(TITLE in line for line in candidate.lines) and any(
                line.startswith("F1Help") for line in candidate.lines
            )
            if complete:
                screen = candidate
                break
        check(screen is not None, "no screendump caught a complete xtop frame")
        (GATE_DIR / "console.raw").write_bytes(bytes(console.output))
        local_lines = screen.lines
        print(f"+ console is {screen.columns}x{screen.rows} cells", flush=True)
        for line in local_lines[:22]:
            print(f"  |{line}")

        remote_lines = ssh_frame(key, port, screen.columns, screen.rows)
        print("+ ssh frame", flush=True)
        for line in remote_lines[:22]:
            print(f"  |{line}")

        compare(local_lines, remote_lines, screen.columns)

        # The colours the extended escape sequences ask for. Reading 38;5;45
        # one number at a time lands in the background arm and paints the whole
        # meter block magenta, which is exactly the bug this pins down.
        meter_row = next(
            index
            for index, line in enumerate(local_lines)
            if "█" in line or "░" in line
        )
        for column, glyph in enumerate(local_lines[meter_row]):
            if glyph != " ":
                continue
            background = screen.cell_background(column, meter_row)
            check(
                background == DEFAULT_BACKGROUND,
                f"meter row cell {column} sits on {background}, not the "
                f"default background",
            )
        header_row = next(
            index
            for index, line in enumerate(local_lines)
            if line.strip().startswith("PID") and "COMMAND" in line
        )
        header_background = screen.cell_background(2, header_row)
        check(
            header_background == HEADER_BACKGROUND,
            f"process header sits on {header_background}, not xterm colour 238",
        )
        title_row = next(index for index, line in enumerate(local_lines) if TITLE in line)
        title_background = screen.cell_background(2, title_row)
        check(
            title_background == TITLE_BACKGROUND,
            f"title bar sits on {title_background}, not xterm colour 24",
        )
        footer_row = next(
            index for index, line in enumerate(local_lines) if line.startswith("F1Help")
        )
        key_background = screen.cell_background(0, footer_row)
        label_background = screen.cell_background(3, footer_row)
        check(
            key_background == FOOTER_KEY_BACKGROUND,
            f"footer key sits on {key_background}, not SGR 46 cyan",
        )
        check(
            label_background == FOOTER_LABEL_BACKGROUND,
            f"footer label sits on {label_background}, not SGR 42 green",
        )
        console.send(b"q")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    print("PASS: xtop renders the same on the local console and over SSH")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
