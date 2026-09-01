#!/usr/bin/env python3
"""Look at the screen, from outside the machine that drew it.

V-06 built the graphical console: the platform's GOP reports `PixelBltOnly`
with a zero framebuffer base, so firmware leaves nothing to draw into, and
`virtio_gpu.c` claims the display device on the bus instead. Everything about
it was verified from the inside -- the driver logs the scanout it created, and
`boot_ui` logs every status it drew -- and the row closed with the one thing
none of that establishes: what a person actually sees. That was written down
as needing an operator to look.

It does not. QEMU's `screendump` writes the scanout surface to a file, which
is the same pixels a viewer would be shown, read from outside the guest. So
this boots with a virtio-GPU attached, waits until the guest says it has
reached a login prompt, and then measures the picture.

What is measured is what a finished boot looks like. When the machine reaches
a login prompt `boot_ui` has handed the display to its terminal, so the screen
carries the ready summary and the prompt -- and no progress bar at all, since
the bar belongs to the boot that has ended. A screen still showing a bar is
therefore showing a moment that has passed, and that is precisely what this
gate found on its first run: `boot_ui_handle_control` drew the last four
stages of boot and presented none of them, so a machine sitting at a login
prompt displayed a bar stopped at 90% for as long as it was left there, while
the serial log reported every stage completing. Nothing watching from inside
could see it.

So the check is two-sided, because either half alone passes for the wrong
reason. A screen with no bar could be a dead display, and a screen with
pixels could be a stale frame. Both together -- the bar gone *and* text drawn
-- describe only the handover.

What this does not establish: that any physical display shows these pixels,
or that Virtualization.framework and Fusion scan out the same way QEMU does.
It is the guest's drawing that is checked here, on the one platform whose
display can be read back mechanically.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-framebuffer-gate.json"
SHOT = BUILD / "qemu-framebuffer-gate.ppm"
QMP_SOCKET = "/tmp/xaios-framebuffer-gate.qmp"

BOOT_DEADLINE = int(os.environ.get("XAIOS_FRAMEBUFFER_TIMEOUT", "420"))

# boot_ui's own palette, from kernel/core/boot_ui.c. The bar is drawn as a dim
# full-width rectangle with a green one over the completed fraction, so these
# two colours are the whole measurement: how much of the bar is green.
GREEN = (50, 210, 100)
DIM = (110, 110, 110)


def read_ppm(path: Path) -> tuple[int, int, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"P6"):
        raise ValueError("screendump did not produce a binary PPM")
    fields: list[bytes] = []
    offset = 2
    while len(fields) < 3:
        while offset < len(data) and data[offset : offset + 1].isspace():
            offset += 1
        if data[offset : offset + 1] == b"#":
            while offset < len(data) and data[offset] != 0x0A:
                offset += 1
            continue
        start = offset
        while offset < len(data) and not data[offset : offset + 1].isspace():
            offset += 1
        fields.append(data[start:offset])
    width, height, _ = (int(field) for field in fields)
    return width, height, data[offset + 1 :]


def inspect(path: Path) -> dict:
    """Count what is on the screen: bar pixels, and drawn pixels generally.

    Counting rather than locating. The bar's position and the text's layout
    are both free to move; what cannot move without meaning something is
    whether a progress bar is on screen at all after boot has finished, and
    whether anything was drawn.
    """
    width, height, pixels = read_ppm(path)
    bar = 0
    drawn = 0
    for offset in range(0, width * height * 3, 3):
        pixel = (pixels[offset], pixels[offset + 1], pixels[offset + 2])
        if pixel in (GREEN, DIM):
            bar += 1
        # The console background is near-black but not exactly black, so
        # "drawn" means visibly brighter than the background rather than
        # non-zero.
        if pixel[0] + pixel[1] + pixel[2] > 120:
            drawn += 1
    return {
        "width": width,
        "height": height,
        "bar_pixels": bar,
        "drawn_pixels": drawn,
    }


def capture(shot: Path) -> tuple[bool, str, list[str]]:
    """Boot with a display attached and photograph it at the login prompt."""
    Path(QMP_SOCKET).unlink(missing_ok=True)
    shot.unlink(missing_ok=True)
    environment = dict(
        os.environ,
        XAIOS_QEMU_EXTRA_ARGS="-device virtio-gpu-pci",
        XAIOS_QEMU_QMP_SOCKET=QMP_SOCKET,
    )
    process = subprocess.Popen(
        [str(ROOT / "platform/qemu/run-qemu-aarch64.sh")],
        cwd=str(ROOT), env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    interesting: list[str] = []
    # Read on a thread. The prompt is written without a newline after it, so a
    # blocking readline on the main thread waits for a line the guest has no
    # reason to send and the deadline below never gets to run -- which is how
    # the first version of this gate sat for fifteen minutes past its own
    # timeout on a machine that had booted correctly.
    collected: list[str] = []
    def drain() -> None:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(1)
            if not chunk:
                return
            collected.append(chunk)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    reached = False
    try:
        deadline = time.monotonic() + BOOT_DEADLINE
        while time.monotonic() < deadline:
            time.sleep(2)
            text = "".join(collected)
            if "xaios login:" in text:
                reached = True
                break
        interesting = [line.strip() for line in "".join(collected).splitlines()
                       if "virtio-gpu:" in line or "boot-ui: adopted" in line]
        if not reached:
            return False, "the guest never reached a login prompt", interesting
        # The prompt is written before the control record that completes the
        # display, so give the guest a moment to finish drawing rather than
        # photographing the frame before the last one.
        time.sleep(5)
        stream = socket.socket(socket.AF_UNIX)
        stream.connect(QMP_SOCKET)
        channel = stream.makefile("rw")
        channel.readline()
        channel.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
        channel.flush()
        channel.readline()
        channel.write(json.dumps(
            {"execute": "screendump", "arguments": {"filename": str(shot)}})
            + "\n")
        channel.flush()
        reply = channel.readline()
        if "error" in reply:
            return False, f"screendump failed: {reply.strip()}", interesting
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
    if not shot.is_file():
        return False, "screendump wrote no file", interesting
    return True, "", interesting


def main() -> int:
    if not (BUILD / "xaios-aarch64.img").is_file():
        print("qemu-framebuffer-gate: build the image first (make image)",
              file=sys.stderr)
        return 2
    ok, why, seen = capture(SHOT)
    failures: list[str] = []
    detail: dict = {}
    if not ok:
        failures.append(why)
    else:
        detail = inspect(SHOT)
        # A handful of stray pixels could match the bar colours inside glyphs;
        # a bar that is actually on screen is thousands of pixels wide.
        if detail["bar_pixels"] > 500:
            failures.append(
                f"the screen still shows a progress bar "
                f"({detail['bar_pixels']} bar pixels) while the guest is at a "
                f"login prompt; the display is behind the machine")
        if detail["drawn_pixels"] < 500:
            failures.append(
                f"the screen is effectively blank ({detail['drawn_pixels']} "
                f"drawn pixels); nothing was presented to the display")
    report = {
        "schema": "xaios.framebuffer.v1",
        "screenshot": str(SHOT),
        "display_lines": seen,
        "measurement": detail,
        "failures": failures,
        "passed": not failures,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for line in seen:
        print(f"  {line}")
    if failures:
        for failure in failures:
            print(f"qemu-framebuffer-gate: {failure}", file=sys.stderr)
        print(f"qemu-framebuffer-gate: report written to {REPORT}")
        return 1
    print(f"qemu-framebuffer-gate: the screen shows the finished handover at "
          f"the login prompt -- no progress bar, "
          f"{detail['drawn_pixels']} pixels drawn; capture at {SHOT}")
    print(f"qemu-framebuffer-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
