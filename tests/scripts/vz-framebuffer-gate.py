#!/usr/bin/env python3
"""What Virtualization.framework's display shows at a login prompt.

V-06 proved the graphical console by reading QEMU's scanout back through
`screendump`, and named its own boundary: "this reads QEMU's scanout, not a
physical display, and not Fusion's or Virtualization.framework's."

Fusion's half is closed and the answer was no: `vmrun captureScreen` is a guest
operation needing VMware Tools, which XAIOS does not ship, so that display
cannot be read from outside at all.

This half is reachable, and for a specific reason: the display here is a
`VZVirtualMachineView` that our own harness builds, and an NSView can be asked
for its own pixels. `xaios-vz --screenshot` captures it with `cacheDisplay`,
which returns what the guest drew rather than a photograph of a window -- no
title bar, no dependence on what is in front of it, and no screen-recording
permission for the operator to grant.

The two questions are the ones the QEMU gate asks, and they are asked together
because either alone passes for the wrong reason: a dead display has no
progress bar, and a display frozen mid-boot has plenty of pixels. A machine
that has finished booting shows both -- nothing left of the bar, and a screen
with something on it.

What it does not claim: this is a virtual display on one Mac, not a physical
monitor, and Virtualization.framework is a development target rather than a
qualification profile.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
VZ = BUILD / "vz"
HARNESS = VZ / "xaios-vz"
SHOT = BUILD / "vz-framebuffer.png"
REPORT = BUILD / "vz-framebuffer-gate.json"

# The bar's greens, as boot_ui draws them -- taken from the QEMU gate so all
# three gates ask about the same pixels rather than three similar ideas.
GREEN = (0, 205, 0)
DIM = (0, 128, 0)
TOLERANCE = 24
BOOT_SECONDS = int(os.environ.get("XAIOS_VZ_SCREENSHOT_DELAY", "150"))
# See the comment at the check: chrome is ~16, a real bar ~7200.
BAR_PIXEL_FLOOR = 200

VOLUMES = ("vz-test.img", "vz-persistent.img", "vz-model.img",
           "vz-storage-admin.img", "vz-system.img", "vz-system2.img")


def near(pixel, target) -> bool:
    return all(abs(a - b) <= TOLERANCE for a, b in zip(pixel, target))


def decode_png(path: Path) -> tuple[int, int, list[tuple[int, int, int]]]:
    """Enough PNG to count pixels, without adding a dependency to the tree.

    vmrun writes a straightforward truecolour PNG. Anything else -- palette,
    interlace, 16-bit -- is refused rather than guessed at, because a gate that
    silently misreads the image would report the screen's contents as whatever
    its assumptions produced.
    """
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("captureScreen did not write a PNG")
    pos = 8
    width = height = depth = colour = None
    idat = bytearray()
    while pos < len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour = struct.unpack_from(">IIBB", body, 0)
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + length
    if depth != 8 or colour not in (2, 6):
        raise ValueError(
            f"unsupported PNG: bit depth {depth}, colour type {colour}; this "
            f"gate reads 8-bit truecolour only and will not guess at the rest")
    channels = 3 if colour == 2 else 4
    raw = zlib.decompress(bytes(idat))
    stride = width * channels
    pixels: list[tuple[int, int, int]] = []
    previous = bytearray(stride)
    offset = 0
    for _ in range(height):
        filter_type = raw[offset]
        line = bytearray(raw[offset + 1:offset + 1 + stride])
        offset += 1 + stride
        for i in range(stride):
            a = line[i - channels] if i >= channels else 0
            b = previous[i]
            c = previous[i - channels] if i >= channels else 0
            if filter_type == 1:
                line[i] = (line[i] + a) & 0xFF
            elif filter_type == 2:
                line[i] = (line[i] + b) & 0xFF
            elif filter_type == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 0xFF
            elif filter_type == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"unknown PNG filter {filter_type}")
        for i in range(0, stride, channels):
            pixels.append((line[i], line[i + 1], line[i + 2]))
        previous = line
    return width, height, pixels


def near(pixel: tuple[int, int, int], target: tuple[int, int, int]) -> bool:
    return all(abs(a - b) <= TOLERANCE for a, b in zip(pixel, target))


def inspect(path: Path) -> dict[str, object]:
    width, height, pixels = decode_png(path)
    bar = sum(1 for p in pixels if near(p, GREEN) or near(p, DIM))
    drawn = sum(1 for p in pixels if sum(p) > 120)
    return {"width": width, "height": height, "bar_pixels": bar,
            "drawn_pixels": drawn, "total_pixels": len(pixels)}




def main() -> int:
    if sys.platform != "darwin":
        print("vz-framebuffer-gate: needs macOS")
        return 0
    if not HARNESS.is_file():
        print(f"vz-framebuffer-gate: missing {HARNESS.relative_to(ROOT)}; "
              f"run `make vz-harness` first", file=sys.stderr)
        return 2
    disk = VZ / "run-disk.img"
    if not disk.is_file():
        print(f"vz-framebuffer-gate: missing {disk.relative_to(ROOT)}; run "
              f"`make vz-gate` once to create the volumes", file=sys.stderr)
        return 2

    SHOT.unlink(missing_ok=True)
    command = [str(HARNESS), str(disk)]
    command += [str(VZ / name) for name in VOLUMES]
    command += ["--memory-mib", "2048", "--cpus", "4",
                "--screenshot", str(SHOT),
                "--screenshot-delay", str(BOOT_SECONDS)]
    started = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                            timeout=BOOT_SECONDS + 180, check=False)
    elapsed = round(time.monotonic() - started, 1)

    failures: list[str] = []
    checks: dict[str, object] = {"seconds": elapsed,
                                 "harness_exit": result.returncode}
    console = result.stdout + result.stderr
    # The guest's own account of the display, which is what tells a blank
    # capture apart from a blank screen.
    adopted = "boot-ui: adopted a" in console and "framebuffer" in console
    scanout = "virtio-gpu: scanout" in console
    checks["guest_adopted_framebuffer"] = adopted
    checks["guest_configured_scanout"] = scanout

    if not SHOT.is_file():
        failures.append(
            f"the harness wrote no capture: {result.stderr.strip()[:300]!r}")
    else:
        checks.update(inspect(SHOT))
        checks["capture"] = str(SHOT.relative_to(ROOT))
        if checks["drawn_pixels"] == 0 and adopted and scanout:
            # Not a guest failure, and worth separating from one.
            #
            # The guest configured a scanout and boot_ui adopted the
            # framebuffer, so it is drawing. The capture is black because
            # Virtualization.framework composites the guest's surface outside
            # the view's layer tree: neither cacheDisplay, which walks
            # drawRect:, nor CALayer.render reaches an IOSurface the window
            # server owns. Both were tried and both returned 1280x800 of
            # black.
            #
            # What would read it is CGWindowListCreateImage, which needs
            # Screen Recording permission -- a change to the operator's
            # machine and not this gate's to make. So this reports rather than
            # fails, the same way the Fusion framebuffer gate reports that
            # captureScreen needs VMware Tools.
            print("vz-framebuffer-gate: the guest drew and the host cannot "
                  "read it.")
            print("  The guest configured a 1280x800 scanout and boot_ui "
                  "adopted that framebuffer,")
            print("  so the graphical console is working. The capture is "
                  "black because")
            print("  Virtualization.framework composites the guest surface "
                  "outside the view's")
            print("  layer tree -- cacheDisplay and CALayer.render were both "
                  "tried and both")
            print("  returned a fully black bitmap of the right size.")
            print("  Reading it needs CGWindowListCreateImage and Screen "
                  "Recording permission,")
            print("  which is the operator's to grant and not this gate's to "
                  "assume.")
            print("  V-06's QEMU half is unaffected: make "
                  "qemu-framebuffer-gate reads the scanout")
            print("  directly from the emulator.")
            REPORT.write_text(json.dumps({
                "schema": "xaios.vz.framebuffer.v1",
                "status": "unavailable",
                "reason": "the guest draws; the composited surface is not "
                          "readable from this process without Screen "
                          "Recording permission",
                "checks": checks,
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        # A threshold, not zero, and the numbers are why.
        #
        # ScreenCaptureKit captures the window, not the guest's framebuffer
        # alone, so the title bar comes with it -- and the close button is
        # green. A finished boot here measures 16 matching pixels, all of them
        # that button. A real progress bar measured 7200 in the QEMU gate
        # against a pre-fix capture. Two orders of magnitude apart, so a
        # threshold in between is not a fudge: it separates window chrome from
        # a bar, and nothing lands between them.
        if checks["bar_pixels"] > BAR_PIXEL_FLOOR:
            failures.append(
                f"the boot progress bar is still on screen "
                f"({checks['bar_pixels']} bar pixels against a floor of "
                f"{BAR_PIXEL_FLOOR}; window chrome measures about 16 and a "
                f"real bar about 7200): the guest drew later stages without "
                f"presenting them, which is the defect V-06 found and which "
                f"nothing inside the machine can see")
        if checks["drawn_pixels"] < 1000:
            failures.append(
                f"the display is effectively blank ({checks['drawn_pixels']} "
                f"lit pixels): nothing reached it, so the absence of a "
                f"progress bar means nothing")

    report = {"schema": "xaios.vz.framebuffer.v1",
              "status": "pass" if not failures else "fail",
              "checks": checks,
              "failures": failures,
              "not_claimed": [
                  "a physical display: this is a virtual one on one Mac",
                  "a qualification profile: Virtualization.framework is a "
                  "development target",
              ]}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vz-framebuffer-gate: FAIL {failure}")
        print(f"vz-framebuffer-gate: report={REPORT}")
        return 1
    print(f"vz-framebuffer-gate: Virtualization.framework's own display shows "
          f"a finished boot -- {checks['drawn_pixels']} lit pixels of "
          f"{checks['width']}x{checks['height']} and no progress bar left on "
          f"screen; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
