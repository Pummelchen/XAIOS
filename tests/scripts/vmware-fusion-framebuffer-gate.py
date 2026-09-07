#!/usr/bin/env python3
"""What a person actually sees on a Fusion guest, read off Fusion's own display.

V-06 closed the graphical console with `make qemu-framebuffer-gate`, which
reads QEMU's scanout back through `screendump` -- the same surface a viewer is
shown -- and it named its own boundary: "this reads QEMU's scanout, not a
physical display, and not Fusion's or Virtualization.framework's." That
mattered because the defect it found was invisible from inside the machine:
`boot_ui_handle_control` drew without presenting, so the last four stages of
boot never reached the device and a machine sitting at a login prompt showed a
progress bar stopped at 90% while the serial log reported everything finished.
Nothing in the guest could tell.

Fusion's half of that boundary looked reachable -- `vmrun captureScreen`
writes what the display is showing to a file -- and it is not. VMware
classifies captureScreen as a *guest* operation: it needs VMware Tools running
inside the machine and a login to it, and XAIOS ships no VMware Tools. There is
no flag for it and nothing an operator can enable; it needs an agent in the
guest, which is a different piece of work from this gate.

So this gate exists to say that, rather than to leave the question looking
open. It boots the guest, asks, and reports the refusal by name. If a guest
agent ever exists, the two questions below are already written and will start
answering.

They are asked together, because either alone passes for the wrong reason. "No
progress bar on screen" is true of a dead display, and "pixels were drawn" is
true of one frozen mid-boot. A machine that has finished booting has to show
both: nothing left of the bar, and a screen with something on it.

The framebuffer here is firmware's, not virtio-GPU's -- Fusion presents a GOP
framebuffer that the kernel maps from `boot->framebuffer_base` -- so this is
not a second test of the virtio-GPU path. It is the question V-06 is actually
about, which is whether what the machine believes it drew is what the display
ends up showing, on a platform whose display it had never been asked on.
"""

from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "vmware_fusion_smoke", Path(__file__).with_name("vmware-fusion-smoke.py"))
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

BUILD = ROOT / "build"
REPORT = BUILD / "vmware-fusion" / "fusion-framebuffer-gate.json"
SHOT = BUILD / "vmware-fusion" / "fusion-screen.png"

# The bar's greens, as boot_ui draws them. Taken from the QEMU gate so both
# gates are asking about the same pixels rather than two similar ideas.
GREEN = (0, 205, 0)
DIM = (0, 128, 0)
# A capture is scaled or colour-converted by nobody here, but a real display
# pipeline is entitled to be a shade off, so the bar match is a small
# neighbourhood rather than an exact triple. Everything else stays a
# brightness question, which no colour conversion changes materially.
TOLERANCE = 24


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
        print("vmware-fusion-framebuffer-gate: needs macOS with VMware Fusion")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"vmware-fusion-framebuffer-gate: no vmrun at {smoke.VMRUN}; "
              f"skipping")
        return 0

    smoke.build_guest()
    smoke.stop_hard()
    smoke.start_vm(0)
    failures: list[str] = []
    checks: dict[str, object] = {}
    try:
        SHOT.parent.mkdir(parents=True, exist_ok=True)
        SHOT.unlink(missing_ok=True)
        result = smoke.vmrun(["captureScreen", str(smoke.VMX), str(SHOT)],
                             check=False)
        if not SHOT.is_file():
            message = result.stdout.strip()
            if "LoginInGuest" in message or "guest operations" in message:
                # Not a failure of the guest, and not something an operator can
                # switch on. VMware classifies captureScreen as a *guest*
                # operation: it needs VMware Tools running inside the machine
                # and a login to it, and XAIOS has no VMware Tools. So this
                # route to V-06's remaining boundary is closed, and saying so
                # is the result. Reported as unavailable rather than failed,
                # and loudly rather than as a quiet pass, so the next person to
                # try does not spend the same afternoon on it.
                print("vmware-fusion-framebuffer-gate: cannot be answered on "
                      "this platform.")
                print("  vmrun captureScreen is a guest operation: it requires "
                      "VMware Tools inside the")
                print("  guest and a login to it. XAIOS ships no VMware Tools, "
                      "so Fusion will not hand")
                print("  over its display to anything here. There is no flag "
                      "for it and nothing for an")
                print("  operator to enable -- it needs an agent in the guest, "
                      "which is a different piece")
                print("  of work from this gate.")
                print("  V-06's QEMU half is unaffected: make "
                      "qemu-framebuffer-gate reads the scanout")
                print("  directly and does not go through the guest.")
                REPORT.parent.mkdir(parents=True, exist_ok=True)
                REPORT.write_text(json.dumps({
                    "schema": "xaios.vmware-fusion.framebuffer.v1",
                    "status": "unavailable",
                    "fusion_version": smoke.fusion_version(),
                    "revision": smoke.git_revision(),
                    "reason": "vmrun captureScreen is a guest operation "
                              "requiring VMware Tools, which XAIOS does not "
                              "ship",
                    "vmrun_output": message[:400],
                }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return 0
            failures.append(
                f"vmrun captureScreen wrote no file: {message[:200]!r}")
        else:
            checks.update(inspect(SHOT))
            checks["capture"] = str(SHOT.relative_to(ROOT))
            # Both halves, for the reason in the docstring: a dead display has
            # no progress bar either.
            if checks["bar_pixels"] != 0:
                failures.append(
                    f"the boot progress bar is still on screen at the login "
                    f"prompt ({checks['bar_pixels']} bar pixels): the guest "
                    f"drew later stages without presenting them, which is the "
                    f"defect V-06 found and which nothing inside the machine "
                    f"can see")
            if checks["drawn_pixels"] < 1000:
                failures.append(
                    f"the display is effectively blank "
                    f"({checks['drawn_pixels']} lit pixels): nothing reached "
                    f"it, so the absence of a progress bar means nothing")
    finally:
        smoke.stop_hard()

    report = {
        "schema": "xaios.vmware-fusion.framebuffer.v1",
        "status": "pass" if not failures else "fail",
        "fusion_version": smoke.fusion_version(),
        "revision": smoke.git_revision(),
        "checks": checks,
        "failures": failures,
        "not_claimed": [
            "this is Fusion's display, not a physical monitor",
            "the framebuffer is firmware's GOP, not the virtio-GPU path the "
            "QEMU gate exercises",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vmware-fusion-framebuffer-gate: FAIL {failure}")
        print(f"vmware-fusion-framebuffer-gate: report={REPORT}")
        return 1
    print(f"vmware-fusion-framebuffer-gate: Fusion's own display shows a "
          f"finished boot -- {checks['drawn_pixels']} lit pixels of "
          f"{checks['width']}x{checks['height']} and no progress bar left on "
          f"screen; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
