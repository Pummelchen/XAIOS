#!/usr/bin/env python3
"""Check the two hardware kits against what their READMEs tell people to do.

`vm-package-gate` boots each virtual-machine kit out of its own archive, which
is the strongest thing a gate can say about a kit: the thing that was
downloaded starts. Neither kit here can be tested that way. Booting the USB kit
means a physical stick in a physical machine, and booting the netboot kit means
firmware fetching from a server on a real network -- and a gate that pretended
otherwise would be worse than none, because it would read as evidence.

So this checks the half that does live here, and says plainly that it is a
half. Two things go wrong with a kit without anyone noticing, and neither needs
hardware to catch:

  * A file is missing, or is not the file the release note gives a checksum
    for. Both kits carry the image or the binaries that were gated elsewhere;
    shipping something else is a packaging fault, and it is silent.
  * A script's own instructions have rotted -- it no longer runs, or the
    command it exists to wrap is no longer spelled the way the README spells
    it.

What this does not check: that a stick boots, that dnsmasq serves, or that any
firmware anywhere accepts these files. See release/xaios_b<n>.md.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
RELEASE = ROOT / "release"
STAGE = BUILD / "boot-media"
REPORT = BUILD / "boot-media-gate.json"

BUILD_NUMBER = (ROOT / "BUILD_NUMBER").read_text().strip()
IMAGE_NAME = f"xaios_b{BUILD_NUMBER}.iso"

# The PE sections that make a netboot image a whole system rather than a
# loader. A binary missing any one of them boots and then asks firmware for a
# file that network boot will never give it.
NETBOOT_SECTIONS = (".xaiosl", ".xaiosk", ".xaiosi", ".xaiose")

# What each kit has to contain. Anything else in the archive is fine; these
# are the files the READMEs tell a person to use.
REQUIRED = {
    f"xaios_b{BUILD_NUMBER}-usb": (IMAGE_NAME, "write-usb.sh", "README.md",
                                   "SHA256SUMS"),
    f"xaios_b{BUILD_NUMBER}-netboot": ("BOOTAA64.EFI", "BOOTX64.EFI",
                                       "serve-netboot.sh", "README.md",
                                       "SHA256SUMS"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def objdump_sections(binary: Path) -> set[str]:
    for candidate in ("llvm-objdump", "/opt/homebrew/opt/llvm/bin/llvm-objdump",
                      "objdump"):
        try:
            result = subprocess.run([candidate, "-h", str(binary)],
                                    capture_output=True, text=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        return {name for name in NETBOOT_SECTIONS if name in result.stdout}
    return set()


def main() -> int:
    failures: list[str] = []
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})
        if not ok:
            failures.append(f"{name}{': ' + detail if detail else ''}")

    for kit, required in REQUIRED.items():
        directory = STAGE / kit
        archive = RELEASE / f"{kit}.zip"

        if not directory.is_dir():
            check(f"{kit}: staged", False,
                  f"no {directory}; run make boot-media")
            continue
        check(f"{kit}: staged", True)

        for name in required:
            check(f"{kit}: carries {name}", (directory / name).is_file())

        # A script a person is told to run, that is not executable, is a
        # README that does not work.
        for script in directory.glob("*.sh"):
            import os
            check(f"{kit}: {script.name} is executable",
                  os.access(script, os.X_OK))

        # The kit's own SHA256SUMS has to describe the kit, or verifying a
        # download proves nothing about it.
        sums = directory / "SHA256SUMS"
        if sums.is_file():
            listed = {}
            for line in sums.read_text().splitlines():
                digest, _, name = line.partition("  ")
                if name:
                    listed[name] = digest
            mismatched = [name for name, digest in listed.items()
                          if not (directory / name).is_file()
                          or sha256(directory / name) != digest]
            check(f"{kit}: SHA256SUMS matches the files beside it",
                  not mismatched, ", ".join(mismatched[:4]))
            missing = [name for name in required
                       if name != "SHA256SUMS" and name not in listed]
            check(f"{kit}: SHA256SUMS covers every required file",
                  not missing, ", ".join(missing))

        if not archive.is_file():
            check(f"{kit}: archived", False, f"no {archive}")
            continue
        with zipfile.ZipFile(archive) as bundle:
            names = {Path(entry).name for entry in bundle.namelist()}
        check(f"{kit}: archive carries every required file",
              set(required) <= names,
              ", ".join(sorted(set(required) - names)))

    # The USB kit ships the image, and it has to be the released one -- the
    # file the release note gives a checksum for and the gates booted.
    usb_image = STAGE / f"xaios_b{BUILD_NUMBER}-usb" / IMAGE_NAME
    released = RELEASE / IMAGE_NAME
    if usb_image.is_file() and released.is_file():
        check("usb kit ships the released image",
              sha256(usb_image) == sha256(released),
              "the kit's copy is not the file in release/")
    else:
        check("usb kit ships the released image", False,
              "the image or the release copy is missing")

    # Both netboot binaries have to be whole systems.
    for binary in ("BOOTAA64.EFI", "BOOTX64.EFI"):
        path = STAGE / f"xaios_b{BUILD_NUMBER}-netboot" / binary
        if not path.is_file():
            check(f"{binary}: carries its payload sections", False, "missing")
            continue
        found = objdump_sections(path)
        check(f"{binary}: carries its payload sections",
              found == set(NETBOOT_SECTIONS),
              "absent: " + ", ".join(sorted(set(NETBOOT_SECTIONS) - found)))

    # The install command is the reason both kits exist. If the client stops
    # spelling it this way, the READMEs are telling people to type something
    # that no longer works.
    client = (ROOT / "userspace/lib/xaios_control_client.c").read_text()
    for token, why in (('"install"', "the install verb"),
                       ('"--confirm-device"', "the confirmation flag"),
                       ('"from"', 'the "from" keyword the READMEs use')):
        check(f"the client still accepts {why}", token in client)

    for kit in REQUIRED:
        readme = STAGE / kit / "README.md"
        if readme.is_file():
            text = readme.read_text()
            check(f"{kit}: README gives the install command",
                  re.search(r"xaiosctl storage install", text) is not None)

    REPORT.write_text(json.dumps(
        {"schema": "xaios.boot-media.v1", "build": BUILD_NUMBER,
         "checks": checks, "failures": failures, "passed": not failures},
        indent=2) + "\n")

    for entry in checks:
        print(f"  {'ok  ' if entry['passed'] else 'FAIL'} {entry['name']}"
              + (f" -- {entry['detail']}" if entry["detail"]
                 and not entry["passed"] else ""))
    if failures:
        print(f"boot-media-gate: {len(failures)} failed")
        return 1
    print(f"boot-media-gate: passed, {len(checks)} checks; this does not "
          f"establish that a stick boots or that a server serves")
    print(f"boot-media-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
