#!/usr/bin/env python3
"""Build and boot the hosted C99 runtime smoke on every XAIOS architecture."""

from __future__ import annotations

import os
import json
import re
import select
import sys
import subprocess
import time
from pathlib import Path
from qemu_gate_lib import qemu_boot_environment

ROOT = Path(__file__).resolve().parents[2]
REQUIREMENTS = json.loads((ROOT / "tests/libc/c99-requirements.json").read_text())
MARKERS = tuple(REQUIREMENTS["runtime_markers"])
FORBIDDEN = ("Cyan Screen of Death", "panic:", "assertion failed")
TMPFILE_EVENT = re.compile(r"xaibootfs: (?:write|delete) path=(/tmp/T\S+)")

# Every architecture this gate covers, and the build that produces the image
# each leg boots. They are deliberately one table rather than two lists: the
# gate builds what it is about to boot, so an architecture cannot be booted
# without being built, and adding one here adds it to both halves at once.
#
# B-31: the make dependency used to build AArch64 and x86-64 while this file
# iterated three architectures, so the RISC-V leg booted whatever `build/`
# happened to hold -- another commit, or the release configuration, or an
# image built with the libc probes off. It stayed green throughout, because a
# leg that boots an unrelated artefact passes exactly like a leg that boots
# the right one.
ARCHES = ("aarch64", "x86_64", "riscv64")
IMAGE_BUILD = {
    "aarch64": {
        "env": {"XAIOS_LIBC_TEST": "1", "XAIOS_BOOT_VERBOSE": "1"},
        "commands": (["./scripts/build-image.sh"],),
    },
    "x86_64": {
        "env": {"XAIOS_TARGET_ARCH": "x86_64", "XAIOS_LIBC_TEST": "1",
                "XAIOS_BOOT_VERBOSE": "1"},
        "commands": (["./scripts/build-image.sh"],),
    },
    # RISC-V takes three scripts, and the first two are not enough. The
    # kernel script compiles the probes in and the image script packs their
    # binaries, both only when told this is a libc-test build. The third
    # makes build/xaios-riscv64-system.img, which the runner copies into the
    # boot state before it starts QEMU and refuses to boot without -- and
    # which carries a copy of the kernel that the loader prefers over the one
    # on the medium, so a system volume left over from an older kernel is a
    # stale artefact of exactly the kind this gate exists to stop booting.
    "riscv64": {
        "env": {"XAIOS_BOOT_TEST_APPS": "1", "XAIOS_LIBC_TEST": "1"},
        "commands": (["./scripts/build-riscv64.sh"],
                     ["./scripts/build-riscv64-image.sh"],
                     ["./scripts/build-riscv64-boot-media.sh"]),
    },
}


def build_image(arch: str) -> None:
    """Produce the image this gate is about to boot.

    A leg that boots an artefact this run did not build tests whatever was
    lying around, and reports it in the same words as a real pass.
    """
    specification = IMAGE_BUILD[arch]
    env = os.environ.copy()
    env.update(specification["env"])
    for command in specification["commands"]:
        print(f"qemu-libc-gate: {arch}: building: {' '.join(command)}",
              flush=True)
        subprocess.run(command, cwd=ROOT, env=env, check=True)


def assert_tmpfiles_removed(text: str, arch: str) -> None:
    events: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = TMPFILE_EVENT.search(line)
        if match is not None:
            action = "delete" if "xaibootfs: delete " in line else "write"
            events.setdefault(match.group(1), []).append(action)
    created = {path: actions for path, actions in events.items() if "write" in actions}
    leaked = [path for path, actions in created.items() if actions[-1] != "delete"]
    if len(created) < 2 or leaked:
        raise RuntimeError(
            f"{arch} tmpfile cleanup failed; created={len(created)}; leaked={leaked}"
        )


def run_arch(arch: str, command: str) -> None:
    env = os.environ.copy()
    if arch == "aarch64":
        env.setdefault("XAIOS_QEMU_ACCEL", "tcg")
        env.setdefault("XAIOS_QEMU_CPU", "cortex-a72")
    elif arch == "x86_64":
        env.setdefault("XAIOS_QEMU_X86_ACCEL", "tcg")
        env.setdefault("XAIOS_QEMU_X86_CPU", "max")
    else:
        # This runner writes the console to a file unless told otherwise, and
        # this gate reads the boot from the process it started.
        env = qemu_boot_environment(arch, env, serial_to_stdout=True)
    process = subprocess.Popen(
        [command], cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=False, bufsize=0,
    )
    output = bytearray()
    deadline = time.monotonic() + int(
        env.get("XAIOS_LIBC_QEMU_TIMEOUT", "720" if arch == "riscv64" else "180"))
    try:
        assert process.stdout is not None
        while time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout.fileno()], [], [], 0.25)
            if ready:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output.extend(chunk)
                text = output.decode(errors="replace")
                if any(marker in text for marker in FORBIDDEN):
                    break
                if all(marker in text for marker in MARKERS):
                    assert_tmpfiles_removed(text, arch)
                    log = ROOT / f"build/qemu-libc-{arch}.log"
                    log.write_text(text)
                    print(f"qemu-libc-gate: {arch}: PASS")
                    return
            elif process.poll() is not None:
                break
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    text = output.decode(errors="replace")
    missing = [marker for marker in MARKERS if marker not in text]
    found_forbidden = [marker for marker in FORBIDDEN if marker in text]
    log = ROOT / f"build/qemu-libc-{arch}.log"
    log.write_text(text)
    raise RuntimeError(
        f"{arch} failed; missing={missing}; forbidden={found_forbidden}; log={log}"
    )


def main() -> int:
    """The hosted C99 runtime, on every architecture that carries one.

    It ran on two, and said "both architectures" as though that were all of
    them. A third has carried the same picolibc sysroot since it gained
    userspace; nothing was asking it to prove the library worked there.

    `--arch NAME` runs one of them. That is for working on a single machine:
    each leg is a full boot, and paying for three to see whether the one just
    changed still works is how a gate stops being run during development.

    `--build-only` stops after the images, for `make image-libc-test`.

    Each architecture is built immediately before it is booted, so what the
    gate reports on is what this run produced.
    """
    selected = None
    build_only = False
    arguments = sys.argv[1:]
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--arch" and index + 1 < len(arguments):
            selected = arguments[index + 1]
            index += 1
        elif argument.startswith("--arch="):
            selected = argument.split("=", 1)[1]
        elif argument == "--build-only":
            build_only = True
        else:
            # Silently ignoring an argument it does not know is how a gate
            # ends up running something other than what it was asked for.
            raise SystemExit(f"unsupported argument {argument!r}")
        index += 1
    arches = ARCHES
    if selected is not None:
        if selected not in arches:
            raise SystemExit(f"unsupported --arch {selected!r}")
        arches = (selected,)
    for arch in arches:
        build_image(arch)
        if not build_only:
            run_arch(arch, f"./platform/qemu/run-qemu-{arch}.sh")
    if build_only:
        print(f"qemu-libc-gate: built libc-test images for "
              f"{', '.join(arches)}")
        return 0
    print(f"qemu-libc-gate: PASS: hosted runtime executed on "
          f"{', '.join(arches)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
