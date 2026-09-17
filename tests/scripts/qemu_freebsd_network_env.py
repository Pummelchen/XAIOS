#!/usr/bin/env python3
"""The FreeBSD end's surroundings for the network interoperability suite.

Moved verbatim out of `qemu-freebsd-network-suite.py` so that the suite keeps
the dialogue and this module keeps the environment it runs in. This half is
every fact about the two machines the suite brings up: the repository paths,
the per-architecture XAIOS build and boot table, the checksum-pinned FreeBSD
release and its image digests, the marker strings both ends announce
themselves with, and the helpers that reserve a port, run a checked command,
download and verify a FreeBSD image, find the AArch64 firmware, build the
cidata seed ISO, wait on a log marker and stop a process.

The guest shell program and the cloud-config that carries it live in
`qemu_freebsd_network_payload.py`; it imports the two marker strings from here
so that they are defined once. The repository root and the build directory are
here because the suite and the payload helper both need them.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"


# How to build the machine under test, and how to start it. The runner
# variables differ per architecture -- the same knob has a different name on
# each -- which is what qemu_gate_lib exists to hide everywhere else; this
# suite predates it and starts its guest itself.
XAIOS_MACHINES = {
    "aarch64": {
        "build": [["make", "image"]],
        "env": {"XAIOS_QEMU_ACCEL": "tcg", "XAIOS_QEMU_SMP": "4"},
        "ssh_port": "XAIOS_QEMU_HOSTFWD_PORT",
        "udp_port": "XAIOS_QEMU_HOSTFWD_UDP_PORT",
        "log": None,
    },
    "riscv64": {
        # The release configuration, which is what `make image` means on the
        # other two. Without it this board builds the boot-test image, whose
        # shell answers commands as built-ins and never launches xtop -- and
        # the PTY check below would be testing a different program.
        "build": [["./scripts/build-riscv64.sh"],
                  ["./scripts/build-riscv64-image.sh"]],
        "env": {"XAIOS_BOOT_TEST_APPS": "0", "XAIOS_RISCV64_CPUS": "4"},
        "ssh_port": "XAIOS_RISCV64_SSH_PORT",
        "udp_port": "XAIOS_RISCV64_HOSTFWD_UDP_PORT",
        "log": "XAIOS_RISCV64_LOG",
    },
}

FREEBSD_RELEASE = "15.1-RELEASE"
FREEBSD_IMAGE_NAME = (
    "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2"
)
FREEBSD_ARCHIVE_SHA256 = (
    "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963"
)
FREEBSD_IMAGE_SHA256 = (
    "ae13edc018ad2d862020de3fdccc24581fae12b3323bfd800db73cb2b7fce23c"
)
FREEBSD_ARCHIVE_URL = (
    "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/"
    f"aarch64/Latest/{FREEBSD_IMAGE_NAME}.xz"
)
XAIOS_READY_MARKER = "SSH server: up and running (tcp/22)"
FREEBSD_PASS_MARKER = "XAIOS_FREEBSD_INTEROP: PASS"
FREEBSD_FAIL_MARKER = "XAIOS_FREEBSD_INTEROP: FAIL"


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_checked(command: list[str], timeout: float, **kwargs: object) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True, timeout=timeout, **kwargs)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(source: str, destination: Path) -> None:
    partial = destination.with_suffix(destination.suffix + ".partial")
    request = urllib.request.Request(
        source, headers={"User-Agent": "XAIOS-QEMU-gate/1"}
    )
    print(f"Downloading {source}", flush=True)
    with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            output.write(block)
    partial.replace(destination)


def prepare_freebsd_image() -> tuple[Path, str]:
    configured = os.environ.get("XAIOS_FREEBSD_IMAGE")
    if configured:
        image = Path(configured).expanduser().resolve()
        if not image.is_file():
            raise RuntimeError(f"XAIOS_FREEBSD_IMAGE does not exist: {image}")
        image_actual = sha256(image)
        if image_actual != FREEBSD_IMAGE_SHA256:
            raise RuntimeError(
                "configured FreeBSD image SHA-256 mismatch: "
                f"expected {FREEBSD_IMAGE_SHA256}, got {image_actual}"
            )
        run_checked(["qemu-img", "check", "-q", str(image)], 120)
        return image, image_actual

    cache = Path(
        os.environ.get(
            "XAIOS_FREEBSD_CACHE_DIR",
            str(Path.home() / ".cache" / "xaios" / "freebsd"),
        )
    ).expanduser()
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"{FREEBSD_IMAGE_NAME}.xz"
    image = cache / FREEBSD_IMAGE_NAME
    if not archive.exists():
        download(FREEBSD_ARCHIVE_URL, archive)
    actual = sha256(archive)
    if actual != FREEBSD_ARCHIVE_SHA256:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"FreeBSD archive SHA-256 mismatch: expected {FREEBSD_ARCHIVE_SHA256}, got {actual}"
        )
    if not image.exists():
        run_checked(["xz", "-dk", str(archive)], 300)
    image_actual = sha256(image)
    if image_actual != FREEBSD_IMAGE_SHA256:
        image.unlink(missing_ok=True)
        raise RuntimeError(
            "FreeBSD image SHA-256 mismatch: "
            f"expected {FREEBSD_IMAGE_SHA256}, got {image_actual}"
        )
    run_checked(["qemu-img", "check", "-q", str(image)], 120)
    return image, FREEBSD_ARCHIVE_SHA256


def find_aarch64_firmware() -> Path:
    configured = os.environ.get("XAIOS_AAVMF_CODE")
    candidates = [
        configured,
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/local/share/qemu/edk2-aarch64-code.fd",
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise RuntimeError("AArch64 QEMU UEFI firmware was not found")


def create_seed_iso(seed_dir: Path, output: Path) -> str:
    output.unlink(missing_ok=True)
    if shutil.which("hdiutil"):
        run_checked(
            [
                "hdiutil",
                "makehybrid",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                "-o",
                str(output),
                str(seed_dir),
            ],
            60,
        )
        return "hdiutil"
    for tool in ("xorrisofs", "genisoimage", "mkisofs"):
        if shutil.which(tool):
            run_checked(
                [
                    tool,
                    "-quiet",
                    "-output",
                    str(output),
                    "-volid",
                    "cidata",
                    "-joliet",
                    "-rock",
                    str(seed_dir),
                ],
                60,
            )
            return tool
    raise RuntimeError(
        "creating the FreeBSD cidata disk requires hdiutil, xorrisofs, "
        "genisoimage, or mkisofs"
    )


def wait_for_marker(log_path: Path, markers: tuple[str, ...], timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            text = log_path.read_text(errors="replace")
            for marker in markers:
                if marker in text:
                    return marker
        time.sleep(0.5)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-80:])
    raise TimeoutError(f"timed out waiting for {markers!r}\n{tail}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()

