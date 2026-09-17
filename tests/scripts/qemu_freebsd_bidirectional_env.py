#!/usr/bin/env python3
"""The FreeBSD end's surroundings: the image, the seed and the QEMU runner.

Moved verbatim out of `qemu-freebsd-bidirectional-suite.py` so that the suite
keeps the dialogue and this module keeps the environment it runs in. This half
is every fact about the pair the suite brings up: the repository paths, the
release and Docker tag, the per-architecture image names with their recorded
digests, the machine table that says how each XAIOS architecture is built and
booted, the marker strings both ends announce themselves with, and the helpers
that download and verify a FreeBSD image, build the cidata seed ISO, wait on a
log marker, stop a process and start the XAIOS runner. The guest shell script
and the cloud-config that carries it live in
`qemu_freebsd_bidirectional_payload.py`.

The repository root is here because the suite and the payload helper both need
it, and it is defined once.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


BUILD = ROOT / "build"
FREEBSD_RELEASE = "15.1-RELEASE"
DOCKER_IMAGE = "xaios-freebsd-qemu-endpoint:15.1"
SERVER_READY = "XAIOS_FREEBSD_SERVER: READY"
CLIENT_PASS = "XAIOS_FREEBSD_CLIENT: PASS"
CLIENT_FAIL = "XAIOS_FREEBSD_CLIENT: FAIL"
XAIOS_READY = "SSH server: up and running (tcp/22)"

IMAGES = {
    "aarch64": {
        "directory": "aarch64",
        "name": "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2",
        "archive_sha256": "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963",
    },
    "x86_64": {
        "directory": "amd64",
        "name": "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2",
        "archive_sha256": "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f",
    },
}

# Outbound SSH budget when QEMU emulates the host's own architecture. The
# aarch64 value is measured on an Apple Silicon host; x86_64 keeps the larger
# value because it has only ever been run cross-emulated, so there is no
# native measurement to justify shrinking it.
NATIVE_OUTBOUND_TIMEOUT = {"aarch64": "60", "x86_64": "600"}
# Budget when QEMU must translate a foreign ISA, which is roughly an order of
# magnitude slower than emulating the host architecture.
CROSS_OUTBOUND_TIMEOUT = "600"

HOST_ARCHITECTURES = {"arm64": "aarch64", "aarch64": "aarch64",
                      "amd64": "x86_64", "x86_64": "x86_64"}

# Which XAIOS machines this suite can pair a FreeBSD one with, and how to
# build and start each.
#
# The FreeBSD end is not one of these, and that is on purpose. What this suite
# measures is XAIOS answering and dialling a real third-party stack in both
# directions; OpenSSH on FreeBSD does not behave differently per instruction
# set, and there is no FreeBSD cloud-init image for RISC-V at all -- so a
# RISC-V FreeBSD would have to be driven over its console and emulated without
# acceleration, adding an hour to every run to measure FreeBSD's port rather
# than this one. The FreeBSD end therefore stays on whichever architecture
# runs natively here, and the report says so rather than implying a pair.
XAIOS_MACHINES = {
    "aarch64": {
        "build": [["make", "image"]],
        "runner": "platform/qemu/run-qemu-aarch64.sh",
        "env": {"XAIOS_QEMU_ACCEL": "tcg", "XAIOS_QEMU_SMP": "4"},
        "persistent": "XAIOS_PERSISTENT_IMAGE",
        "ssh_port": "XAIOS_QEMU_HOSTFWD_PORT",
        "udp_port": "XAIOS_QEMU_HOSTFWD_UDP_PORT",
        "log": None,
    },
    "x86_64": {
        "build": [["make", "image-x86_64"]],
        "runner": "platform/qemu/run-qemu-x86_64.sh",
        "env": {"XAIOS_QEMU_X86_ACCEL": "tcg", "XAIOS_QEMU_X86_SMP": "4"},
        "persistent": "XAIOS_X86_PERSISTENT_IMAGE",
        "ssh_port": "XAIOS_QEMU_HOSTFWD_PORT",
        "udp_port": "XAIOS_QEMU_HOSTFWD_UDP_PORT",
        "log": None,
    },
    "riscv64": {
        # The release configuration, which is what `make image` means on the
        # other two. The boot-test build answers shell commands as kernel
        # built-ins and never launches an application, so a suite that ran
        # against it would be testing a different program.
        "build": [["./scripts/build-riscv64.sh"],
                  ["./scripts/build-riscv64-image.sh"]],
        "runner": "platform/qemu/run-qemu-riscv64.sh",
        "env": {"XAIOS_BOOT_TEST_APPS": "0", "XAIOS_RISCV64_CPUS": "4"},
        "persistent": "XAIOS_PERSISTENT_IMAGE",
        "ssh_port": "XAIOS_RISCV64_SSH_PORT",
        "udp_port": "XAIOS_RISCV64_HOSTFWD_UDP_PORT",
        "log": "XAIOS_RISCV64_LOG",
    },
}


def freebsd_architecture() -> str:
    """The architecture the FreeBSD end runs as: the host's, where possible.

    It runs natively there. Anything else is emulated instruction by
    instruction, and the FreeBSD end is not what is under test.
    """
    host = HOST_ARCHITECTURES.get(platform.machine().lower())
    return host if host in IMAGES else "aarch64"


def default_outbound_timeout(architecture: str) -> str:
    # The budget depends on the host/guest pairing, not on the guest
    # architecture alone. Keying it off the guest only held on an AArch64
    # development host, where aarch64 happened to be native and x86_64
    # happened to be emulated; on an x86_64 CI runner that mapping inverts
    # and leaves the cross-emulated aarch64 guest with the 60 second budget.
    host = HOST_ARCHITECTURES.get(platform.machine().lower())
    if host is None or host != architecture:
        return CROSS_OUTBOUND_TIMEOUT
    return NATIVE_OUTBOUND_TIMEOUT[architecture]


def run_checked(
    command: list[str], timeout: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        timeout=timeout,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(source: str, destination: Path) -> None:
    partial = destination.with_suffix(destination.suffix + ".partial")
    request = urllib.request.Request(
        source, headers={"User-Agent": "XAIOS-QEMU-gate/2"}
    )
    print(f"Downloading {source}", flush=True)
    with urllib.request.urlopen(request, timeout=60) as response, partial.open(
        "wb"
    ) as output:
        for block in iter(lambda: response.read(1024 * 1024), b""):
            output.write(block)
    partial.replace(destination)


def prepare_freebsd_image(architecture: str) -> tuple[Path, str, str]:
    configured = os.environ.get("XAIOS_FREEBSD_IMAGE")
    if configured:
        image = Path(configured).expanduser().resolve()
        if not image.is_file():
            raise RuntimeError(f"XAIOS_FREEBSD_IMAGE does not exist: {image}")
        run_checked(["qemu-img", "check", "-q", str(image)], 180)
        return image, sha256(image), "configured"

    metadata = IMAGES[architecture]
    name = str(metadata["name"])
    cache = Path(
        os.environ.get(
            "XAIOS_FREEBSD_CACHE_DIR",
            str(Path.home() / ".cache" / "xaios" / "freebsd"),
        )
    ).expanduser()
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"{name}.xz"
    image = cache / name
    url = (
        f"https://download.freebsd.org/releases/VM-IMAGES/{FREEBSD_RELEASE}/"
        f"{metadata['directory']}/Latest/{name}.xz"
    )
    if not archive.exists():
        download(url, archive)
    archive_identity = sha256(archive)
    if archive_identity != metadata["archive_sha256"]:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            "FreeBSD archive SHA-256 mismatch: "
            f"expected {metadata['archive_sha256']}, got {archive_identity}"
        )
    if not image.exists():
        run_checked(["xz", "-dk", str(archive)], 900)
    run_checked(["qemu-img", "check", "-q", str(image)], 180)
    return image, sha256(image), archive_identity


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
    raise RuntimeError("no cidata ISO creation tool was found")


def wait_for_marker(
    log_path: Path, markers: tuple[str, ...], timeout: float
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            contents = log_path.read_text(errors="replace")
            for marker in markers:
                if marker in contents:
                    return marker
        time.sleep(0.5)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-100:])
    raise TimeoutError(f"timed out waiting for {markers!r}\n{tail}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def xaios_process(
    architecture: str, env: dict[str, str], log_file: object
) -> subprocess.Popen[bytes]:
    machine = XAIOS_MACHINES[architecture]
    env.update(machine["env"])
    persistent = BUILD / f"qemu-freebsd-bidirectional-{architecture}-state.img"
    persistent.unlink(missing_ok=True)
    env[machine["persistent"]] = str(persistent)
    return subprocess.Popen(
        [str(ROOT / machine["runner"])],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
