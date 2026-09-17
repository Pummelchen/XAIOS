#!/usr/bin/env python3
"""Run a FreeBSD OpenSSH/SFTP client against one XAIOS QEMU guest."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys


# The helper modules live beside this gate. The directory is added explicitly
# rather than assumed from how the script was started, because repository
# checks import this file as a module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import arch_from_argv, qemu_runner, smoke_timeout  # noqa: E402

from qemu_freebsd_network_env import (  # noqa: E402,F401
    BUILD,
    FREEBSD_ARCHIVE_SHA256,
    FREEBSD_FAIL_MARKER,
    FREEBSD_IMAGE_NAME,
    FREEBSD_IMAGE_SHA256,
    FREEBSD_PASS_MARKER,
    FREEBSD_RELEASE,
    ROOT,
    XAIOS_MACHINES,
    XAIOS_READY_MARKER,
    create_seed_iso,
    find_aarch64_firmware,
    prepare_freebsd_image,
    reserve_port,
    run_checked,
    stop_process,
    wait_for_marker,
)
from qemu_freebsd_network_payload import (  # noqa: E402,F401
    freebsd_client_script,
    freebsd_user_data,
)


# Which XAIOS is under test. The FreeBSD client is not parameterised, and that
# is deliberate: what this suite measures is XAIOS's SSH, SFTP and UDP against
# a real third-party implementation, and OpenSSH on FreeBSD behaves the same
# whichever instruction set FreeBSD was built for. The client's architecture
# is chosen for speed -- it runs natively under HVF on this host -- because
# emulating a foreign FreeBSD would add an hour to every run and would be
# testing FreeBSD's port rather than XAIOS's.
ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"


def main() -> int:
    required = ("qemu-system-aarch64", "qemu-img", "xz", "ssh-keygen")
    if ARCH != "aarch64":
        required += (f"qemu-system-{ARCH}",)
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"error: missing required tools: {', '.join(missing)}")

    BUILD.mkdir(parents=True, exist_ok=True)
    base_image, image_identity = prepare_freebsd_image()
    machine = XAIOS_MACHINES[ARCH]
    work = BUILD / f"qemu-freebsd-network-suite{SUFFIX}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    key_dir = work / "keys"
    key_dir.mkdir(mode=0o700)
    for name in ("authorized", "unauthorized"):
        run_checked(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"xaios-freebsd-{name}",
                "-f",
                str(key_dir / name),
            ],
            30,
        )

    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    build_env.pop("XAIOS_SSH_USERS_FILE", None)
    build_env["XAIOS_SSH_PASSWORD_AUTH"] = "0"
    for command in machine["build"]:
        run_checked(command, smoke_timeout(ARCH, 240),
                    env={**build_env, **machine["env"]})

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    xaios_log = BUILD / f"qemu-freebsd-xaios{SUFFIX}.log"
    xaios_log.unlink(missing_ok=True)
    xaios_persistent = work / "xaios-persistent.img"
    xaios_env = build_env.copy()
    xaios_env.update(machine["env"])
    xaios_env.update({
        machine["ssh_port"]: str(ssh_port),
        machine["udp_port"]: str(udp_port),
        "XAIOS_PERSISTENT_IMAGE": str(xaios_persistent),
    })
    if machine["log"] is not None:
        # This board's runner writes the console to a file of its own, and
        # this suite watches the console for the readiness marker.
        xaios_env[machine["log"]] = str(xaios_log)
        xaios_log_file = open(os.devnull, "wb")
    else:
        xaios_log_file = xaios_log.open("wb")
    xaios = subprocess.Popen(
        [str(ROOT / qemu_runner(ARCH))],
        cwd=ROOT,
        env=xaios_env,
        stdin=subprocess.DEVNULL,
        stdout=xaios_log_file,
        stderr=subprocess.STDOUT,
    )

    freebsd: subprocess.Popen[bytes] | None = None
    freebsd_log_file = None
    try:
        wait_for_marker(xaios_log, (XAIOS_READY_MARKER,),
                        smoke_timeout(ARCH, 180))
        seed_dir = work / "cidata"
        seed_dir.mkdir()
        (seed_dir / "meta-data").write_text(
            "instance-id: xaios-freebsd-interop\nlocal-hostname: xaios-freebsd-client\n",
            encoding="ascii",
        )
        (seed_dir / "user-data").write_text(
            freebsd_user_data(
                (key_dir / "authorized").read_text(encoding="ascii"),
                (key_dir / "unauthorized").read_text(encoding="ascii"),
                ssh_port,
                udp_port,
                ARCH,
            ),
            encoding="ascii",
        )
        seed_iso = work / "cidata.iso"
        iso_tool = create_seed_iso(seed_dir, seed_iso)
        overlay = work / "freebsd-overlay.qcow2"
        run_checked(
            [
                "qemu-img",
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(base_image),
                str(overlay),
            ],
            30,
        )

        freebsd_log = BUILD / f"qemu-freebsd-client{SUFFIX}.log"
        freebsd_log_file = freebsd_log.open("wb")
        accel = os.environ.get(
            "XAIOS_FREEBSD_QEMU_ACCEL",
            "hvf" if platform.system() == "Darwin" else "tcg",
        )
        command = [
            "qemu-system-aarch64",
            "-machine", f"virt,accel={accel},gic-version=3",
            "-cpu", "host" if accel == "hvf" else "max",
            "-m", os.environ.get("XAIOS_FREEBSD_QEMU_MEMORY", "2048"),
            "-smp", os.environ.get("XAIOS_FREEBSD_QEMU_SMP", "4"),
            "-display", "none",
            "-monitor", "none",
            "-serial", "stdio",
            "-no-reboot",
            "-drive", f"if=pflash,format=raw,readonly=on,file={find_aarch64_firmware()}",
            "-drive", f"if=none,format=qcow2,id=freebsd,file={overlay}",
            "-device", "virtio-blk-pci,drive=freebsd,bootindex=0",
            "-drive", f"if=none,format=raw,readonly=on,id=cidata,file={seed_iso}",
            "-device", "virtio-blk-pci,drive=cidata",
            "-netdev", "user,id=net0",
            "-device", "virtio-net-pci,netdev=net0",
        ]
        print("+", " ".join(command), flush=True)
        freebsd = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=freebsd_log_file,
            stderr=subprocess.STDOUT,
        )
        marker = wait_for_marker(
            freebsd_log,
            (FREEBSD_PASS_MARKER, FREEBSD_FAIL_MARKER),
            float(os.environ.get("XAIOS_FREEBSD_TIMEOUT",
                                 str(smoke_timeout(ARCH, 600)))),
        )
        if marker != FREEBSD_PASS_MARKER:
            tail = "\n".join(
                freebsd_log.read_text(errors="replace").splitlines()[-100:]
            )
            raise RuntimeError(f"FreeBSD interoperability suite failed\n{tail}")
        if xaios.poll() is not None:
            raise RuntimeError(f"XAIOS QEMU exited unexpectedly with status {xaios.returncode}")

        report = {
            "status": "pass",
            "xaios_architecture": ARCH,
            "client_architecture_note":
                "the client runs on the host's own architecture, natively. "
                "What is under test is XAIOS's SSH, SFTP and UDP against a "
                "third-party implementation; OpenSSH on FreeBSD does not "
                "behave differently per instruction set, and emulating a "
                "foreign FreeBSD would measure FreeBSD's port rather than "
                "this one.",
            "client_os": "FreeBSD",
            "client_release": FREEBSD_RELEASE,
            "client_architecture": "aarch64",
            "client_image": FREEBSD_IMAGE_NAME,
            "client_image_identity": image_identity,
            "client_archive_sha256": FREEBSD_ARCHIVE_SHA256,
            "client_image_sha256": FREEBSD_IMAGE_SHA256,
            "freebsd_qemu_accel": accel,
            "seed_tool": iso_tool,
            "xaios_qemu_accel": "tcg",
            "checks": {
                "public_key_auth": "passed",
                "unauthorized_key_rejection": "passed",
                "xaiosctl": "passed",
                "sftp_round_trip": "passed",
                "ssh_pty_ansi_xtop": "passed",
                "udp_echo": "passed",
            },
        }
        report_path = BUILD / f"qemu-freebsd-network-suite{SUFFIX}.json"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"PASS: FreeBSD 15.1 OpenSSH/SFTP/UDP interoperability against "
            f"XAIOS on {ARCH} ({report_path})"
        )
        return 0
    finally:
        if freebsd is not None:
            stop_process(freebsd)
        if freebsd_log_file is not None:
            freebsd_log_file.close()
        stop_process(xaios)
        xaios_log_file.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
