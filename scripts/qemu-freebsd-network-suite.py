#!/usr/bin/env python3
"""Run a FreeBSD OpenSSH/SFTP client against one XAIOS QEMU guest."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
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
XAIOS_READY_MARKER = "syscall: net_listen protocol=17 port=2223 sockfd="
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
        process.wait(timeout=10)


def freebsd_client_script(
    private_key: str, unauthorized_key: str, ssh_port: int, udp_port: int
) -> str:
    return f"""#!/bin/sh
exec >/dev/console 2>&1
set -eu

fail() {{
    echo "{FREEBSD_FAIL_MARKER}: $*"
    poweroff
    exit 1
}}

key=/tmp/xaios-authorized
bad_key=/tmp/xaios-unauthorized
cat >"$key" <<'XAIOS_AUTHORIZED_KEY'
{private_key.rstrip()}
XAIOS_AUTHORIZED_KEY
cat >"$bad_key" <<'XAIOS_UNAUTHORIZED_KEY'
{unauthorized_key.rstrip()}
XAIOS_UNAUTHORIZED_KEY
chmod 600 "$key" "$bad_key"

host=10.0.2.2
port={ssh_port}
ssh_base="-i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -p $port"

echo "XAIOS_FREEBSD_INTEROP: client $(uname -K) $(uname -m) OpenSSH_$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\\([^,]*\\).*/\\1/p')"
ready=0
attempt=0
while [ "$attempt" -lt 90 ]; do
    if ssh $ssh_base admin@$host 'echo freebsd-ssh-ok' >/tmp/ssh-ready.out 2>/tmp/ssh-ready.err; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done
[ "$ready" -eq 1 ] || fail "SSH did not become ready"
[ "$(cat /tmp/ssh-ready.out)" = "freebsd-ssh-ok" ] || fail "SSH command output mismatch"
echo "XAIOS_FREEBSD_INTEROP: SSH public-key command PASS"

if ssh -i "$bad_key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=5 -p "$port" admin@$host 'echo rejected-key-ran' >/tmp/bad-key.out 2>/tmp/bad-key.err; then
    fail "unauthorized key was accepted"
fi
[ ! -s /tmp/bad-key.out ] || fail "unauthorized key command reached XAIOS"
echo "XAIOS_FREEBSD_INTEROP: unauthorized key rejection PASS"

ssh $ssh_base admin@$host 'xaiosctl version --json' >/tmp/version.json || fail "xaiosctl version failed"
grep -q '"status":"ok"' /tmp/version.json || fail "xaiosctl response was not successful"
grep -q '"architecture":"aarch64"' /tmp/version.json || fail "xaiosctl did not report AArch64"
echo "XAIOS_FREEBSD_INTEROP: xaiosctl PASS"

printf 'freebsd-sftp-roundtrip\\nsecond-line\\n' >/tmp/sftp-source
cat >/tmp/sftp.batch <<'XAIOS_SFTP_BATCH'
put /tmp/sftp-source /tmp/freebsd-sftp
ls -l /tmp/freebsd-sftp
get /tmp/freebsd-sftp /tmp/sftp-result
rename /tmp/freebsd-sftp /tmp/freebsd-sftp-renamed
get /tmp/freebsd-sftp-renamed /tmp/sftp-renamed-result
rm /tmp/freebsd-sftp-renamed
quit
XAIOS_SFTP_BATCH
sftp -b /tmp/sftp.batch -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -P "$port" admin@$host >/tmp/sftp.log 2>&1 || {{ cat /tmp/sftp.log; fail "SFTP batch failed"; }}
cmp /tmp/sftp-source /tmp/sftp-result || fail "SFTP round trip differed"
cmp /tmp/sftp-source /tmp/sftp-renamed-result || fail "SFTP rename round trip differed"
grep -q '/tmp/freebsd-sftp' /tmp/sftp.log || fail "SFTP stat/list output missing"
echo "XAIOS_FREEBSD_INTEROP: SFTP read/write/stat/rename/remove PASS"

{{ sleep 2; printf 'M'; sleep 0.1; printf '/sshd\n'; sleep 0.1; printf 'h'; sleep 0.1; printf 'h'; sleep 0.1; printf 'q'; }} | TERM=xterm ssh -tt $ssh_base admin@$host 'htop' >/tmp/htop.ansi 2>/tmp/htop.err || fail "PTY htop failed"
printf '\\033[2J\\033[H' >/tmp/clear-sequence
printf '\\033[?1049h' >/tmp/alternate-enter
printf '\\033[?1049l' >/tmp/alternate-leave
grep -F -f /tmp/alternate-enter /tmp/htop.ansi >/dev/null || fail "PTY htop did not enter alternate screen"
grep -F -f /tmp/clear-sequence /tmp/htop.ansi >/dev/null || fail "PTY htop lacked ANSI clear sequence"
grep -q 'Tasks:' /tmp/htop.ansi || fail "PTY htop lacked task meter"
grep -q 'Filter:' /tmp/htop.ansi || fail "PTY htop lacked interactive filter"
grep -q 'XAIOS htop help' /tmp/htop.ansi || fail "PTY htop lacked help screen"
grep -q '60 frames/s' /tmp/htop.ansi || fail "PTY htop lacked frame-cap status"
grep -F -f /tmp/alternate-leave /tmp/htop.ansi >/dev/null || fail "PTY htop did not leave alternate screen"
echo "XAIOS_FREEBSD_INTEROP: SSH PTY interactive htop PASS"

payload='freebsd-udp-echo'
reply="$(printf '%s' "$payload" | nc -u -w 5 "$host" {udp_port})" || fail "UDP echo failed"
[ "$reply" = "$payload" ] || fail "UDP echo payload mismatch"
echo "XAIOS_FREEBSD_INTEROP: UDP PASS"

echo "{FREEBSD_PASS_MARKER}"
poweroff
"""


def freebsd_user_data(
    private_key: str, unauthorized_key: str, ssh_port: int, udp_port: int
) -> str:
    client = freebsd_client_script(
        private_key, unauthorized_key, ssh_port, udp_port
    )
    encoded = base64.b64encode(client.encode("ascii")).decode("ascii")
    return (
        "#cloud-config\n"
        "package_update: false\n"
        "package_upgrade: false\n"
        "write_files:\n"
        "  - path: /etc/rc.conf.d/firstboot_freebsd_update\n"
        "    permissions: '0644'\n"
        "    owner: root:wheel\n"
        "    content: 'firstboot_freebsd_update_enable=\"NO\"'\n"
        "  - path: /etc/rc.conf.d/firstboot_pkg_upgrade\n"
        "    permissions: '0644'\n"
        "    owner: root:wheel\n"
        "    content: 'firstboot_pkg_upgrade_enable=\"NO\"'\n"
        "  - path: /root/xaios-freebsd-client.sh\n"
        "    permissions: '0700'\n"
        "    owner: root:wheel\n"
        "    encoding: b64\n"
        f"    content: {encoded}\n"
        "runcmd:\n"
        "  - /bin/sh /root/xaios-freebsd-client.sh\n"
    )


def main() -> int:
    required = ("qemu-system-aarch64", "qemu-img", "xz", "ssh-keygen")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"error: missing required tools: {', '.join(missing)}")

    BUILD.mkdir(parents=True, exist_ok=True)
    base_image, image_identity = prepare_freebsd_image()
    work = BUILD / "qemu-freebsd-network-suite"
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
    build_env.pop("XAIOS_SSH_PASSWORD_AUTH", None)
    run_checked(["make", "image"], 240, env=build_env)

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    xaios_log = BUILD / "qemu-freebsd-xaios.log"
    xaios_persistent = work / "xaios-persistent.img"
    xaios_env = build_env.copy()
    xaios_env.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port),
            "XAIOS_QEMU_HOSTFWD_UDP_PORT": str(udp_port),
            "XAIOS_PERSISTENT_IMAGE": str(xaios_persistent),
        }
    )
    xaios_log_file = xaios_log.open("wb")
    xaios = subprocess.Popen(
        [str(ROOT / "scripts" / "run-qemu-aarch64.sh")],
        cwd=ROOT,
        env=xaios_env,
        stdin=subprocess.DEVNULL,
        stdout=xaios_log_file,
        stderr=subprocess.STDOUT,
    )

    freebsd: subprocess.Popen[bytes] | None = None
    freebsd_log_file = None
    try:
        wait_for_marker(xaios_log, (XAIOS_READY_MARKER,), 180)
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

        freebsd_log = BUILD / "qemu-freebsd-client.log"
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
            "-smp", os.environ.get("XAIOS_FREEBSD_QEMU_SMP", "2"),
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
            float(os.environ.get("XAIOS_FREEBSD_TIMEOUT", "600")),
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
                "ssh_pty_ansi_htop": "passed",
                "udp_echo": "passed",
            },
        }
        report_path = BUILD / "qemu-freebsd-network-suite.json"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            "PASS: FreeBSD 15.1 OpenSSH/SFTP/UDP interoperability "
            f"({report_path})"
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
