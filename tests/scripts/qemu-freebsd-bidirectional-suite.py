#!/usr/bin/env python3
"""Run bidirectional SSH/SFTP/SCP checks between XAIOS and real FreeBSD."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


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


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])


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


def freebsd_script(
    private_key: str,
    unauthorized_key: str,
    server_password: str,
    expected_architecture: str,
) -> str:
    return f"""#!/bin/sh
# amd64 cloud images keep the framebuffer as /dev/console even with QEMU's
# headless mode.  ttyu0 is the serial console consumed by the gate on both
# supported architectures.
if [ -c /dev/ttyu0 ]; then
    exec >/dev/ttyu0 2>&1
else
    exec >/dev/console 2>&1
fi
set -eu

fail() {{
    echo "{CLIENT_FAIL}: $*"
    exit 1
}}

printf '%s\n' '{server_password}' | pw useradd xaios -m -s /bin/sh -h 0 \
    || fail "could not create server user"
mkdir -p /home/xaios/fixture/nested
printf 'freebsd-to-xaios-scp\n' >/home/xaios/fixture/nested/source.txt
chown -R xaios:xaios /home/xaios
cat >>/etc/ssh/sshd_config <<'XAIOS_SSHD_CONFIG'
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
XAIOS_SSHD_CONFIG
sysrc sshd_enable=YES >/dev/null
/usr/bin/ssh-keygen -A || fail "could not generate FreeBSD SSH host keys"
service sshd restart || fail "could not start FreeBSD sshd"
sockstat -4 -l | grep -q ':22' || fail "FreeBSD sshd is not listening"
echo "{SERVER_READY}"
sleep 10

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
port=2223
ssh_base="-i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -p $port"
ready=0
attempt=0
while [ "$attempt" -lt 120 ]; do
    if ssh $ssh_base admin@$host 'echo freebsd-client-ssh-ok' >/tmp/ssh-ready.out 2>/tmp/ssh-ready.err; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done
[ "$ready" -eq 1 ] || fail "XAIOS SSH did not become reachable"
[ "$(cat /tmp/ssh-ready.out)" = "freebsd-client-ssh-ok" ] || fail "SSH output mismatch"

printf 'echo freebsd-pty-ok\nexit\n' | ssh -tt $ssh_base admin@$host \
    >/tmp/pty.out 2>/tmp/pty.err || {{ cat /tmp/pty.err; fail "PTY shell failed"; }}
[ "$(grep -c 'freebsd-pty-ok' /tmp/pty.out)" -ge 2 ] \
    || fail "PTY shell output mismatch"

if ssh -i "$bad_key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=5 -p "$port" admin@$host true >/tmp/bad.out 2>/tmp/bad.err; then
    fail "unauthorized key was accepted"
fi

ssh $ssh_base admin@$host 'xaiosctl version --json' >/tmp/version.json \
    || fail "xaiosctl failed"
grep -q '"status":"ok"' /tmp/version.json || fail "xaiosctl status mismatch"
grep -q '"architecture":"{expected_architecture}"' /tmp/version.json \
    || fail "xaiosctl architecture mismatch"

printf 'freebsd-sftp-roundtrip\nsecond-line\n' >/tmp/sftp-source
cat >/tmp/sftp.batch <<'XAIOS_SFTP_BATCH'
put /tmp/sftp-source /tmp/freebsd-sftp
ls -l /tmp/freebsd-sftp
get /tmp/freebsd-sftp /tmp/sftp-result
rename /tmp/freebsd-sftp /tmp/freebsd-sftp-renamed
get /tmp/freebsd-sftp-renamed /tmp/sftp-renamed-result
rm /tmp/freebsd-sftp-renamed
quit
XAIOS_SFTP_BATCH
sftp -b /tmp/sftp.batch -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -P "$port" admin@$host >/tmp/sftp.log 2>&1 \
    || {{ cat /tmp/sftp.log; fail "SFTP batch failed"; }}
cmp /tmp/sftp-source /tmp/sftp-result || fail "SFTP content differed"
cmp /tmp/sftp-source /tmp/sftp-renamed-result || fail "SFTP renamed content differed"

scp -vvv -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -P "$port" /tmp/sftp-source admin@$host:/tmp/freebsd-scp >/tmp/scp-upload.log 2>&1 \
    || {{ cat /tmp/scp-upload.log; fail "FreeBSD scp upload failed"; }}
scp -vvv -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -P "$port" admin@$host:/tmp/freebsd-scp /tmp/scp-result >/tmp/scp-download.log 2>&1 \
    || {{ cat /tmp/scp-download.log; fail "FreeBSD scp download failed"; }}
cmp /tmp/sftp-source /tmp/scp-result || fail "SCP content differed"

payload='freebsd-udp-echo'
reply=''
attempt=0
while [ "$attempt" -lt 5 ]; do
    reply="$(printf '%s' "$payload" | nc -u -w 5 "$host" 2224)" || true
    [ "$reply" = "$payload" ] && break
    attempt=$((attempt + 1))
    sleep 1
done
[ "$reply" = "$payload" ] || fail "UDP payload mismatch after 5 attempts"

echo "{CLIENT_PASS}"
"""


def user_data(
    private_key: str,
    unauthorized_key: str,
    server_password: str,
    architecture: str,
) -> str:
    script = freebsd_script(
        private_key, unauthorized_key, server_password, architecture
    )
    encoded = base64.b64encode(script.encode("ascii")).decode("ascii")
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
        "  - path: /root/xaios-freebsd-suite.sh\n"
        "    permissions: '0700'\n"
        "    owner: root:wheel\n"
        "    encoding: b64\n"
        f"    content: {encoded}\n"
        "runcmd:\n"
        "  - /bin/sh /root/xaios-freebsd-suite.sh\n"
    )


def xaios_process(
    architecture: str, env: dict[str, str], log_file: object
) -> subprocess.Popen[bytes]:
    if architecture == "aarch64":
        env.update(
            {
                "XAIOS_QEMU_ACCEL": "tcg",
                "XAIOS_QEMU_SMP": "4",
                "XAIOS_PERSISTENT_IMAGE": str(
                    BUILD / "qemu-freebsd-bidirectional-xaios-persistent.img"
                ),
            }
        )
        runner = ROOT / "scripts" / "run-qemu-aarch64.sh"
    else:
        env.update(
            {
                "XAIOS_QEMU_X86_ACCEL": "tcg",
                "XAIOS_QEMU_X86_SMP": "4",
                "XAIOS_X86_PERSISTENT_IMAGE": str(
                    BUILD / "qemu-freebsd-bidirectional-x86-persistent.img"
                ),
            }
        )
        runner = ROOT / "scripts" / "run-qemu-x86_64.sh"
    Path(env.get("XAIOS_PERSISTENT_IMAGE", env.get("XAIOS_X86_PERSISTENT_IMAGE", ""))).unlink(missing_ok=True)
    return subprocess.Popen(
        [str(runner)],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    architecture = os.environ.get("XAIOS_QEMU_NETWORK_ARCH", "aarch64")
    if architecture not in IMAGES:
        raise SystemExit("error: XAIOS_QEMU_NETWORK_ARCH must be aarch64 or x86_64")
    required = ("docker", "qemu-img", "xz", "ssh-keygen", "ssh")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"error: missing required tools: {', '.join(missing)}")

    BUILD.mkdir(parents=True, exist_ok=True)
    work = BUILD / f"qemu-freebsd-bidirectional-{architecture}"
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
    server_password = "Xf" + secrets.token_hex(16)
    password_file = work / "freebsd-password"
    password_file.write_text(server_password + "\n", encoding="ascii")
    password_file.chmod(0o600)

    base_image, image_sha256, archive_identity = prepare_freebsd_image(architecture)
    seed_dir = work / "cidata"
    seed_dir.mkdir()
    (seed_dir / "meta-data").write_text(
        "instance-id: xaios-freebsd-bidirectional\n"
        "local-hostname: xaios-freebsd-server\n",
        encoding="ascii",
    )
    (seed_dir / "user-data").write_text(
        user_data(
            (key_dir / "authorized").read_text(encoding="ascii"),
            (key_dir / "unauthorized").read_text(encoding="ascii"),
            server_password,
            architecture,
        ),
        encoding="ascii",
    )
    seed_iso = work / "cidata.iso"
    iso_tool = create_seed_iso(seed_dir, seed_iso)

    run_checked(
        [
            "docker",
            "build",
            "--pull",
            "--file",
            "tests/network/Dockerfile.freebsd-qemu",
            "--tag",
            DOCKER_IMAGE,
            ".",
        ],
        900,
    )

    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    build_env.pop("XAIOS_SSH_USERS_FILE", None)
    build_env.pop("XAIOS_SSH_PASSWORD_AUTH", None)
    build_target = "image" if architecture == "aarch64" else "image-x86_64"
    run_checked(["make", build_target], 360, build_env)

    xaios_ssh_port = reserve_port(socket.SOCK_STREAM)
    xaios_udp_port = reserve_port(socket.SOCK_DGRAM)
    freebsd_ssh_port = reserve_port(socket.SOCK_STREAM)
    xaios_log = BUILD / f"qemu-freebsd-bidirectional-xaios-{architecture}.log"
    freebsd_log = BUILD / f"qemu-freebsd-docker-{architecture}.log"
    xaios_env = build_env.copy()
    xaios_env.update(
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(xaios_ssh_port),
            "XAIOS_QEMU_HOSTFWD_UDP_PORT": str(xaios_udp_port),
        }
    )
    xaios_log_file = xaios_log.open("wb")
    xaios = xaios_process(architecture, xaios_env, xaios_log_file)
    container_name = f"xaios-freebsd-{architecture}-{os.getpid()}"
    freebsd: subprocess.Popen[bytes] | None = None
    freebsd_log_file = None
    try:
        wait_for_marker(xaios_log, (XAIOS_READY,), 240)
        freebsd_log_file = freebsd_log.open("wb")
        command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--add-host",
            "host.docker.internal:host-gateway",
            "--publish",
            f"{freebsd_ssh_port}:2222/tcp",
            "--volume",
            f"{base_image}:/images/freebsd.qcow2:ro",
            "--volume",
            f"{seed_iso}:/seed/cidata.iso:ro",
            "--volume",
            f"{work}:/work",
            "--env",
            f"XAIOS_FREEBSD_ARCH={architecture}",
            "--env",
            f"XAIOS_RELAY_SSH_PORT={xaios_ssh_port}",
            "--env",
            f"XAIOS_RELAY_UDP_PORT={xaios_udp_port}",
            DOCKER_IMAGE,
        ]
        print("+", " ".join(command), flush=True)
        freebsd = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=freebsd_log_file,
            stderr=subprocess.STDOUT,
        )
        server_marker = wait_for_marker(
            freebsd_log,
            (SERVER_READY, CLIENT_FAIL),
            float(os.environ.get("XAIOS_FREEBSD_TIMEOUT", "1200")),
        )
        if server_marker != SERVER_READY:
            raise RuntimeError("FreeBSD server provisioning failed")
        run_checked(
            [
                sys.executable,
                str(ROOT / "tests" / "network" / "xaios-outbound-client.py"),
                "--xaios-port",
                str(xaios_ssh_port),
                "--xaios-key",
                str(key_dir / "authorized"),
                "--target-port",
                str(freebsd_ssh_port),
                "--password-file",
                str(password_file),
                "--timeout",
                os.environ.get("XAIOS_OUTBOUND_TIMEOUT", "60"),
            ],
            900,
        )
        marker = wait_for_marker(
            freebsd_log,
            (CLIENT_PASS, CLIENT_FAIL),
            float(os.environ.get("XAIOS_FREEBSD_TIMEOUT", "1200")),
        )
        if marker != CLIENT_PASS:
            tail = "\n".join(freebsd_log.read_text(errors="replace").splitlines()[-120:])
            raise RuntimeError(f"FreeBSD client suite failed\n{tail}")
        if xaios.poll() is not None:
            raise RuntimeError(f"XAIOS exited unexpectedly: {xaios.returncode}")
        if freebsd.poll() is not None:
            raise RuntimeError(f"FreeBSD container exited unexpectedly: {freebsd.returncode}")

        report = {
            "schema": "xaios.qemu.freebsd_bidirectional.v1",
            "status": "pass",
            "xaios_architecture": architecture,
            "freebsd_release": FREEBSD_RELEASE,
            "freebsd_architecture": (
                "arm64" if architecture == "aarch64" else "amd64"
            ),
            "freebsd_image": IMAGES[architecture]["name"],
            "freebsd_archive_sha256": archive_identity,
            "freebsd_image_sha256": image_sha256,
            "freebsd_runtime": "QEMU TCG inside Debian 13 Docker",
            "seed_tool": iso_tool,
            "checks": {
                "freebsd_to_xaios_ssh": "passed",
                "freebsd_to_xaios_pty": "passed",
                "freebsd_to_xaios_unauthorized_key_rejection": "passed",
                "freebsd_to_xaios_sftp": "passed",
                "freebsd_to_xaios_scp": "passed",
                "freebsd_to_xaios_udp": "passed",
                "xaios_to_freebsd_ssh": "passed",
                "xaios_to_freebsd_wrong_password_rejection": "passed",
                "xaios_to_freebsd_scp_file": "passed",
                "xaios_to_freebsd_scp_recursive_upload": "passed",
                "xaios_to_freebsd_scp_recursive_download": "passed",
                "xaios_freebsd_known_host_persistence": "passed",
            },
        }
        report_path = BUILD / f"qemu-freebsd-bidirectional-{architecture}.json"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"PASS: FreeBSD bidirectional suite ({report_path})")
        return 0
    finally:
        if freebsd is not None and freebsd.poll() is None:
            subprocess.run(
                ["docker", "stop", "--time", "10", container_name],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            try:
                freebsd.wait(timeout=15)
            except subprocess.TimeoutExpired:
                freebsd.kill()
                freebsd.wait(timeout=5)
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
