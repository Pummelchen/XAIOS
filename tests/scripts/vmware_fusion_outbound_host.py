#!/usr/bin/env python3
"""Host plumbing and the disposable far end for the Fusion outbound gate.

This module owns everything the outbound gate needs from *this* side of the
bridge: the shared paths under `build/`, the commands run on the host, the LAN
address a bridged guest shares, and the throwaway Debian OpenSSH container that
stands in for a far end. `vmware-fusion-outbound-gate.py` and
`vmware_fusion_outbound_guest.py` both import from here, so the host keys, the
Docker image and the `build/` paths are named exactly once.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "scripts"))

_SMOKE = ROOT / "tests" / "scripts" / "vmware-fusion-smoke.py"
_spec = importlib.util.spec_from_file_location("fusion_smoke", _SMOKE)
assert _spec is not None and _spec.loader is not None
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

BUILD = ROOT / "build"
FUSION_BUILD = BUILD / "vmware-fusion"
REPORT = FUSION_BUILD / "fusion-outbound-gate.json"
SERIAL = smoke.SERIAL

# The guest's own client identity, packed into the image by build-image.sh at
# `/etc/xaios_ssh_client_identity`. The far end authorises its public half, so
# the outbound session is public-key from end to end and no password for
# anything exists anywhere in this gate.
OUTBOUND_KEY = BUILD / "fusion-outbound-key"
OUTBOUND_KEY_PUBLIC = OUTBOUND_KEY.with_suffix(".pub")
# Never packed into the guest. Its only job is to be the key the far end
# trusts when the negative control runs, so that the guest's key is genuinely
# the wrong one for one command and the right one for every other.
WRONG_KEY = BUILD / "fusion-outbound-wrong-key"
WRONG_KEY_PUBLIC = WRONG_KEY.with_suffix(".pub")
GUEST_IDENTITY = "/etc/xaios_ssh_client_identity"

DOCKER_IMAGE = "xaios-fusion-outbound-sshd:13"
DOCKERFILE = BUILD / "fusion-outbound-sshd.Dockerfile"
PROVISION = BUILD / "fusion-outbound-provision"
WORK = BUILD / "fusion-outbound-work"

# What the resolver falls back to when DHCP offers no option 6. A bridged
# guest that ends up here took no DNS from the LAN it is on, which is a
# different fault from a resolver that answers badly, and worth separating.
DNS_COMPILED_FALLBACK = "8.8.8.8"


def fnv1a64(data: bytes) -> int:
    """The hash the guest's own `stat` reports for a file's contents.

    Recomputing it here is what makes an SCP check a content check: the guest
    is asked what it thinks it stored, and the answer has to match bytes this
    side generated. `scp: transfer complete` and exit zero do not.
    """
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def run(command: list[str], *, timeout: int = 120, check: bool = True,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a host command, and on failure say what it printed.

    `check=True` on its own raises CalledProcessError, whose message is the
    exit status and nothing else. A `docker cp` that failed because the far
    end had already died then reaches the report as "returned non-zero exit
    status 1", which sends the reader to the wrong place.
    """
    print("+", " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(command)} failed with {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}")
    return result


def default_route_interface() -> str:
    result = run(["/sbin/route", "-n", "get", "default"], check=False)
    match = re.search(r"interface:\s*(\S+)", result.stdout)
    if match is None:
        raise RuntimeError("this host has no IPv4 default route, so there is "
                           "no LAN interface the bridged guest shares")
    return match.group(1)


def host_lan_address() -> tuple[str, str]:
    """The address the guest has to be able to reach, and its mask.

    Read from the interface carrying the default route rather than picked from
    a list: a Docker or vmnet address is up and has an IPv4, and publishing the
    far end on one of those would produce a container this host can reach and
    the guest cannot, which fails as "outbound SSH is broken".
    """
    interface = default_route_interface()
    result = run(["/sbin/ifconfig", interface], check=False)
    match = re.search(r"\n\s*inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)",
                      result.stdout)
    if match is None:
        raise RuntimeError(f"interface {interface} carries the default route "
                           f"but reports no IPv4 address")
    mask = int(match.group(2), 16)
    return match.group(1), str(ipaddress.IPv4Address(mask))


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def ensure_keys() -> None:
    for path in (OUTBOUND_KEY, WRONG_KEY):
        if path.is_file() and path.with_suffix(".pub").is_file():
            continue
        path.unlink(missing_ok=True)
        path.with_suffix(".pub").unlink(missing_ok=True)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", path.name,
             "-f", str(path)])
        path.chmod(0o600)


def build_far_end_image() -> None:
    """A Debian 13 OpenSSH server, built the way the QEMU suite builds its client.

    Same base and same registry-refresh-then-fall-back-to-cache handling as
    `qemu-docker-network-suite.py`, with `openssh-server` added because that
    suite only ever needed the client half.
    """
    DOCKERFILE.parent.mkdir(parents=True, exist_ok=True)
    DOCKERFILE.write_text(
        "FROM debian:13\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
        "RUN apt-get update \\\n"
        "    && apt-get install -y --no-install-recommends \\\n"
        "        openssh-server openssh-client \\\n"
        "    && rm -rf /var/lib/apt/lists/* \\\n"
        "    && mkdir -p /run/sshd\n",
        encoding="ascii")
    command = ["docker", "build", "--pull", "--file", str(DOCKERFILE),
               "--tag", DOCKER_IMAGE, str(DOCKERFILE.parent)]
    try:
        run(command, timeout=600)
    except RuntimeError:
        cached = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30)
        if cached.returncode != 0:
            raise
        print(f"warning: registry refresh failed; using the cached "
              f"{DOCKER_IMAGE} image", flush=True)


def write_provisioning() -> None:
    """Everything the far end needs, mounted read-only rather than baked in.

    Keys change every run; the image does not. Keeping them apart means the
    image is cacheable and the keys are never in a layer.
    """
    if PROVISION.exists():
        shutil.rmtree(PROVISION)
    PROVISION.mkdir(parents=True, mode=0o700)
    (PROVISION / "authorized_keys").write_text(
        OUTBOUND_KEY_PUBLIC.read_text(encoding="ascii"), encoding="ascii")
    (PROVISION / "wrong_authorized_keys").write_text(
        WRONG_KEY_PUBLIC.read_text(encoding="ascii"), encoding="ascii")
    (PROVISION / "entry.sh").write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "useradd -m -s /bin/bash xaios\n"
        "mkdir -p /home/xaios/.ssh\n"
        "cp /provision/authorized_keys /home/xaios/.ssh/authorized_keys\n"
        "chmod 700 /home/xaios/.ssh\n"
        "chmod 600 /home/xaios/.ssh/authorized_keys\n"
        "chown -R xaios:xaios /home/xaios\n"
        # Password and keyboard-interactive off, so an outbound session that
        # gets in did so with the key. Without this a far end that fell back
        # to another method would still look like a passing key check.
        "cat >>/etc/ssh/sshd_config <<'CONFIG'\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PermitRootLogin no\n"
        "PubkeyAuthentication yes\n"
        "CONFIG\n"
        "ssh-keygen -A\n"
        "mkdir -p /run/sshd\n"
        "exec /usr/sbin/sshd -D -e\n", encoding="ascii")
    (PROVISION / "entry.sh").chmod(0o755)


def docker_exec(container: str, *command: str,
                check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["docker", "exec", container, *command], check=check)


def start_far_end(container: str, port: int) -> None:
    subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                   timeout=60, check=False)
    run(["docker", "run", "--detach", "--name", container,
         "--publish", f"0.0.0.0:{port}:22/tcp",
         "--volume", f"{PROVISION}:/provision:ro",
         DOCKER_IMAGE, "/provision/entry.sh"])
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        logs = subprocess.run(["docker", "logs", container],
                              capture_output=True, text=True, timeout=30,
                              check=False)
        if "Server listening on 0.0.0.0 port 22" in logs.stdout + logs.stderr:
            return
        time.sleep(0.5)
    raise RuntimeError(f"the far-end container never started sshd:\n"
                       f"{logs.stdout}\n{logs.stderr}")


def stop_far_end(container: str) -> None:
    subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                   timeout=60, check=False)
    # The image goes too, so a gate run leaves the machine as it found it.
    # `XAIOS_FUSION_KEEP_IMAGE=1` keeps it for the next run, which is worth
    # about forty seconds of apt.
    if os.environ.get("XAIOS_FUSION_KEEP_IMAGE") != "1":
        subprocess.run(["docker", "image", "rm", "-f", DOCKER_IMAGE],
                       capture_output=True, timeout=120, check=False)
