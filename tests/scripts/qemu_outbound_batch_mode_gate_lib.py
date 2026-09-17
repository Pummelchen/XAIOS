#!/usr/bin/env python3
"""Shared run context for the B-37 outbound batch-mode gate.

Moved verbatim out of `qemu-outbound-batch-mode-gate.py` so the gate and the
guest-plumbing half (`qemu_outbound_batch_mode_guest_lib.py`) can name one copy
of the run context. This module owns the selected architecture and every path,
constant and bounded timeout derived from it, the disposable Debian far end and
the key fixtures, and the small process helpers both halves call.

It is imported and is not itself a program: `python3
tests/scripts/qemu-outbound-batch-mode-gate.py` remains the only entry point,
with the same command line, output and exit codes.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import QEMU_ARCHES

TARGET_ARCH = os.environ.get("XAIOS_QEMU_NETWORK_ARCH", "aarch64")
for _index, _argument in enumerate(sys.argv):
    if _argument == "--arch" and _index + 1 < len(sys.argv):
        TARGET_ARCH = sys.argv[_index + 1]
    elif _argument.startswith("--arch="):
        TARGET_ARCH = _argument.split("=", 1)[1]
if TARGET_ARCH not in QEMU_ARCHES:
    raise SystemExit(f"error: architecture must be one of {', '.join(QEMU_ARCHES)}")

BUILD_COMMANDS = {
    "aarch64": [["make", "image"]],
    "x86_64": [["make", "image-x86_64"]],
    "riscv64": [["./scripts/build-riscv64.sh"], ["./scripts/build-riscv64-image.sh"]],
}[TARGET_ARCH]
SUFFIX = "" if TARGET_ARCH == "aarch64" else f"-{TARGET_ARCH}"

DOCKER_IMAGE = "xaios-b37-outbound-sshd:13"
# Its own directory, holding nothing but the Dockerfile: a build context is
# shipped to the daemon whole, and build/ holds this run's private keys.
CONTEXT = BUILD / "b37-outbound-context"
DOCKERFILE = CONTEXT / "Dockerfile"
PROVISION = BUILD / "b37-outbound-provision"
KEYS = BUILD / "b37-outbound-keys"
CONTAINER = "xaios-b37-outbound-far-end"

# The guest reaches the host through the user-mode network's gateway, which is
# where the far end's published port lives.
FAR_END_ADDRESS = "10.0.2.2"
FAR_END_USER = "xaios"
GUEST_IDENTITY = "/etc/xaios_ssh_client_identity"
PASSPHRASE = "b37-locked-key-passphrase"

SSH_READY_MARKER = "SSH server: up and running (tcp/22)"
BOOT_TIMEOUT = int(os.environ.get("XAIOS_TEST_BOOT_TIMEOUT", "300"))
FATAL_BOOT_MARKERS = (
    "CYAN SCREEN OF DEATH",
    "System halted. Manual reset required",
    "kernel panic",
    "assertion failed",
)
PROMPT = b"admin@xaios"
PASSPHRASE_PROMPT = b" key passphrase: "

# The bounded wait the client applies to a prompt nobody answers, and the room
# this gate gives it. Both halves matter: too early and the client gave up on
# somebody still typing, too late and it is the outer session timing out
# rather than the client deciding anything.
PROMPT_IDLE_SECONDS = 60.0
IDLE_LOWER_BOUND = 45.0
IDLE_UPPER_BOUND = 110.0

# What a command that is not itself under test gets before it counts as hung:
# staging a file, reading one back. Generous, because this runs on an emulated
# machine that may be sharing the host with other work, and because nothing is
# claimed about how fast these are. The claims about promptness are asserted
# on the measured duration of the run that makes them, never on a budget.
PLUMBING_TIMEOUT = 180.0

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR"]


def run(command: list[str], *, timeout: int = 180, check: bool = True,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} exited {result.returncode}\n"
                           f"{result.stdout}\n{result.stderr}")
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ------------------------------------------------------------------ fixtures

def ensure_keys() -> None:
    """Four keys, and what each is for.

    `inbound` gets this gate into the guest. `plain` and `locked` are the two
    forms of the guest's own outbound identity -- the same question asked of
    the client twice, once of a key with no passphrase and once of a key with
    one. `wrong` never leaves this directory: only its public half is used,
    to make the far end refuse something.

    `-a 1` on the encrypted key keeps its bcrypt KDF to a single round. The
    guest does that work on an emulated CPU, and the number of rounds is not
    what is under test.
    """
    if KEYS.exists():
        shutil.rmtree(KEYS)
    KEYS.mkdir(parents=True, mode=0o700)
    for name in ("inbound", "plain", "wrong"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-C", f"xaios-b37-{name}", "-f", str(KEYS / name)], timeout=60)
        (KEYS / name).chmod(0o600)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-a", "1", "-N", PASSPHRASE,
         "-C", "xaios-b37-locked", "-f", str(KEYS / "locked")], timeout=60)
    (KEYS / "locked").chmod(0o600)
    header = (KEYS / "locked").read_text(encoding="ascii").splitlines()[0]
    require(header == "-----BEGIN OPENSSH PRIVATE KEY-----",
            f"unexpected private key header: {header!r}")


def build_far_end_image() -> None:
    if CONTEXT.exists():
        shutil.rmtree(CONTEXT)
    CONTEXT.mkdir(parents=True, exist_ok=True)
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
               "--tag", DOCKER_IMAGE, str(CONTEXT)]
    try:
        run(command, timeout=900)
    except RuntimeError:
        cached = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30)
        if cached.returncode != 0:
            raise
        print(f"warning: registry refresh failed; using cached {DOCKER_IMAGE}",
              flush=True)


def write_provisioning() -> None:
    if PROVISION.exists():
        shutil.rmtree(PROVISION)
    PROVISION.mkdir(parents=True, mode=0o700)
    # Both forms of the guest's identity are authorised: the encrypted one has
    # to be able to get in once its passphrase is typed, or the PTY check
    # would pass for the wrong reason.
    (PROVISION / "authorized_keys").write_text(
        (KEYS / "plain.pub").read_text(encoding="ascii")
        + (KEYS / "locked.pub").read_text(encoding="ascii"), encoding="ascii")
    (PROVISION / "wrong_authorized_keys").write_text(
        (KEYS / "wrong.pub").read_text(encoding="ascii"), encoding="ascii")
    (PROVISION / "entry.sh").write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "useradd -m -s /bin/bash xaios\n"
        "mkdir -p /home/xaios/.ssh\n"
        "cp /provision/authorized_keys /home/xaios/.ssh/authorized_keys\n"
        "chmod 700 /home/xaios/.ssh\n"
        "chmod 600 /home/xaios/.ssh/authorized_keys\n"
        "printf 'b37-download-payload\\n' > /home/xaios/to-guest.txt\n"
        "chown -R xaios:xaios /home/xaios\n"
        # Nothing but the key gets in, so a session that succeeded proves the
        # key was used rather than some fallback.
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


def start_far_end(port: int) -> None:
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True,
                   timeout=60, check=False)
    run(["docker", "run", "--detach", "--name", CONTAINER,
         "--publish", f"0.0.0.0:{port}:22/tcp",
         "--volume", f"{PROVISION}:/provision:ro",
         DOCKER_IMAGE, "/provision/entry.sh"], timeout=120)
    deadline = time.monotonic() + 120.0
    logs = subprocess.CompletedProcess([], 0, "", "")
    while time.monotonic() < deadline:
        logs = subprocess.run(["docker", "logs", CONTAINER], capture_output=True,
                              text=True, timeout=30, check=False)
        if "Server listening on 0.0.0.0 port 22" in logs.stdout + logs.stderr:
            return
        time.sleep(0.5)
    raise RuntimeError(f"far end never started sshd:\n{logs.stdout}\n{logs.stderr}")


def stop_far_end() -> None:
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True,
                   timeout=60, check=False)
    if os.environ.get("XAIOS_B37_KEEP_IMAGE") != "1":
        subprocess.run(["docker", "image", "rm", "-f", DOCKER_IMAGE],
                       capture_output=True, timeout=180, check=False)


def far_end(*command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["docker", "exec", "--user", "xaios", CONTAINER, *command],
               timeout=60, check=check)


def authorise_far_end(name: str) -> None:
    """Point the far end's authorized_keys at one of the provisioned files."""
    run(["docker", "exec", CONTAINER, "cp", f"/provision/{name}",
         "/home/xaios/.ssh/authorized_keys"], timeout=60)
    run(["docker", "exec", CONTAINER, "chown", "xaios:xaios",
         "/home/xaios/.ssh/authorized_keys"], timeout=60)
    run(["docker", "exec", CONTAINER, "chmod", "600",
         "/home/xaios/.ssh/authorized_keys"], timeout=60)
