#!/usr/bin/env python3
"""B-37: what the guest's own ssh/scp do when nobody is at the keyboard.

`/bin/ssh` and `/bin/scp` used to write a passphrase prompt on every
invocation that named an identity file, including for a key stored with no
passphrase at all, and then wait for an answer. Driven with a PTY -- which is
what `vmware-fusion-outbound-gate.py` has to do -- something answers. Driven
without one, which is every script, every CI job and every `ssh host 'ssh
...'`, nothing answers and the command never returns.

This gate is the no-terminal half. Almost every guest command here is run
over an SSH session with **no PTY** and stdin closed, so a prompt cannot be
answered even in principle, and every one of them has a bounded timeout: a
hang is a failure, not a wait. The three claims:

  * a key with no passphrase is not asked about -- the run completes, and no
    prompt appears anywhere in its output;
  * `-o BatchMode=yes` (and scp's `-B`) turns a credential that would have
    been asked for into an error with a non-zero exit, promptly;
  * even with no flag at all, a prompt nobody answers ends in a failure
    rather than an unbounded wait.

Each has a control beside it, because each can be green for the wrong reason:

  * a session that "succeeded" because the far end lets anyone in -- so the
    same command is run again with the guest's key taken out of the far end's
    `authorized_keys`, and has to be refused;
  * an scp that reports `transfer complete` having moved nothing -- so the
    bytes are read back on the far end and compared, and the destination of
    the *refused* transfer has to be absent;
  * an option parser that accepts `-o anything` and ignores it, which would
    make `BatchMode=yes` look implemented while doing nothing -- so an
    unknown `-o` has to be refused;
  * and the PTY path the Fusion gate depends on is driven here too, with an
    encrypted key, so that "it no longer prompts" cannot mean "it can no
    longer prompt".

Two boots, because a key reaches this guest exactly one way. The kernel
refuses to store credential material handed to it at runtime -- an SFTP write
whose bytes contain "BEGIN " is rejected, by design -- so the identity file
has to be packed into the image, and the image holds one. The first boot
carries a key with no passphrase; the second carries the same key material
stored with one. Everything that needs a plain key runs in the first, and
everything that needs an encrypted key runs in the second.

The far end is a disposable Debian 13 container with OpenSSH, built and
thrown away by this gate, published on a host port the guest reaches through
the user-mode network's gateway address. Nothing of the operator's is used.
"""

from __future__ import annotations

import json
import os
import selectors
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (QEMU_ARCHES, qemu_boot_environment, qemu_runner,
                           smoke_timeout, translate_qemu_env, write_report)

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


# ----------------------------------------------------------------- the guest

def build_guest_image(identity: Path) -> None:
    """Build the image with `identity` packed in as the client's key.

    A key reaches this guest no other way: the kernel refuses writes whose
    bytes look like credential material, which is what an OpenSSH private key
    is, so the runtime routes -- SFTP, a shell redirect -- are closed by
    design. That is why this gate builds twice.
    """
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(KEYS / "inbound.pub")
    env["XAIOS_SSH_CLIENT_IDENTITY_FILE"] = str(identity)
    if TARGET_ARCH == "riscv64":
        env.setdefault("XAIOS_BOOT_TEST_APPS", "0")
    for command in BUILD_COMMANDS:
        print("+", " ".join(command), f"[identity={identity.name}]", flush=True)
        result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                capture_output=True,
                                timeout=smoke_timeout(TARGET_ARCH, 1200))
        if result.returncode != 0:
            tail = "\n".join((result.stdout + result.stderr).splitlines()[-40:])
            raise RuntimeError(f"guest image build failed:\n{tail}")


def start_guest(name: str, port: int) -> tuple[subprocess.Popen[bytes], object]:
    log_path = BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}-{name}.log"
    log_file = log_path.open("wb")
    persistent = BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}-{name}.img"
    persistent.unlink(missing_ok=True)
    env = qemu_boot_environment(
        TARGET_ARCH, os.environ.copy(), accel="tcg", smp=4,
        persistent=persistent, hostfwd_port=port,
        state_dir=BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}-{name}-state",
        serial_to_stdout=True)
    env.update(translate_qemu_env(TARGET_ARCH, {}))
    process = subprocess.Popen([str(ROOT / qemu_runner(TARGET_ARCH))], cwd=ROOT,
                               env=env, stdin=subprocess.DEVNULL,
                               stdout=log_file, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + smoke_timeout(TARGET_ARCH, BOOT_TIMEOUT)
    while time.monotonic() < deadline:
        if log_path.exists():
            text = log_path.read_text(errors="replace")
            if SSH_READY_MARKER in text:
                print(f"guest {name!r} is up on port {port}", flush=True)
                return process, log_file
            lower = text.lower()
            fatal = next((m for m in FATAL_BOOT_MARKERS if m.lower() in lower),
                         None)
            if fatal is not None:
                raise RuntimeError(f"fatal guest boot marker {fatal!r}")
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before the guest was ready")
        time.sleep(0.25)
    raise TimeoutError(f"the guest never reached {SSH_READY_MARKER!r}")


def stop_guest(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


class GuestRun:
    """One guest command run with no PTY, and how long it took."""

    def __init__(self, command: str, output: str, status: int,
                 seconds: float) -> None:
        self.command = command
        self.output = output
        self.status = status
        self.seconds = seconds

    def record(self) -> dict[str, object]:
        return {"command": self.command, "exit_status": self.status,
                "seconds": round(self.seconds, 1),
                "output": self.output.strip()}


def guest_no_pty(port: int, command: str, *, timeout: float) -> GuestRun:
    """Run one command on the guest with no terminal and stdin closed.

    `-T` refuses a PTY outright and stdin is /dev/null, so a prompt written
    by whatever the guest launches has nobody to answer it. The timeout is
    the point of the exercise: it fires as a failure, never as a wait.
    """
    argv = ["ssh", "-T", *SSH_BASE, "-i", str(KEYS / "inbound"),
            "-p", str(port), "admin@127.0.0.1", command]
    print(f"GUEST (no pty)> {command}", flush=True)
    started = time.monotonic()
    try:
        result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        partial = (expired.stdout or b"") + (expired.stderr or b"")
        raise RuntimeError(
            f"NO PTY: still blocked after {timeout:.0f}s; "
            f"partial output = {partial!r}\n  command: {command}") from None
    seconds = time.monotonic() - started
    finished = GuestRun(command, result.stdout + result.stderr,
                        result.returncode, seconds)
    print(f"  exit {finished.status} after {seconds:.1f}s: "
          f"{finished.output.strip()!r}", flush=True)
    return finished


class GuestShell:
    """A PTY-backed guest session -- the path the Fusion gate relies on."""

    def __init__(self, port: int, timeout: float = 150.0) -> None:
        self.timeout = timeout
        self.process = subprocess.Popen(
            ["ssh", "-tt", *SSH_BASE, "-i", str(KEYS / "inbound"),
             "-p", str(port), "admin@127.0.0.1"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        assert self.process.stdout is not None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.output = bytearray()
        self.cursor = 0

    def _drain(self) -> None:
        assert self.process.stdout is not None
        while True:
            try:
                chunk = self.process.stdout.read(4096)
            except BlockingIOError:
                return
            if not chunk:
                return
            self.output.extend(chunk)

    def expect(self, marker: bytes, description: str) -> bytes:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            position = self.output.find(marker, self.cursor)
            if position >= 0:
                end = position + len(marker)
                seen = bytes(self.output[self.cursor:end])
                self.cursor = end
                return seen
            if self.process.poll() is not None:
                self._drain()
                break
            if self.selector.select(timeout=0.25):
                self._drain()
        tail = bytes(self.output[-4096:]).decode(errors="replace")
        raise RuntimeError(f"timed out waiting for {description}\n{tail}")

    def send(self, text: str) -> None:
        print(f"GUEST (pty)> {text.strip()}", flush=True)
        assert self.process.stdin is not None
        self.process.stdin.write(text.encode("ascii"))
        self.process.stdin.flush()

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.send("exit\n")
            except (BrokenPipeError, OSError):
                pass
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)


# -------------------------------------------------------------------- phases

def plain_key_phase(port: int, far_port: int,
                    transcripts: dict[str, object]) -> None:
    """The boot whose packed identity has no passphrase."""
    endpoint = f"{FAR_END_USER}@{FAR_END_ADDRESS}"

    first = guest_no_pty(
        port,
        f"ssh -i {GUEST_IDENTITY} -p {far_port} {endpoint} "
        "printf b37-no-pty-plain-ok",
        timeout=150.0)
    transcripts["plain_key_no_flag"] = first.record()
    require(first.status == 0, f"plain key with no PTY exited {first.status}")
    require("b37-no-pty-plain-ok" in first.output,
            "the far end's output never arrived")
    require("passphrase" not in first.output,
            f"a passphrase prompt was still written: {first.output!r}")
    require(first.seconds < IDLE_LOWER_BOUND,
            f"the run took {first.seconds:.1f}s, long enough to have been a "
            "prompt that timed out rather than a prompt never written")

    batch = guest_no_pty(
        port,
        f"ssh -o BatchMode=yes -i {GUEST_IDENTITY} -p {far_port} "
        f"{endpoint} printf b37-batch-mode-ok",
        timeout=150.0)
    transcripts["plain_key_batch_mode"] = batch.record()
    require(batch.status == 0, f"the BatchMode run exited {batch.status}")
    require("b37-batch-mode-ok" in batch.output,
            "the BatchMode run produced no far-end output")

    payload = f"b37-upload-{int(time.time())}"
    staged = guest_no_pty(port, f"echo {payload} > /tmp/b37-payload.txt",
                          timeout=PLUMBING_TIMEOUT)
    require(staged.status == 0, "could not stage the upload payload")
    upload = guest_no_pty(
        port,
        f"scp -o BatchMode=yes -i {GUEST_IDENTITY} -P {far_port} "
        f"/tmp/b37-payload.txt {endpoint}:/home/xaios/from-guest.txt",
        timeout=240.0)
    transcripts["scp_upload_batch_mode"] = upload.record()
    require(upload.status == 0, f"scp exited {upload.status}")
    require("scp: transfer complete" in upload.output,
            "scp did not report a completed transfer")
    landed = far_end("cat", "/home/xaios/from-guest.txt").stdout.strip()
    require(landed == payload, f"the far end holds {landed!r}, not {payload!r}")
    transcripts["scp_upload_bytes_on_far_end"] = landed

    download = guest_no_pty(
        port,
        f"scp -B -i {GUEST_IDENTITY} -P {far_port} "
        f"{endpoint}:/home/xaios/to-guest.txt /tmp/b37-download.txt",
        timeout=240.0)
    transcripts["scp_download_dash_b"] = download.record()
    require(download.status == 0, f"the scp download exited {download.status}")
    require("scp: transfer complete" in download.output,
            "the scp download did not report a completed transfer")
    read_back = guest_no_pty(port, "cat /tmp/b37-download.txt",
                             timeout=PLUMBING_TIMEOUT)
    require("b37-download-payload" in read_back.output,
            f"the downloaded file reads {read_back.output!r}")
    transcripts["scp_download_bytes_on_guest"] = read_back.output.strip()

    unknown = guest_no_pty(
        port,
        f"ssh -o StrictHostKeyChecking=no -i {GUEST_IDENTITY} "
        f"-p {far_port} {endpoint} printf should-not-run",
        timeout=60.0)
    transcripts["unknown_option_refused"] = unknown.record()
    require(unknown.status != 0, "an unsupported -o option was accepted")
    require("only -o BatchMode=yes|no is understood" in unknown.output,
            f"the option was not refused clearly: {unknown.output!r}")
    require("should-not-run" not in unknown.output, "the command ran anyway")

    # The control: the same command, against a far end that no longer
    # authorises this key. If this passes, the ones above meant nothing.
    authorise_far_end("wrong_authorized_keys")
    try:
        refused = guest_no_pty(
            port,
            f"ssh -o BatchMode=yes -i {GUEST_IDENTITY} -p {far_port} "
            f"{endpoint} printf should-not-run",
            timeout=150.0)
    finally:
        authorise_far_end("authorized_keys")
    transcripts["unauthorised_at_far_end"] = refused.record()
    require(refused.status != 0, "the far end let in a key it does not hold")
    require("public-key authentication failed" in refused.output,
            f"the far end refused for the wrong reason: {refused.output!r}")

    shell = GuestShell(port)
    try:
        shell.expect(PROMPT, "the guest shell prompt")
        mark = len(shell.output)
        shell.send(f"ssh -i {GUEST_IDENTITY} -p {far_port} {endpoint} "
                   "printf b37-interactive-plain-ok\n")
        shell.expect(b"b37-interactive-plain-ok", "the plain-key output")
        shell.expect(PROMPT, "the prompt after the plain-key run")
        section = bytes(shell.output[mark:]).decode(errors="replace")
    finally:
        shell.close()
    require("passphrase" not in section,
            f"the plain key was asked about on a PTY: {section!r}")
    transcripts["pty_plain_key"] = section


def locked_key_phase(port: int, far_port: int,
                     transcripts: dict[str, object]) -> None:
    """The boot whose packed identity is stored with a passphrase."""
    endpoint = f"{FAR_END_USER}@{FAR_END_ADDRESS}"

    batch = guest_no_pty(
        port,
        f"ssh -o BatchMode=yes -i {GUEST_IDENTITY} -p {far_port} "
        f"{endpoint} printf should-not-run",
        timeout=60.0)
    transcripts["encrypted_key_batch_mode"] = batch.record()
    require(batch.status != 0, "an encrypted key in BatchMode exited zero")
    require("needs a passphrase and BatchMode=yes is set" in batch.output,
            f"no clear reason was given: {batch.output!r}")
    require("should-not-run" not in batch.output, "the command ran anyway")
    require(batch.seconds < 20.0,
            f"the refusal took {batch.seconds:.1f}s, which is a wait")

    staged = guest_no_pty(port, "echo b37-should-not-move > /tmp/b37-payload.txt",
                          timeout=PLUMBING_TIMEOUT)
    require(staged.status == 0, "could not stage the upload payload")
    scp_batch = guest_no_pty(
        port,
        f"scp -B -i {GUEST_IDENTITY} -P {far_port} /tmp/b37-payload.txt "
        f"{endpoint}:/home/xaios/should-not-land.txt",
        timeout=60.0)
    transcripts["encrypted_key_scp_dash_b"] = scp_batch.record()
    require(scp_batch.status != 0, "scp -B with an encrypted key exited zero")
    require("needs a passphrase and BatchMode=yes is set" in scp_batch.output,
            f"scp gave no clear reason: {scp_batch.output!r}")
    absent = far_end("test", "-e", "/home/xaios/should-not-land.txt",
                     check=False)
    require(absent.returncode != 0, "the refused scp moved a file anyway")

    # No flag at all: the prompt goes out, nobody can answer it, and it has to
    # end rather than wait.
    stuck = guest_no_pty(
        port,
        f"ssh -i {GUEST_IDENTITY} -p {far_port} {endpoint} printf should-not-run",
        timeout=IDLE_UPPER_BOUND + 90.0)
    transcripts["encrypted_key_no_flag_no_pty"] = stuck.record()
    require(stuck.status != 0, "an unanswered prompt exited zero")
    require("key passphrase:" in stuck.output,
            f"the prompt itself never appeared: {stuck.output!r}")
    require("nothing answered the prompt" in stuck.output,
            f"no reason was given for giving up: {stuck.output!r}")
    require(IDLE_LOWER_BOUND < stuck.seconds < IDLE_UPPER_BOUND,
            f"gave up after {stuck.seconds:.1f}s, outside "
            f"{IDLE_LOWER_BOUND}-{IDLE_UPPER_BOUND}s")

    # And the path the Fusion gate depends on: a terminal, a prompt, an answer.
    shell = GuestShell(port)
    try:
        shell.expect(PROMPT, "the guest shell prompt")
        mark = len(shell.output)
        shell.send(f"ssh -i {GUEST_IDENTITY} -p {far_port} {endpoint} "
                   "printf b37-interactive-ok\n")
        shell.expect(PASSPHRASE_PROMPT, "the passphrase prompt on a PTY")
        shell.send(PASSPHRASE + "\n")
        shell.expect(b"b37-interactive-ok", "the interactive command output")
        shell.expect(PROMPT, "the prompt after the interactive run")
        section = bytes(shell.output[mark:]).decode(errors="replace")
    finally:
        shell.close()
    transcripts["pty_encrypted_key"] = section


def main() -> int:
    if shutil.which("docker") is None:
        raise SystemExit("error: the Docker CLI is required for the far end")
    run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=60)

    ensure_keys()
    build_far_end_image()
    write_provisioning()

    far_port = reserve_port()
    transcripts: dict[str, object] = {}
    results: dict[str, object] = {
        "architecture": TARGET_ARCH,
        "far_end_port": far_port,
        "prompt_idle_seconds": PROMPT_IDLE_SECONDS,
        "transcripts": transcripts,
    }

    start_far_end(far_port)
    try:
        for name, identity, phase in (
                ("plain", KEYS / "plain", plain_key_phase),
                ("locked", KEYS / "locked", locked_key_phase)):
            build_guest_image(identity)
            guest_port = reserve_port()
            guest, log_file = start_guest(name, guest_port)
            try:
                phase(guest_port, far_port, transcripts)
            finally:
                stop_guest(guest)
                log_file.close()
        results["status"] = "pass"
    finally:
        stop_far_end()

    write_report(BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}.json", results)
    print(json.dumps(results, indent=2, sort_keys=True), flush=True)
    print("QEMU_OUTBOUND_BATCH_MODE_GATE: PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
