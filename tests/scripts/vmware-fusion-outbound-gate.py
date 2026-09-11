#!/usr/bin/env python3
"""What a Fusion guest does as a client, and as something in the middle.

`vmware-fusion-network-gate.py` answers the inbound half of F-03: a bridged
guest takes a real lease, forms a global SLAAC address, answers ICMPv6 and
serves SSH and SFTP on both families. It says nothing about the guest reaching
out, and it said so, listing outbound SSH under `not_claimed` because the only
far end available was the operator's own Mac account.

That is no longer the only option. The far end here is a disposable Debian 13
container built and thrown away by this gate, published on the port this host
offers to the LAN the guest is bridged onto; nothing on the operator's machine
is touched, and no key of theirs is used. What that buys is the other three
claims F-03 still owed: the guest opening an outbound session and getting an
answer, a file moved each way and compared byte for byte, and a `direct-tcpip`
channel through the guest -- the shape OpenSSH's `ProxyJump` uses.

Every one of those has a negative control beside it, because each of them can
be made to look green by something that is not the thing:

  * an outbound session that "succeeds" because the far end would let anyone
    in -- so the same command is run once with the guest's key removed from
    the far end's `authorized_keys`, and has to be refused;
  * an SCP that reports `scp: transfer complete` and exit zero having moved
    the wrong bytes -- so the payload is compared three ways, and the gate
    additionally fetches a copy with one byte changed and requires the
    comparison to notice;
  * a forwarded channel that "opened" and carried nothing, or an `ssh -J` that
    silently bypassed the jump host because the target happens to be reachable
    from here too -- so 256 KiB is pulled through the channel and checksummed,
    and a forward to a closed port has to fail as a *channel* open failure,
    which is a different sentence from the one this host's own stack produces
    when it refuses a connection itself.

DNSSEC is the claim this host can only half answer, and the half it cannot is
left alone rather than dressed up. See `dnssec_checks` below.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import selectors
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "scripts"))

import importlib.util

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

# The guest shell's prompt, and the two things its ssh/scp say. The prompt is
# wrapped in colour escapes, which is why the marker is the text between them
# rather than a whole line.
PROMPT = b"admin@xaios"
PASSPHRASE_PROMPT = b" key passphrase: "
TRANSFER_COMPLETE = b"scp: transfer complete"
PUBKEY_REFUSED = b"ssh: public-key authentication failed"

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
        sock.bind(("0.0.0.0", 0))
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


class GuestShell:
    """A PTY-backed session on the guest, because its ssh client asks a question.

    `/bin/ssh` prompts for the identity file's passphrase on every invocation,
    including for a key that has none. Driven without a terminal the prompt is
    written and nothing answers it, and the command hangs until the outer SSH
    times out -- which reads as "outbound SSH does not work" and is not. So the
    session is a terminal, and the prompt is answered.
    """

    def __init__(self, address: str, timeout: float = 90.0) -> None:
        self.timeout = timeout
        self.process = subprocess.Popen(
            ["ssh", "-tt", "-F", "/dev/null", "-i", str(smoke.TEST_KEY),
             "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR",
             f"admin@{address}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        assert self.process.stdout is not None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.output = bytearray()
        self.cursor = 0
        self.expect(PROMPT, "the guest's first shell prompt")

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
                result = bytes(self.output[self.cursor:end])
                self.cursor = end
                return result
            if self.process.poll() is not None:
                self._drain()
                break
            if self.selector.select(timeout=0.25):
                self._drain()
        tail = bytes(self.output[-3000:]).decode(errors="replace")
        raise RuntimeError(f"timed out waiting for {description}\n{tail}")

    def send(self, text: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((text + "\n").encode("ascii"))
        self.process.stdin.flush()

    def command(self, command: str) -> str:
        print(f"guest> {command}", flush=True)
        self.send(command)
        return self.expect(PROMPT, f"the prompt after {command!r}").decode(
            errors="replace")

    def client_command(self, command: str) -> str:
        """One ssh/scp invocation, and the assertion that it asks nothing.

        This used to require the passphrase prompt, on the reasoning that a
        client which stopped asking should be caught rather than quietly fed a
        stray newline. The reasoning was right and the expectation was
        backwards: the identity this gate packs is generated with `-N ""` and
        has no passphrase, so asking for one was the defect (`B-37`). The
        client now reads the key before deciding, and a plain key is never
        prompted for.

        So the assertion inverts rather than disappearing. A prompt here means
        the client is asking for a credential that does not exist, which is
        what B-37 was, and this raises on it.
        """
        print(f"guest> {command}", flush=True)
        self.send(command)
        answer = self.expect(PROMPT, f"the prompt after {command!r}").decode(
            errors="replace")
        if PASSPHRASE_PROMPT.decode(errors="replace") in answer:
            raise RuntimeError(
                f"{command!r} was asked for a passphrase. The identity this "
                f"gate packs has none, so there is nothing to answer: this is "
                f"B-37 returning. Output: {answer[:300]!r}")
        return answer

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.send("exit")
            except OSError:
                pass
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


CONTENT_HASH = re.compile(r"content_hash=(\d+)")
SIZE = re.compile(r"size=(\d+)")


def guest_file_identity(shell: GuestShell, path: str) -> tuple[int, int]:
    output = shell.command(f"stat {path}")
    content = CONTENT_HASH.search(output)
    size = SIZE.search(output)
    if content is None or size is None:
        raise RuntimeError(f"the guest did not describe {path}: {output!r}")
    return int(size.group(1)), int(content.group(1))


def jump_config(path: Path, guest: str, target: str, port: int) -> None:
    path.write_text(
        "Host xaios-jump\n"
        f"  HostName {guest}\n"
        "  Port 22\n"
        "  User admin\n"
        f"  IdentityFile {smoke.TEST_KEY}\n"
        "  IdentitiesOnly yes\n"
        "  StrictHostKeyChecking no\n"
        "  UserKnownHostsFile /dev/null\n"
        "  BatchMode yes\n"
        "Host far-end-via-xaios\n"
        f"  HostName {target}\n"
        f"  Port {port}\n"
        "  User xaios\n"
        f"  IdentityFile {OUTBOUND_KEY}\n"
        "  IdentitiesOnly yes\n"
        "  StrictHostKeyChecking no\n"
        "  UserKnownHostsFile /dev/null\n"
        "  BatchMode yes\n"
        "  ProxyJump xaios-jump\n", encoding="ascii")
    path.chmod(0o600)


def outbound_checks(shell: GuestShell, container: str, host_ip: str,
                    port: int, checks: dict[str, object],
                    failures: list[str]) -> None:
    identity = f"-i {GUEST_IDENTITY} -p {port} xaios@{host_ip}"

    # 1. Outbound SSH. The token is minted after the far end is already up and
    # written into it from this side, so the only way it can appear in the
    # guest's output is a session the guest opened and read it through.
    token = secrets.token_hex(16)
    (WORK / "token.txt").write_text(token + "\n", encoding="ascii")
    run(["docker", "cp", str(WORK / "token.txt"),
         f"{container}:/home/xaios/token.txt"])
    docker_exec(container, "chown", "xaios:xaios", "/home/xaios/token.txt")
    session = shell.client_command(
        f"ssh {identity} cat /home/xaios/token.txt")
    checks["outbound_ssh"] = {
        "token_returned": token in session,
        "transcript": session.strip()[-300:],
    }
    if token not in session:
        failures.append(
            "the guest opened no usable outbound SSH session: the far end's "
            f"token did not come back\n{session}")

    # 1b. Negative control. Same command, same key in the guest, but the far
    # end now trusts a key the guest has never had. A far end that would admit
    # anyone, or a client that reports success without authenticating, shows
    # up here and nowhere else.
    run(["docker", "cp", str(PROVISION / "wrong_authorized_keys"),
         f"{container}:/home/xaios/.ssh/authorized_keys"])
    docker_exec(container, "chown", "xaios:xaios",
                "/home/xaios/.ssh/authorized_keys")
    docker_exec(container, "chmod", "600", "/home/xaios/.ssh/authorized_keys")
    try:
        refused = shell.client_command(
            f"ssh {identity} cat /home/xaios/token.txt")
    finally:
        run(["docker", "cp", str(PROVISION / "authorized_keys"),
             f"{container}:/home/xaios/.ssh/authorized_keys"])
        docker_exec(container, "chown", "xaios:xaios",
                    "/home/xaios/.ssh/authorized_keys")
        docker_exec(container, "chmod", "600",
                    "/home/xaios/.ssh/authorized_keys")
    rejected = (PUBKEY_REFUSED.decode() in refused) and (token not in refused)
    checks["outbound_ssh_wrong_key_refused"] = {
        "refused": rejected,
        "transcript": refused.strip()[-300:],
    }
    if not rejected:
        failures.append(
            "an outbound session was not refused when the far end stopped "
            f"trusting the guest's key, so the check above proves nothing"
            f"\n{refused}")

    # 2. Outbound SCP, both directions, compared by content rather than by
    # exit status. Three parties have to agree: the bytes this host generated,
    # the hash the guest reports for its copy, and the digest the far end
    # computes for the copy the guest sent back.
    payload = (secrets.token_hex(2048) + "\n").encode("ascii")
    fixture = WORK / "fixture.hex"
    fixture.write_bytes(payload)
    expected_sha = hashlib.sha256(payload).hexdigest()
    expected_fnv = fnv1a64(payload)
    run(["docker", "cp", str(fixture), f"{container}:/home/xaios/fixture.hex"])
    docker_exec(container, "chown", "xaios:xaios", "/home/xaios/fixture.hex")

    # `-P` for scp, `-p` for ssh. Writing the two out separately rather than
    # patching one string into the other keeps the difference visible; getting
    # it wrong costs a boot to discover.
    download = shell.client_command(
        f"scp -i {GUEST_IDENTITY} -P {port} "
        f"xaios@{host_ip}:/home/xaios/fixture.hex "
        f"/tmp/fusion-outbound-down.hex")
    size, content = guest_file_identity(shell, "/tmp/fusion-outbound-down.hex")
    checks["outbound_scp_download"] = {
        "transfer_complete": TRANSFER_COMPLETE.decode() in download,
        "guest_bytes": size,
        "expected_bytes": len(payload),
        "guest_content_hash": content,
        "expected_content_hash": expected_fnv,
        "identical": size == len(payload) and content == expected_fnv,
    }
    if not checks["outbound_scp_download"]["identical"]:
        failures.append(
            f"the file the guest fetched over SCP is not the file the far end "
            f"holds: {size} bytes hash {content}, expected {len(payload)} "
            f"bytes hash {expected_fnv}")

    upload = shell.client_command(
        f"scp -i {GUEST_IDENTITY} -P {port} /tmp/fusion-outbound-down.hex "
        f"xaios@{host_ip}:/home/xaios/from-guest.hex")
    digest = docker_exec(container, "sha256sum", "/home/xaios/from-guest.hex",
                         check=False)
    returned_sha = digest.stdout.split()[0] if digest.stdout.split() else ""
    checks["outbound_scp_upload"] = {
        "transfer_complete": TRANSFER_COMPLETE.decode() in upload,
        "far_end_sha256": returned_sha,
        "expected_sha256": expected_sha,
        "identical": returned_sha == expected_sha,
    }
    if returned_sha != expected_sha:
        failures.append(
            f"the file the guest sent over SCP did not arrive intact: the far "
            f"end holds {returned_sha!r}, this host generated {expected_sha!r}")

    # 2b. Negative control, and the reason the two checks above compare
    # content. The same fetch is repeated against a copy with one byte
    # changed. The client still reports `scp: transfer complete` and the
    # session still ends cleanly -- an exit-status gate passes here -- so the
    # hash is required to differ, and a comparison that had been quietly
    # trivial (both sides zero, both sides empty) fails this instead.
    corrupted = bytearray(payload)
    index = len(corrupted) // 3
    corrupted[index] ^= 0x01
    corrupt_path = WORK / "fixture-corrupt.hex"
    corrupt_path.write_bytes(bytes(corrupted))
    run(["docker", "cp", str(corrupt_path),
         f"{container}:/home/xaios/fixture-corrupt.hex"])
    docker_exec(container, "chown", "xaios:xaios",
                "/home/xaios/fixture-corrupt.hex")
    corrupt_transfer = shell.client_command(
        f"scp -i {GUEST_IDENTITY} -P {port} "
        f"xaios@{host_ip}:/home/xaios/fixture-corrupt.hex "
        f"/tmp/fusion-outbound-corrupt.hex")
    bad_size, bad_content = guest_file_identity(
        shell, "/tmp/fusion-outbound-corrupt.hex")
    noticed = bad_content != expected_fnv and bad_content == fnv1a64(
        bytes(corrupted))
    checks["outbound_scp_corruption_noticed"] = {
        "client_reported_success": TRANSFER_COMPLETE.decode() in corrupt_transfer,
        "guest_content_hash": bad_content,
        "good_content_hash": expected_fnv,
        "corrupt_content_hash": fnv1a64(bytes(corrupted)),
        "same_length": bad_size == len(payload),
        "noticed": noticed,
    }
    if not noticed:
        failures.append(
            "a single changed byte did not change the hash the guest reports, "
            "so the SCP comparison above is not comparing contents")


def forwarding_checks(container: str, guest_ip: str, host_ip: str, port: int,
                      token: str, checks: dict[str, object],
                      failures: list[str]) -> None:
    config = WORK / "jump.conf"
    jump_config(config, guest_ip, host_ip, port)

    # 3. direct-tcpip through the guest. `ssh -v` names the jump host it went
    # through, which is the difference between a forwarded session and one
    # that reached the far end directly -- worth asserting, because from this
    # host the far end is also reachable without any guest at all.
    jumped = run(["ssh", "-v", "-F", str(config), "far-end-via-xaios",
                  "cat", "/home/xaios/token.txt"], timeout=180, check=False)
    transcript = jumped.stdout + jumped.stderr
    via_proxy = "(via proxy)" in transcript
    checks["forward_direct_tcpip"] = {
        "exit_code": jumped.returncode,
        "token_returned": token in jumped.stdout,
        "client_reports_via_proxy": via_proxy,
        "channel": next((line.strip() for line in transcript.splitlines()
                         if "direct-tcpip" in line), None),
    }
    if jumped.returncode != 0 or token not in jumped.stdout or not via_proxy:
        failures.append(
            "no usable direct-tcpip session through the guest: "
            f"rc={jumped.returncode} via_proxy={via_proxy}\n{transcript[-1200:]}")

    # 3b. And the channel has to have carried the data, not merely opened. A
    # quarter of a megabyte is more than one channel window, so a forward that
    # opens and then stalls on flow control fails here rather than passing on
    # the strength of a handshake.
    big = WORK / "forward-payload.bin"
    big_bytes = secrets.token_bytes(262144)
    big.write_bytes(big_bytes)
    run(["docker", "cp", str(big), f"{container}:/home/xaios/payload.bin"])
    docker_exec(container, "chown", "xaios:xaios", "/home/xaios/payload.bin")
    fetched = WORK / "forward-payload.out"
    fetched.unlink(missing_ok=True)
    pulled = run(["scp", "-F", str(config),
                  "far-end-via-xaios:/home/xaios/payload.bin", str(fetched)],
                 timeout=300, check=False)
    arrived = fetched.read_bytes() if fetched.exists() else b""
    checks["forward_payload"] = {
        "exit_code": pulled.returncode,
        "bytes_sent": len(big_bytes),
        "bytes_received": len(arrived),
        "identical": arrived == big_bytes,
        "sha256": hashlib.sha256(arrived).hexdigest() if arrived else None,
    }
    if arrived != big_bytes:
        failures.append(
            f"the forwarded channel did not carry the payload intact: "
            f"{len(arrived)} of {len(big_bytes)} bytes\n{pulled.stderr[-600:]}")

    # 3c. Negative control, and the one that proves the guest is in the path.
    # A forward to a closed port has to fail the way a *channel* fails --
    # the guest answering CHANNEL_OPEN_FAILURE because its own connect() did.
    # This host refusing a connection itself says something else entirely, and
    # the gate requires the two sentences to differ: if `ssh -J` were silently
    # bypassing the jump host, this check would produce the local refusal.
    closed = reserve_port()
    closed_config = WORK / "jump-closed.conf"
    jump_config(closed_config, guest_ip, host_ip, closed)
    blocked = run(["ssh", "-F", str(closed_config), "-o", "ConnectTimeout=10",
                   "far-end-via-xaios", "true"], timeout=120, check=False)
    blocked_text = blocked.stdout + blocked.stderr
    direct = run(["ssh", "-F", "/dev/null", "-i", str(OUTBOUND_KEY),
                  "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                  "-o", "StrictHostKeyChecking=no",
                  "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "ConnectTimeout=10", "-p", str(closed),
                  f"xaios@{host_ip}", "true"], timeout=120, check=False)
    direct_text = direct.stdout + direct.stderr
    channel_failure = "open failed" in blocked_text
    local_refusal = "Connection refused" in direct_text
    checks["forward_closed_port_refused"] = {
        "closed_port": closed,
        "through_guest_exit_code": blocked.returncode,
        "through_guest": next((line.strip() for line in
                               blocked_text.splitlines()
                               if "open failed" in line), None)
                          or blocked_text.strip()[-200:],
        "direct_from_this_host": direct_text.strip()[-200:],
        "channel_open_failure": channel_failure,
        "direct_attempt_refused_locally": local_refusal,
        "shapes_differ": channel_failure and local_refusal
                         and "open failed" not in direct_text,
    }
    if blocked.returncode == 0:
        failures.append("a forward to a closed port succeeded")
    if not checks["forward_closed_port_refused"]["shapes_differ"]:
        failures.append(
            "a forward to a closed port did not fail as a channel open "
            "failure distinguishable from this host's own connection refusal, "
            "so nothing here shows the guest was in the path:\n"
            f"through guest: {blocked_text[-400:]}\n"
            f"direct: {direct_text[-400:]}")


NSLOOKUP = re.compile(r"^\s*(\S+): (.+?)\s*$", re.MULTILINE)


# XAIOS_ERR_CANCELLED, which the resolver reports when a query misses its own
# deadline or the chain walk misses its budget. It is not a verdict about the
# chain; it means no verdict was reached, and reading it as one is how a
# timeout gets recorded as a refusal.
#
# This used to be the bare "error(7)" of the status code, which said nothing
# and sat one typo away from "dnssec-unverified" in a reader's eye. B-36 gave
# the shell a word for it; B-35 made the thing it names less likely, by giving
# each query in the walk its own deadline instead of sharing one across all of
# them.
TIMED_OUT = "dnssec-timeout"

# B-33's fixture zone, answered from the committed chain in boot-test
# builds. 10.53.0.7 is the address the chain signs; the forged name shares
# its zone and key with one bit flipped in the signature.
DNSSEC_FIXTURE_NAME = "selftest"
DNSSEC_FIXTURE_FORGED = "forged.selftest"
DNSSEC_FIXTURE_ADDRESS = "10.53.0.7"


def guest_nslookup(shell: GuestShell, name: str, *, attempts: int = 40,
                   retry_timeouts: int = 0) -> str:
    """The guest's answer for one name, waited out rather than sampled once.

    The resolver is asynchronous: the first call starts the chain and returns
    `pending`, and the answer arrives on a later call. A check that read the
    first reply would record `pending` for everything and never fail.

    `retry_timeouts` restarts the whole resolution when it comes back as
    `dnssec-timeout`. Each query in the chain now has its own fifteen-second
    deadline and the walk as a whole has a forty-five-second budget, so a slow
    delegation no longer spends the whole allowance on one hop -- but a walk
    can still run out, and retrying gives it another budget rather than filing
    the timeout as an answer.
    """
    for attempt in range(retry_timeouts + 1):
        answer = "pending"
        for _ in range(attempts):
            output = shell.command(f"nslookup {name}")
            found = None
            for owner, value in NSLOOKUP.findall(output):
                if owner.lower() == name.lower():
                    found = value
            if found is not None:
                answer = found
            if answer != "pending":
                break
            time.sleep(1.0)
        if answer != TIMED_OUT or attempt == retry_timeouts:
            return answer
        time.sleep(2.0)
    return answer


def dnssec_checks(shell: GuestShell, checks: dict[str, object],
                  failures: list[str], not_claimed: list[str]) -> None:
    """What this host can and cannot establish about the guest's resolver.

    This used to say a signed chain could not be staged inside a guest, and
    gave a good reason: the anchors are the compiled IANA roots,
    `dnssec_set_trust_anchors` has no in-guest caller, and the resolver address
    comes from the DHCP lease with no override, so a chain this gate controlled
    had no root to hang from. B-33 gave it one. In boot-test builds -- which is
    how `vmware-fusion-smoke` builds this guest -- the resolver answers
    `selftest` and `forged.selftest` from the chain committed at
    `kernel/net/dns_selftest_chain.h`, walking it in full with the anchor
    passed in as the parent DS set rather than installed globally. That is
    asserted here, and it is the claim.

    Two further things are asserted, and neither of them is:

      * the resolver was wired from the bridged lease rather than falling back
        to the compiled address, which is falsifiable and fails whenever the
        bridge or the lease does; and
      * an RFC 6761 `.invalid` name yields no address, which is the fail-closed
        contract. This one cannot go red on a healthy machine and is recorded
        as a contract assertion rather than as evidence.

    `XAIOS_FUSION_DNSSEC_LIVE=1` runs the pair that does demonstrate local
    validation -- `example.com`, correctly signed, against `dnssec-failed.org`,
    deliberately signed wrong, through the same LAN resolver in the same
    minute. When both land it is its own negative control: the bogus answer is
    present and handed to the guest, because the guest sets CD and the upstream
    passes the RRset through, so a refusal is a signature decision and nothing
    else. It has been seen to land -- `example.com` to an address and
    `dnssec-failed.org` to `dnssec-unverified` -- and it is still recorded as
    an observation that never fails the gate, for two reasons. It needs the
    public internet, which no gate here may. And it does not always reach a
    verdict: the longer chain was observed spending its budget and saying so,
    which reports a timeout and says nothing about the signature. That used to
    be much easier to hit, because the whole walk shared one fifteen-second
    budget against a five-second retransmit timer (B-35); each query now has
    that budget to itself and the walk has one of its own. Failing a gate on a
    timeout would be reporting the weather; passing on it would be worse.
    """
    text = SERIAL.read_text(errors="replace")
    lease = re.search(r"network: DHCP lease ip=\w+ mask=\w+ gw=\w+ dns=(\w+)",
                      text)
    configured = re.search(
        r"dns: configured validating resolver (\d+\.\d+\.\d+\.\d+)", text)
    leased_dns = (str(ipaddress.IPv4Address(int(lease.group(1), 16)))
                  if lease else None)
    checks["dnssec_resolver_wiring"] = {
        "dhcp_offered_dns": leased_dns,
        "resolver_configured": configured.group(1) if configured else None,
        "compiled_fallback": DNS_COMPILED_FALLBACK,
        "from_bridged_lease": bool(
            configured and leased_dns
            and configured.group(1) == leased_dns
            and configured.group(1) != DNS_COMPILED_FALLBACK),
    }
    if not checks["dnssec_resolver_wiring"]["from_bridged_lease"]:
        failures.append(
            f"the guest did not take its validating resolver from the bridged "
            f"lease: DHCP offered {leased_dns}, the resolver was configured as "
            f"{configured.group(1) if configured else None}")

    # The signed chain, validated inside this guest, on this hypervisor.
    #
    # This is what the docstring above used to say could not be staged, and
    # the reason it gave was right at the time: the anchors are the compiled
    # IANA roots, dnssec_set_trust_anchors has no in-guest caller, and the
    # resolver address comes from the bridged lease, so a chain we control had
    # no root to hang from. B-33 gave it one. Under XAIOS_BOOT_TEST_APPS --
    # which vmware-fusion-smoke builds this guest with -- the resolver answers
    # two names from the chain committed at kernel/net/dns_selftest_chain.h,
    # walking root DNSKEY to DS to child DNSKEY to RRSIG with the anchor passed
    # in as the parent DS set rather than installed globally. No packet leaves
    # the guest, nothing depends on the LAN's resolver, and no anchor is
    # swapped underneath a real resolution.
    #
    # The pair is its own control: the two names share a zone and a key and
    # differ by one flipped bit in the signature. Both answering means nothing
    # is being verified; neither answering means the resolver is broken rather
    # than strict. Only good-resolves-and-forged-refused can happen if the
    # chain is really being walked.
    good = guest_nslookup(shell, DNSSEC_FIXTURE_NAME, attempts=12)
    forged = guest_nslookup(shell, DNSSEC_FIXTURE_FORGED, attempts=12)
    checks["dnssec_local_chain"] = {
        "name": DNSSEC_FIXTURE_NAME,
        "answer": good,
        "expected": DNSSEC_FIXTURE_ADDRESS,
        "forged_name": DNSSEC_FIXTURE_FORGED,
        "forged_answer": forged,
        "validated": good == DNSSEC_FIXTURE_ADDRESS,
        "forged_refused": forged == "dnssec-unverified",
    }
    if good != DNSSEC_FIXTURE_ADDRESS:
        failures.append(
            f"the guest did not validate the committed signed chain: "
            f"{DNSSEC_FIXTURE_NAME} answered {good!r}, expected "
            f"{DNSSEC_FIXTURE_ADDRESS}. This walk needs no network and no "
            f"LAN resolver, so a failure here is the guest's own validator")
    if forged != "dnssec-unverified":
        failures.append(
            f"the guest accepted a tampered signature: "
            f"{DNSSEC_FIXTURE_FORGED} answered {forged!r}, expected "
            f"dnssec-unverified. The forged zone differs from the good one by "
            f"a single bit in the RRSIG, so accepting it means the signature "
            f"is not being checked at all")

    unresolvable = f"{secrets.token_hex(6)}.xaios-fusion-gate.invalid"
    answer = guest_nslookup(shell, unresolvable, attempts=8)
    manufactured = False
    try:
        ipaddress.ip_address(answer)
        manufactured = True
    except ValueError:
        manufactured = False
    checks["dnssec_fail_closed"] = {
        "name": unresolvable,
        "answer": answer,
        "no_address_returned": not manufactured,
        "note": "a contract assertion, not evidence: on a healthy machine "
                "nothing can make this go red",
    }
    if manufactured:
        failures.append(
            f"the guest returned an address for a name that cannot exist: "
            f"{unresolvable} -> {answer}")

    # The claim stays open whatever the observation below says. A gate cannot
    # rest on the public internet, and this one does not: the sentence names
    # what would have to change for the claim to be closable here.
    not_claimed.append(
        "live recursive DNSSEC against a public resolver: that needs the "
        "internet, which no gate here may depend on, and it does not always "
        "reach a verdict. XAIOS_FUSION_DNSSEC_LIVE=1 records the signed-versus"
        "-bogus pair as an observation that never affects pass or fail. Local "
        "validation of a signed chain is no longer in this list -- see "
        "dnssec_local_chain above")

    if os.environ.get("XAIOS_FUSION_DNSSEC_LIVE") != "1":
        return

    signed = guest_nslookup(shell, "example.com", retry_timeouts=1)
    bogus = guest_nslookup(shell, "dnssec-failed.org", retry_timeouts=2)
    signed_ok = False
    try:
        signed_ok = ipaddress.ip_address(signed).version == 4
    except ValueError:
        signed_ok = False
    if signed_ok and bogus == "dnssec-unverified":
        verdict = ("the guest accepted a correctly signed chain and refused a "
                   "mis-signed one through the same resolver")
    elif TIMED_OUT in (signed, bogus):
        verdict = ("inconclusive: a resolution spent its budget before "
                   "reaching a verdict, which is a timeout and not a "
                   "signature decision")
    else:
        verdict = (f"inconclusive: signed={signed!r} bogus={bogus!r}, which is "
                   f"neither the accept-and-refuse pair nor a timeout")
    checks["dnssec_live_chain_observation"] = {
        "contributes_to_status": False,
        "requires_public_internet": True,
        "signed_name": "example.com",
        "signed_answer": signed,
        "signed_accepted": signed_ok,
        "bogus_name": "dnssec-failed.org",
        "bogus_answer": bogus,
        "bogus_refused": bogus == "dnssec-unverified",
        "verdict": verdict,
    }
    print(f"vmware-fusion-outbound-gate: DNSSEC observation -- {verdict}",
          flush=True)


CONTAINER = f"xaios-fusion-outbound-{os.getpid()}"


def main() -> int:
    if sys.platform != "darwin":
        print("vmware-fusion-outbound-gate: needs macOS with VMware Fusion")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"vmware-fusion-outbound-gate: no vmrun at {smoke.VMRUN}; "
              f"skipping")
        return 0
    if shutil.which("docker") is None:
        print("vmware-fusion-outbound-gate: the far end is a Docker "
              "container and there is no docker on PATH; skipping")
        return 0

    BUILD.mkdir(parents=True, exist_ok=True)
    smoke.ensure_test_key()
    ensure_keys()
    host_ip, netmask = host_lan_address()
    port = reserve_port()

    # The guest's client identity has to be inside the image, so it is set
    # before the build rather than after: build_guest copies this environment.
    os.environ["XAIOS_SSH_CLIENT_IDENTITY_FILE"] = str(OUTBOUND_KEY)
    smoke.build_guest()
    # After the build, not before: a failed build-image.sh clears build/ on its
    # way out, and a working directory created ahead of it comes back missing.
    WORK.mkdir(parents=True, exist_ok=True)
    build_far_end_image()
    write_provisioning()

    failures: list[str] = []
    checks: dict[str, object] = {"host_lan_address": host_ip,
                                 "far_end_port": port}
    not_claimed: list[str] = [
        "outbound SSH and SCP over IPv6: the far end is published on this "
        "host's IPv4 LAN address only, so nothing here exercises the guest's "
        "client on the other family",
        "behaviour under loss or reordering: the LAN is not a controlled link",
    ]
    shell: GuestShell | None = None
    try:
        start_far_end(CONTAINER, port)
        smoke.stop_hard()
        guest_ip, _ = smoke.start_vm(0)
        checks["guest_ipv4"] = guest_ip
        network = ipaddress.IPv4Network(f"{host_ip}/{netmask}", strict=False)
        checks["guest_shares_host_lan"] = (
            ipaddress.IPv4Address(guest_ip) in network)
        if not checks["guest_shares_host_lan"]:
            failures.append(
                f"the guest took {guest_ip}, which is not on {network}; the "
                f"far end is published on this host's LAN address and a guest "
                f"elsewhere cannot reach it")

        shell = GuestShell(guest_ip)
        outbound_checks(shell, CONTAINER, host_ip, port, checks, failures)
        token = (WORK / "token.txt").read_text(encoding="ascii").strip()
        forwarding_checks(CONTAINER, guest_ip, host_ip, port, token, checks,
                          failures)
        dnssec_checks(shell, checks, failures, not_claimed)
    except (OSError, RuntimeError, subprocess.SubprocessError,
            TimeoutError) as error:
        failures.append(str(error))
    finally:
        if shell is not None:
            try:
                shell.close()
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
        try:
            smoke.stop_hard()
        except (OSError, RuntimeError, subprocess.SubprocessError,
                TimeoutError) as error:
            failures.append(f"cleanup: the Fusion VM did not stop: {error}")
        stop_far_end(CONTAINER)

    report = {
        "schema": "xaios.vmware-fusion.outbound.v1",
        "status": "pass" if not failures else "fail",
        "fusion_version": smoke.fusion_version(),
        "revision": smoke.git_revision(),
        "attachment": "bridged",
        "far_end": "disposable Debian 13 OpenSSH container on this host's LAN "
                   "address; no account or setting on the Mac is used",
        "checks": checks,
        "failures": failures,
        "not_claimed": not_claimed,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vmware-fusion-outbound-gate: FAIL {failure}")
        print(f"vmware-fusion-outbound-gate: report={REPORT}")
        return 1
    forward = checks.get("forward_payload", {})
    print(f"vmware-fusion-outbound-gate: guest {checks.get('guest_ipv4')} "
          f"opened SSH and SCP to {host_ip}:{port} with content verified both "
          f"ways, carried {forward.get('bytes_received')} bytes through a "
          f"direct-tcpip channel, and refused the wrong key, a corrupted "
          f"payload and a closed forward; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
