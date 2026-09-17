#!/usr/bin/env python3
"""The guest side of the Fusion outbound gate: its PTY session and the checks.

`GuestShell` is the terminal the guest's own `ssh` and `scp` are driven
through, and this module also carries the two check groups that use it --
outbound sessions and files, and `direct-tcpip` forwarding through the guest.
Host-side plumbing, keys and shared paths come from
`vmware_fusion_outbound_host`, so nothing is defined twice.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import selectors
import subprocess
import time
from pathlib import Path

from vmware_fusion_outbound_host import (
    GUEST_IDENTITY,
    OUTBOUND_KEY,
    PROVISION,
    WORK,
    docker_exec,
    fnv1a64,
    reserve_port,
    run,
    smoke,
)

# The guest shell's prompt, and the two things its ssh/scp say. The prompt is
# wrapped in colour escapes, which is why the marker is the text between them
# rather than a whole line.
PROMPT = b"admin@xaios"
PASSPHRASE_PROMPT = b" key passphrase: "
TRANSFER_COMPLETE = b"scp: transfer complete"
PUBKEY_REFUSED = b"ssh: public-key authentication failed"


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
