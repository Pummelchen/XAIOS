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
import shutil
import sys
import time

from qemu_gate_lib import write_report
from qemu_outbound_batch_mode_gate_lib import (
    BUILD, FAR_END_ADDRESS, FAR_END_USER, GUEST_IDENTITY, IDLE_LOWER_BOUND,
    IDLE_UPPER_BOUND, KEYS, PASSPHRASE, PASSPHRASE_PROMPT, PLUMBING_TIMEOUT,
    PROMPT, PROMPT_IDLE_SECONDS, SUFFIX, TARGET_ARCH, authorise_far_end,
    build_far_end_image, ensure_keys, far_end, require, reserve_port, run,
    start_far_end, stop_far_end, write_provisioning)
from qemu_outbound_batch_mode_guest_lib import (GuestShell, build_guest_image,
                                               guest_no_pty, start_guest,
                                               stop_guest)


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
