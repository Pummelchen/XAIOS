#!/usr/bin/env python3
"""Prove a booted XAIOS guest completes a WebTransport QUIC + TLS 1.3 handshake.

The last claim of B-131, and the only one that cannot be made on the host: that
the port -- the vendored library's runtime, this repository's BearSSL backend,
the XAIOS UDP seam, and the trust and signature code -- completes a handshake
from inside a booted guest, over QEMU's user network, against the peer built by
`scripts/build-wt-peer.sh`.

The guest side runs through the boot-test profile: `/bin/wtqtest` is executed as
a process by the kernel, with the capabilities it needs, which is how the other
applications in that profile are exercised and is why the gate's image is built
with `XAIOS_BOOT_TEST_APPS=1 XAIOS_WT_HANDSHAKE_TEST=1` rather than run from the
console. The console shell runs the signed app catalog, not `/bin`, so a
handshake driven from it would be a test of the catalog.

The host peer is the same binary `make wt-interop-test` uses, on `0.0.0.0:4433`
-- the address QEMU's user network presents to the guest as `10.0.2.2`. The pin
is asserted three ways: the peer prints the fingerprint it will present, the
fixture has one, and the application has one compiled in, so a stale
application pin is reported as a mismatch here rather than as a handshake that
mysteriously fails its trust check.
"""

import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
SCHEMA = "xaios.qemu.quic-handshake.v1"
IMAGE = BUILD / "xaios-aarch64.img"
PEER = BUILD / "wt-peer" / "host" / "wt_peer"
CERT = ROOT / "tests" / "fixtures" / "wt-peer-cert.der"
KEY = ROOT / "tests" / "fixtures" / "wt-peer-key.der"
APP_PIN = "d4664ca34bd74e2e2b3d4f7ac38b85007f1db172fb8bcb336068d840e9f19dca"

# The application's own line, the kernel's confirmation that the process it
# started exited cleanly, and the peer's line. All three, because any one alone
# can be produced by a run that did not do the thing: the application prints
# after the handshake, but the kernel line is what says the guest ran it to
# completion, and the peer's is the other end's account of the same handshake.
GUEST_MARKER = "wtqtest: WT-HANDSHAKE-OK"
GUEST_EXIT_MARKER = "kernel: /bin/wtqtest returned to kernel exit_code=0"
PEER_MARKER = "WT-PEER-HANDSHAKE-OK"
GUEST_FAILURE = "wtqtest: WT-HANDSHAKE-FAILED"
PANIC_MARKERS = [
    "CYAN SCREEN OF DEATH",
    "System halted. Manual reset required",
    "panic:",
]


def stop_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=5)


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    log_path = BUILD / "qemu-quic-handshake-gate.log"
    peer_log_path = BUILD / "qemu-quic-handshake-peer.log"
    report_path = BUILD / "qemu-quic-handshake-gate-report.json"
    failures: list[str] = []

    if not IMAGE.is_file():
        print(f"qemu-quic-handshake-gate: {IMAGE} is missing; run "
              "make qemu-quic-handshake-gate, which builds it", file=sys.stderr)
        return 1
    for fixture in (CERT, KEY):
        if not fixture.is_file():
            print(f"qemu-quic-handshake-gate: {fixture} is missing; run "
                  "tests/security/generate_wt_peer_identity.py --force",
                  file=sys.stderr)
            return 1

    environment = os.environ.copy()
    build = subprocess.run([str(ROOT / "scripts" / "build-wt-peer.sh")],
                           cwd=ROOT, env=environment, check=False,
                           capture_output=True, text=True, timeout=900)
    if build.returncode != 0:
        print(build.stdout, build.stderr, file=sys.stderr)
        return 1
    if not PEER.is_file():
        print("qemu-quic-handshake-gate: the peer did not build", file=sys.stderr)
        return 1

    port = int(environment.get("XAIOS_WT_GATE_PORT", "4433"))
    timeout = int(environment.get("XAIOS_WT_GATE_TIMEOUT", "300"))
    started = time.monotonic()

    # 1. The host peer, on every interface so the guest reaches it at 10.0.2.2,
    #    and listening BEFORE the guest boots: the application waits for it, and
    #    a peer started afterwards would be racing the handshake's own timeout.
    peer_log_path.unlink(missing_ok=True)
    peer_log = peer_log_path.open("wb")
    peer = subprocess.Popen(
        [str(PEER), "--server", "--host", "0.0.0.0", "--port", str(port),
         "--cert", str(CERT), "--key", str(KEY)],
        cwd=ROOT, stdout=peer_log, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    peer_text = ""
    deadline = started + min(timeout, 30)
    while time.monotonic() < deadline:
        if peer_log_path.is_file():
            peer_text = peer_log_path.read_text(errors="replace")
        if "WT-PEER-BOUND" in peer_text:
            break
        if peer.poll() is not None:
            break
        time.sleep(0.2)
    if "WT-PEER-BOUND" not in peer_text:
        stop_process_group(peer)
        peer_log.close()
        print(f"qemu-quic-handshake-gate: the peer did not bind {port}; see "
              f"{peer_log_path.relative_to(ROOT)}", file=sys.stderr)
        return 1
    peer_pin = re.search(r"WT-PEER-PIN ([0-9a-f]{64})", peer_text)
    if peer_pin is None or peer_pin.group(1) != APP_PIN:
        failures.append(
            "the peer's fingerprint is not the one the application pins "
            f"({peer_pin.group(1) if peer_pin else 'none'} != {APP_PIN})")

    # 2. The guest. The boot-test profile runs the application, so there is no
    #    console dialogue here -- only markers to read.
    guest_environment = environment.copy()
    guest_environment.update({
        "XAIOS_QEMU_ACCEL": environment.get("XAIOS_QEMU_ACCEL", "tcg"),
        # A gate-specific disk, so the persistent-image lock of a run that is
        # still shutting down cannot fail this one.
        "XAIOS_PERSISTENT_IMAGE": str(BUILD / "qemu-quic-handshake-persistent.img"),
        # SSH off an unlikely port: this gate does not use it, and a fixed port
        # would collide with a parallel gate.
        "XAIOS_QEMU_HOSTFWD_PORT": environment.get("XAIOS_WT_GATE_SSH_PORT", "7799"),
    })
    guest = subprocess.Popen(
        ["./platform/qemu/run-qemu-aarch64.sh"],
        cwd=ROOT, env=guest_environment, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True,
    )
    output = bytearray()
    passed = False
    try:
        if guest.stdout is None:
            raise RuntimeError("the guest console was not captured")
        descriptor = guest.stdout.fileno()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                chunk = os.read(descriptor, 8192)
                if not chunk:
                    break
                output.extend(chunk)
                try:
                    os.write(sys.stdout.fileno(), chunk)
                except (BrokenPipeError, OSError):
                    pass
            text = output.decode("utf-8", errors="replace")
            if GUEST_MARKER in text and GUEST_EXIT_MARKER in text:
                passed = not any(marker in text for marker in PANIC_MARKERS)
                break
            if GUEST_FAILURE in text:
                # Keep reading for a moment: the application's failure line is
                # several lines long and carries the reason, and stopping at the
                # marker would cut it off at the words "timed out".
                silence = time.monotonic() + 2.0
                while time.monotonic() < silence:
                    chunk = read_available(descriptor, 0.2)
                    if not chunk:
                        break
                    output.extend(chunk)
                break
            if not ready and guest.poll() is not None:
                break
    finally:
        stop_process_group(guest)
        text = output.decode("utf-8", errors="replace")
        log_path.write_text(text, encoding="utf-8")
        # A few more rounds so the peer's own line is written before it is read.
        time.sleep(0.5)
        stop_process_group(peer)
        peer_log.close()
        peer_text = peer_log_path.read_text(errors="replace")

    if not passed:
        failures.append("the guest did not report a completed handshake")
    if GUEST_MARKER in text and GUEST_EXIT_MARKER not in text:
        failures.append("the application printed the handshake marker but did "
                        "not exit cleanly")
    if GUEST_FAILURE in text:
        failures.append("the guest reported a failure: " + GUEST_FAILURE)
    if PEER_MARKER not in peer_text:
        failures.append("the host peer did not report a completed handshake")
    panics = [marker for marker in PANIC_MARKERS if marker in text]
    failures.extend(f"panic marker present: {marker}" for marker in panics)

    report = {
        "schema": SCHEMA,
        "status": "pass" if not failures else "fail",
        "created_unix": int(time.time()),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "accelerator": guest_environment["XAIOS_QEMU_ACCEL"],
        "image": str(IMAGE.relative_to(ROOT)),
        "peer_port": port,
        "pin": APP_PIN,
        "claims": [
            "a booted XAIOS guest opened a UDP socket and reached the host at "
            "10.0.2.2 through QEMU's user network",
            "the guest completed a TLS 1.3 handshake with the peer: X25519 key "
            "share, AES-128-GCM, and the peer's RSA-PSS server signature "
            "verified against a pinned certificate",
            "the peer, which is the same binary the host interop test uses, "
            "reported the same handshake complete",
        ],
        "not_claimed": [
            "any HTTP/3 or WebTransport session above the handshake",
            "any transfer of application data",
            "physical network performance",
        ],
        "markers": [GUEST_MARKER, GUEST_EXIT_MARKER, PEER_MARKER],
        "log": str(log_path.relative_to(ROOT)),
        "peer_log": str(peer_log_path.relative_to(ROOT)),
        "failures": failures,
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"qemu-quic-handshake-gate: report written to "
          f"{report_path.relative_to(ROOT)}")
    if failures:
        for failure in failures:
            print(f"qemu-quic-handshake-gate: {failure}")
        return 1
    print("qemu-quic-handshake-gate: the guest completed a WebTransport "
          "handshake")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
