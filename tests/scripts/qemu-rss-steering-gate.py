#!/usr/bin/env python3
"""Receive-side scaling, measured rather than asserted.

The claim this gate exists to test is that a virtio-net device steers received
frames across the driver's receive queues by a hash of the flow. Every weaker
version of that claim passes without the feature working:

  * "four queue pairs exist" passes on a driver that never receives a frame on
    three of them, which is what the tranche before RSS already did;
  * "more than one queue received something" passes on a device that spreads
    by whatever rule it had before RSS was configured -- a multi-queue tap
    steers by its own hash on the host side, so frames arrive spread even with
    the feature off;
  * "some queue counts are non-zero" passes on a hash key whose low bits do
    not move, which is a real defect this gate found: an arithmetic-progression
    key put five hundred frames from sixty-four distinct flows onto exactly two
    of four queues, because one key byte came out zero and that byte was the
    window the low bits of a source port reach.

So the gate runs the same traffic twice against two builds that differ in one
thing: the size of the indirection table. With sixteen buckets the table names
all four pairs round robin; built with -DVIRTIO_NET_RSS_TABLE_ENTRIES=1 it has
one bucket naming queue zero, RSS is still negotiated, configured and accepted
by the device, and every frame must arrive on pair zero. The host side is
byte-for-byte identical between the two: same tap, same four host queues, same
flows, same frames. Anything that spreads traffic other than the device's own
indirection table would spread it in both, so the control failing is what makes
the first run's spread mean what it says.

The gate passes only when the steering run spreads and the control run does
not. A green control is a red gate: it says the measurement is not measuring.

This needs a multi-queue tap, which needs Linux and root. macOS has no tap
device at all -- SLIRP, vmnet and QEMU's other backends here are single-queue,
so a device on them advertises one pair and there is nothing to steer. On such
a host this gate fails with that message rather than skipping, because a skip
that prints green is the failure mode it was written to avoid.
"""
import argparse
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

# Line buffered, because the build and the emulator write to the same log
# through their own file descriptors: buffered output here would put this
# script's lines after theirs and make the order of events a fiction.
sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import BUILD, ROOT, write_report  # noqa: E402

REPORT = BUILD / "qemu-rss-steering-report.json"
GUEST_MAC = "52:54:00:12:34:57"
READY_MARKER = "SSH server: up and running (tcp/22)"
PAIRS_MARKER = "virtio-net-persist: queue pairs serviced="
RECEIVE_RE = re.compile(
    r"virtio-net-persist: receive serviced=(\d+) carrying=(\d+) rss=(\d+) "
    r"hash_types=0x([0-9a-f]+) frames=(\d+) "
    r"frames_by_pair=(\d+),(\d+),(\d+),(\d+)")
PAIRS_RE = re.compile(
    r"virtio-net-persist: queue pairs serviced=(\d+) offered=(\d+) rss=(\d+)")
RSS_RE = re.compile(
    r"virtio-net-persist: rss configured hash_types=0x([0-9a-f]+) "
    r"supported=0x([0-9a-f]+) table=(\d+) pairs=(\d+) key_bytes=(\d+)")
FORBIDDEN = ["x86_64: panic:", "Triple fault", "Cyan Screen of Death"]


class Unsupported(Exception):
    """The host cannot build the device this gate needs."""


# ---------------------------------------------------------------- host set-up


def require_multiqueue_host(tap: str, queues: int) -> bool:
    """Make sure a tap with `queues` queues exists. Returns True if we made it.

    Every failure here is a hard failure. A device with one queue pair cannot
    demonstrate steering and cannot fail to, so a run on such a host proves
    nothing in either direction and must not report a result.
    """
    if sys.platform != "linux":
        raise Unsupported(
            f"a multi-queue tap needs Linux; this host is {sys.platform}, "
            "where every QEMU network backend available is single-queue and a "
            "virtio-net device therefore advertises one queue pair")
    if not Path("/dev/net/tun").exists():
        raise Unsupported("/dev/net/tun is absent; no tap device can be made")
    if os.geteuid() != 0:
        raise Unsupported("creating and addressing a tap needs root")
    if shutil.which("ip") is None:
        raise Unsupported("iproute2's ip(8) is not on PATH")
    if Path(f"/sys/class/net/{tap}").exists():
        detail = subprocess.run(["ip", "-d", "link", "show", tap],
                                capture_output=True, text=True).stdout
        if "multi_queue" not in detail:
            raise Unsupported(
                f"{tap} exists but is not a multi_queue tap; delete it or "
                "pass --tap with another name")
        print(f"rss-steering: using the existing multi-queue tap {tap}")
        subprocess.run(["ip", "link", "set", tap, "up"], check=True)
        return False
    subprocess.run(["ip", "tuntap", "add", "dev", tap, "mode", "tap",
                    "multi_queue", "vnet_hdr"], check=True)
    subprocess.run(["ip", "addr", "add", "10.77.0.1/24", "dev", tap],
                   check=False)
    subprocess.run(["ip", "link", "set", tap, "up"], check=True)
    print(f"rss-steering: created multi-queue tap {tap} with {queues} queues")
    return True


# ------------------------------------------------------------------ the flows


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_frame(host_mac: bytes, src_port: int, payload: bytes) -> bytes:
    """One IPv4/UDP frame addressed to the guest's own MAC.

    Unicast to the guest rather than broadcast so the device's receive filter
    accepts it, and IPv4/UDP because those are the four-tuple hash types the
    driver asks for. The guest has no address on this subnet and drops the
    datagram, which does not matter: the count this gate reads is taken in the
    driver, on the queue the device chose, before anything looks at the frame.
    """
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, 9, udp_len, 0) + payload
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + udp_len, src_port, 0, 64,
                     17, 0)
    ip += socket.inet_aton("10.77.0.1") + socket.inet_aton("10.77.0.9")
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    guest = bytes.fromhex(GUEST_MAC.replace(":", ""))
    return guest + host_mac + b"\x08\x00" + ip + udp


def drive_flows(tap: str, flows: int, per_flow: int, gap: float,
                base_port: int) -> int:
    """Interleave `flows` distinct source ports, `per_flow` frames each.

    Interleaved rather than flow by flow so a slow guest emptying its rings
    cannot make an early flow's queue look busy and a late one's look idle: at
    every moment all the flows are equally far along.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((tap, 0))
        host_mac = sock.getsockname()[4]
        payload = b"xaios-rss-steering-probe" + b"\x00" * 8
        sent = 0
        for _ in range(per_flow):
            for flow in range(flows):
                sock.send(udp_frame(host_mac, base_port + flow, payload))
                sent += 1
                time.sleep(gap)
        return sent
    finally:
        sock.close()


# ------------------------------------------------------------------- one boot


def tail(text: str, lines: int = 40) -> str:
    """The last of the guest's own output, for a failure to be diagnosable.

    A gate that says only "the marker never appeared" sends the next person
    back to reproduce the run by hand to find out why.
    """
    return "\n  guest output, last %d lines:\n    %s" % (
        lines, "\n    ".join(text.splitlines()[-lines:]))


def build_image(table_entries: int) -> None:
    env = os.environ.copy()
    env["XAIOS_TARGET_ARCH"] = "x86_64"
    env["XAIOS_BOOT_TEST_APPS"] = "1"
    if table_entries != 16:
        env["XAIOS_KERNEL_CFLAGS_EXTRA"] = (
            f"-DVIRTIO_NET_RSS_TABLE_ENTRIES={table_entries}U")
    print(f"rss-steering: building x86_64 image with a {table_entries}-entry "
          "indirection table")
    subprocess.run(["./scripts/build-image.sh"], cwd=ROOT, env=env, check=True)


def run_arm(name: str, tap: str, queues: int, flows: int, per_flow: int,
            gap: float, base_port: int, boot_timeout: int,
            settle: float) -> Dict[str, object]:
    """Boot, wait for the link, drive the flows, read the counts back."""
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_X86_ACCEL", "tcg")
    env.setdefault("XAIOS_QEMU_X86_CPU", "max")
    env["XAIOS_QEMU_X86_TAP"] = tap
    env["XAIOS_QEMU_X86_TAP_QUEUES"] = str(queues)
    persistent = BUILD / f"xaios-x86-rss-{name}-persistent.img"
    persistent.unlink(missing_ok=True)
    env["XAIOS_X86_PERSISTENT_IMAGE"] = str(persistent)

    proc = subprocess.Popen(["./platform/qemu/run-qemu-x86_64.sh"], cwd=ROOT,
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=False, bufsize=0,
                            start_new_session=True)
    chunks: List[str] = []

    def pump(seconds: float) -> str:
        deadline = time.time() + seconds
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                data = os.read(fd, 65536)
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="replace"))
            elif proc.poll() is not None:
                break
        return "".join(chunks)

    try:
        deadline = time.time() + boot_timeout
        text = ""
        while time.time() < deadline:
            text = pump(1.0)
            if any(bad in text for bad in FORBIDDEN):
                raise RuntimeError(
                    f"{name}: guest failed to boot{tail(text)}")
            if READY_MARKER in text and PAIRS_MARKER in text:
                break
        else:
            raise RuntimeError(
                f"{name}: guest did not reach '{READY_MARKER}' and "
                f"'{PAIRS_MARKER}' within {boot_timeout}s{tail(text)}")

        pairs = PAIRS_RE.search(text)
        rss = RSS_RE.search(text)
        if pairs is None or rss is None:
            raise RuntimeError(
                f"{name}: the driver printed no RSS summary{tail(text)}")
        serviced, offered, rss_on = (int(pairs.group(1)), int(pairs.group(2)),
                                     int(pairs.group(3)))
        # Everything below reads counts printed after this point, so that a
        # line describing the boot's own traffic cannot be mistaken for one
        # describing the flows this gate sends.
        mark = len(text)
        print(f"rss-steering[{name}]: serviced={serviced} offered={offered} "
              f"rss={rss_on} hash_types=0x{rss.group(1)} "
              f"supported=0x{rss.group(2)} table={rss.group(3)} "
              f"key_bytes={rss.group(5)}")
        sent = drive_flows(tap, flows, per_flow, gap, base_port)
        print(f"rss-steering[{name}]: sent {sent} frames over {flows} flows")
        text = pump(settle)
        after = text[mark:]
        lines = RECEIVE_RE.findall(after)
        if not lines:
            raise RuntimeError(
                f"{name}: the driver reported no receive distribution after "
                f"{sent} frames were sent; nothing arrived at all"
                f"{tail(after)}")
        last = lines[-1]
        counts = [int(last[5]), int(last[6]), int(last[7]), int(last[8])]
        return {
            "arm": name,
            "serviced_pairs": serviced,
            "offered_pairs": offered,
            "rss": rss_on,
            "hash_types": f"0x{rss.group(1)}",
            "supported_hash_types": f"0x{rss.group(2)}",
            "table_entries": int(rss.group(3)),
            "key_bytes": int(rss.group(5)),
            "frames_sent": sent,
            "frames_counted": int(last[4]),
            "frames_by_pair": counts,
            "pairs_carrying": sum(1 for c in counts if c > 0),
        }
    finally:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), 15)
                proc.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(proc.pid), 9)
                except ProcessLookupError:
                    pass
        persistent.unlink(missing_ok=True)


# -------------------------------------------------------------- the judgement


def steering_failures(arm: Dict[str, object], share_cap: float) -> List[str]:
    """The assertion. Applied unchanged to both arms; the control must fail it.

    Every serviced pair has to have carried a frame, not merely more than one
    of them. "More than one" was true of the broken hash key that put
    sixty-four flows on two of four queues, so it is not a test of steering --
    it is a test of whether anything at all moved.
    """
    failures: List[str] = []
    counts: List[int] = arm["frames_by_pair"]  # type: ignore[assignment]
    serviced: int = arm["serviced_pairs"]  # type: ignore[assignment]
    total = sum(counts)
    if arm["rss"] != 1:
        failures.append("the device did not accept RSS")
    if serviced < 2:
        failures.append(f"only {serviced} queue pair(s) in service")
    if total == 0:
        failures.append("no frames arrived on any pair")
        return failures
    idle = [i for i in range(serviced) if counts[i] == 0]
    if idle:
        failures.append(
            f"pairs {idle} carried nothing of {total} frames "
            f"(by pair: {counts})")
    busiest = max(counts)
    if busiest > share_cap * total:
        failures.append(
            f"pair {counts.index(busiest)} carried {busiest} of {total} "
            f"frames, over the {share_cap:.0%} share a hash should never "
            f"concentrate (by pair: {counts})")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tap", default="xaiosmq0")
    parser.add_argument("--queues", type=int, default=4)
    parser.add_argument("--flows", type=int, default=64)
    parser.add_argument("--frames-per-flow", type=int, default=6)
    parser.add_argument("--gap", type=float, default=0.006)
    parser.add_argument("--base-port", type=int, default=20000)
    parser.add_argument("--boot-timeout", type=int, default=420)
    parser.add_argument("--settle", type=float, default=20.0)
    parser.add_argument("--share-cap", type=float, default=0.75)
    parser.add_argument("--skip-build", action="store_true",
                        help="reuse whatever build/ already holds; only sound "
                             "when the two arms are being driven by hand")
    args = parser.parse_args()

    created = False
    report: Dict[str, object] = {"gate": "qemu-rss-steering"}
    try:
        created = require_multiqueue_host(args.tap, args.queues)
    except Unsupported as exc:
        print(f"rss-steering: FAIL: {exc}")
        report["status"] = "fail"
        report["reason"] = str(exc)
        write_report(REPORT, report)
        return 1

    try:
        arms: Dict[str, Dict[str, object]] = {}
        for name, table_entries in (("steering", 16), ("control", 1)):
            if not args.skip_build:
                build_image(table_entries)
            arms[name] = run_arm(name, args.tap, args.queues, args.flows,
                                 args.frames_per_flow, args.gap,
                                 args.base_port, args.boot_timeout,
                                 args.settle)
            print(f"rss-steering[{name}]: frames_by_pair="
                  f"{arms[name]['frames_by_pair']} "
                  f"counted={arms[name]['frames_counted']}")

        steering = steering_failures(arms["steering"], args.share_cap)
        control = steering_failures(arms["control"], args.share_cap)
        failures: List[str] = []
        for reason in steering:
            failures.append(f"steering run: {reason}")
        if not control:
            failures.append(
                "control run: the same assertion passed against a one-entry "
                "indirection table naming only queue zero, so it is not the "
                "device's steering that this gate measures")
        control_counts = arms["control"]["frames_by_pair"]
        if arms["control"]["pairs_carrying"] != 1:
            failures.append(
                f"control run: {arms['control']['pairs_carrying']} pairs "
                f"carried frames ({control_counts}); with one bucket naming "
                "queue zero every frame must arrive on pair zero")

        report["arms"] = arms
        report["control_failed_as_required"] = bool(control)
        report["control_reasons"] = control
        report["failures"] = failures
        report["status"] = "pass" if not failures else "fail"
        write_report(REPORT, report)

        print("")
        for name, arm in arms.items():
            print(f"rss-steering: {name:9s} rss={arm['rss']} "
                  f"table={arm['table_entries']} "
                  f"serviced={arm['serviced_pairs']} "
                  f"frames_by_pair={arm['frames_by_pair']} "
                  f"carrying={arm['pairs_carrying']}")
        print(f"rss-steering: control failed the steering assertion for: "
              f"{control or 'nothing -- it passed, which is the bug'}")
        if failures:
            print("rss-steering: FAIL")
            for reason in failures:
                print(f"  - {reason}")
            return 1
        print("rss-steering: PASS: distinct flows land on different receive "
              "queues, and collapse onto one when the indirection table says "
              "so")
        return 0
    finally:
        if created:
            subprocess.run(["ip", "link", "del", args.tap], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
