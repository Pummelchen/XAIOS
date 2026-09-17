#!/usr/bin/env python3
"""B-40: one peer that barely reads, and a server that serves nobody else.

sshd is a single thread. Its loop accepts new connections, services every open
one, and runs the channel tick; a write that cannot complete is waited on
*inside* that loop, so the wait is not one session's, it is every session's and
the listener's with them.

The transmit path has had a bound on that wait for as long as it has existed,
and the bound asked the wrong question. It measured the gap since the last byte
the peer took and reset on any byte at all, so:

  * a peer that takes a trickle -- a few hundred bytes in each ten seconds --
    renewed the bound forever and held the loop for as long as it liked; and
  * a peer that took nothing was noticed after ten seconds, and then the
    transmit was abandoned *and nothing else happened*. The channel stayed
    open, the connection stayed open, the next tick tried the same write, and
    the server was held for another ten seconds. The peer kept its session and
    kept the machine.

The bound now asks what it should: in each ten-second window the peer must have
taken at least SSHD_TRANSMIT_WINDOW_MIN_BYTES (10 KiB, a kibibyte a second). A
window the peer clears starts another, so a genuinely slow session runs for as
long as it keeps taking its data; a peer below the floor loses its connection,
once, with the reason on the console.

The harness is a relay that carries one authenticated session at full speed and
then starts taking its slice: 4 KiB every six seconds, 683 bytes a second,
comfortably under the floor and comfortably over nothing. What the session is
carrying is a direct-tcpip forward from a host service that writes as fast as
the guest will take it -- the guest's mutable volume caps a file at 256 KiB,
which is less than the host's own socket buffers absorb, so a file download
would never fill the pipe and never make the server wait at all.

The claim being tested is about the *other* sessions, so that is what is
measured: an ordinary SFTP session is opened over and over for ninety seconds
and timed. A gate that watched only the slow session would prove nothing --
the slow session is slow either way.

What separates the two outcomes:

  * unfixed, the server is held in ten-second blocks, over and over, and the
    trickling session is still there at the end of them. Probes taken during
    those blocks wait seconds each, and the console says "transmit queue
    stalled" repeatedly with nothing closed.
  * fixed, the server is held for one window at most, the trickling connection
    is closed with the reason named on the console, and every probe after that
    is a normal sub-second session.

Two controls, because both of the obvious ways to fake this pass otherwise:

  * a peer that keeps up must NOT be closed. The same forward is run first at
    full speed and has to move megabytes without the bound firing. A "fix"
    that closed every session whose socket ever filled would sail through the
    trickle case and break every real transfer.
  * the trickle has to have been a trickle. The relay's own measured rate is
    asserted to be below the floor, and the amount the host service pushed is
    asserted to be far more than the peer took, so the guest really did have
    data it was trying to hand over.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time

from qemu_sshd_transmit_rate_gate_lib import (ARCH, BUILD, CLOSE_BUDGET,
                                             CONTROL_MIN_BYTES,
                                             CONTROL_SECONDS, DRAIN_BUDGET,
                                             FLOOR_BYTES_PER_SECOND,
                                             FLOOR_MARKER, MAX_SLOW_PROBES,
                                             OBSERVE_SECONDS, OLD_STALL_MARKER,
                                             READY_MARKER, ROOT,
                                             SLOW_PROBE_SECONDS, SUFFIX,
                                             TRICKLE_RCVBUF, TRIGGER_BYTES,
                                             Blaster, TrickleRelay, build,
                                             connect_forward, drain,
                                             open_tunnel,
                                             qemu_boot_environment,
                                             qemu_runner, reserve_port,
                                             run_sftp, smoke_timeout,
                                             stop_process, wait_for_marker,
                                             wait_for_ssh)


def main() -> int:
    gate_dir = BUILD / f"sshd-transmit-rate{SUFFIX}"
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-sshd-transmit-rate-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)

    build(key)

    port = reserve_port()
    log_path = BUILD / f"qemu-sshd-transmit-rate{SUFFIX}.log"
    log_path.unlink(missing_ok=True)
    env = qemu_boot_environment(
        ARCH, os.environ.copy(), accel="tcg", smp=4, hostfwd_port=port,
        persistent=gate_dir / "persistent.img",
        state_dir=gate_dir / "state",
        serial_to_stdout=True)
    handle = log_path.open("wb")
    qemu = subprocess.Popen([str(ROOT / qemu_runner(ARCH))], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=handle,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)

    blaster = Blaster()
    stop_drains = threading.Event()
    relay: TrickleRelay | None = None
    tunnels: list[subprocess.Popen[str]] = []
    sinks: list[socket.socket] = []
    failures: list[str] = []
    checks: dict[str, object] = {}
    probe_timeout = float(smoke_timeout(ARCH, 120))
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 240)), qemu)
        wait_for_ssh(port, qemu, float(smoke_timeout(ARCH, 180)))

        # --- Control: a peer that keeps up is left alone --------------------
        control_mark = len(log_path.read_bytes())
        control_local = reserve_port()
        tunnels.append(open_tunnel(key, port, control_local, blaster.port))
        time.sleep(5.0)
        control_sink = connect_forward(control_local)
        sinks.append(control_sink)
        control_bytes = [0]
        threading.Thread(target=drain,
                         args=(control_sink, control_bytes, stop_drains),
                         daemon=True).start()
        time.sleep(CONTROL_SECONDS)
        control_console = log_path.read_bytes()[control_mark:].decode(
            "utf-8", "replace")
        checks["control_bytes"] = control_bytes[0]
        checks["control_floor_lines"] = control_console.count(FLOOR_MARKER)
        if control_bytes[0] < CONTROL_MIN_BYTES:
            failures.append(
                f"a forward drained as fast as the host could take it carried "
                f"only {control_bytes[0]} bytes in {CONTROL_SECONDS:.0f}s, "
                f"under the {CONTROL_MIN_BYTES} this gate needs before it can "
                f"claim anything about a slow one")
        if control_console.count(FLOOR_MARKER) != 0:
            failures.append(
                "the server closed a transmit for being below the minimum "
                "rate while the peer was taking everything it could. The "
                "bound is firing on peers that keep up, which would break "
                "every real transfer on the machine")

        # The control session goes before the slow one starts: what is being
        # measured below is a server with one trickling peer attached, not a
        # server also carrying a transfer at full speed.
        stop_process(tunnels.pop())
        control_sink.close()
        sinks.remove(control_sink)
        time.sleep(2.0)

        # --- The trickling peer ---------------------------------------------
        mark = len(log_path.read_bytes())
        blasted_before = blaster.sent
        relay = TrickleRelay(port)
        slow_local = reserve_port()
        # This session goes through the relay, so the client connects to the
        # relay's port rather than to the guest's.
        tunnels.append(open_tunnel(key, relay.port, slow_local, blaster.port))
        time.sleep(8.0)
        slow_sink = connect_forward(slow_local)
        sinks.append(slow_sink)
        slow_bytes = [0]
        threading.Thread(target=drain,
                         args=(slow_sink, slow_bytes, stop_drains),
                         daemon=True).start()

        # Wait for the relay to start taking slices, so the observation below
        # is of a server with a trickling peer attached rather than of a
        # server with a fast one.
        deadline = time.monotonic() + 60.0
        while relay.trickling_since is None and time.monotonic() < deadline:
            time.sleep(0.5)
        if relay.trickling_since is None:
            failures.append(
                f"the relay never reached the {TRIGGER_BYTES} bytes at which "
                f"it starts trickling, so no peer was ever slow and nothing "
                f"below this is a test of B-40")

        started = time.monotonic()
        probes: list[tuple[float, int | None, float]] = []
        while time.monotonic() - started < OBSERVE_SECONDS:
            at = time.monotonic() - started
            code, message, seconds = run_sftp(key, port, "ls /state\n",
                                              probe_timeout)
            probes.append((round(at, 1), code, round(seconds, 1)))
            if code != 0:
                failures.append(
                    f"an ordinary SFTP session {at:.0f}s into the trickle did "
                    f"not complete: rc={code} {message!r}")
                break

        # Stop trickling and take the rest as fast as it comes: until the
        # backlog between the two is drained there is no way to see whether
        # the guest has closed its end.
        drain_started = time.monotonic()
        relay.stop_trickle.set()
        while (relay.stream_ended_at is None and
               time.monotonic() - drain_started < DRAIN_BUDGET):
            time.sleep(0.5)

        slow = [probe for probe in probes if probe[2] > SLOW_PROBE_SECONDS]
        console = log_path.read_bytes()[mark:].decode("utf-8", "replace")
        checks["probes"] = len(probes)
        checks["slow_probes"] = slow
        checks["worst_probe_seconds"] = max((p[2] for p in probes),
                                            default=None)
        checks["trickle_slices"] = relay.slices
        checks["trickled_bytes"] = relay.trickled
        checks["trickle_rate_bytes_per_second"] = round(relay.rate(), 1)
        checks["blaster_bytes"] = blaster.sent - blasted_before
        checks["floor_lines"] = console.count(FLOOR_MARKER)
        checks["old_stall_lines"] = console.count(OLD_STALL_MARKER)
        checks["stream_ended_after_s"] = (
            round(relay.stream_ended_at - relay.trickling_since, 1)
            if relay.stream_ended_at is not None
            and relay.trickling_since is not None else None)
        checks["guest_sent_eof"] = relay.guest_eof_at is not None
        checks["bytes_from_guest"] = relay.from_guest
        checks["floor_marker_once"] = console.count(FLOOR_MARKER) == 1

        # The trickle has to have been one: slices actually taken, at a rate
        # under the floor, while the guest had far more than that to give.
        if relay.slices < 3:
            failures.append(
                f"the relay took only {relay.slices} slices, too few to say "
                f"the peer was reading at all -- a peer that takes nothing is "
                f"the case the old bound already caught")
        if relay.rate() >= FLOOR_BYTES_PER_SECOND:
            failures.append(
                f"the peer took {relay.rate():.0f} bytes a second, at or "
                f"above the {FLOOR_BYTES_PER_SECOND:.0f} the server requires. "
                f"A peer above the floor is meant to be served, so this run "
                f"tests nothing")
        blasted = blaster.sent - blasted_before
        if blasted < 4 * relay.trickled:
            failures.append(
                f"the host service pushed {blasted} bytes against the "
                f"{relay.trickled} the peer took, not enough of a backlog to "
                f"be sure the guest had anything queued to hand over")

        if console.count(FLOOR_MARKER) == 0:
            # Before blaming the guest, check the gate created the condition.
            #
            # The peer's read rate is not what the guest experiences: the host
            # kernel buffers on the peer's behalf, so the guest can be writing
            # briskly into a socket whose reader is crawling. A run here took
            # 641 B/s at the socket while the guest had already written 725,203
            # bytes and no session waited longer than 0.6s -- the guest was
            # never shown a slow peer, correctly closed nothing, and the gate
            # called that the defect. TRICKLE_RCVBUF is set to stop it, and
            # this is the assertion that the setting worked.
            #
            # Still a failure, and still non-zero: an inconclusive run that
            # exits 0 is a gate that cannot fail. It names the host instead of
            # accusing the guest.
            absorbed = relay.from_guest - relay.trickled
            if (relay.from_guest > 4 * relay.trickled
                    and checks["worst_probe_seconds"] < SLOW_PROBE_SECONDS):
                failures.append(
                    f"INCONCLUSIVE, not a guest defect: the host absorbed "
                    f"{absorbed} bytes on the peer's behalf -- the guest wrote "
                    f"{relay.from_guest} while the peer took {relay.trickled} "
                    f"-- and no session waited more than "
                    f"{checks['worst_probe_seconds']}s, "
                    f"so the guest was never shown a slow peer and had nothing "
                    f"to close. The receive buffer is capped at "
                    f"{TRICKLE_RCVBUF} bytes and this host gave "
                    f"{getattr(relay, 'effective_rcvbuf', 'unknown')}. Lower "
                    f"it, or pin the floor with a hosted test driving "
                    f"send_all_within directly")
            else:
                failures.append(
                    f"the guest never closed the trickling transmit. The "
                    f"console has {console.count(OLD_STALL_MARKER)} stall "
                    f"lines and no {FLOOR_MARKER!r}: the peer took a slice "
                    f"inside every window and kept both its session and the "
                    f"server's attention, which is B-40")
        if relay.stream_ended_at is None:
            failures.append(
                f"the trickling session was still being served at the end: "
                f"with the trickle lifted, bytes kept arriving for the whole "
                f"{DRAIN_BUDGET:.0f}s drain. The server has to end a "
                f"transmit it is not getting anywhere with, not merely "
                f"abandon the packet and try the same write on the next "
                f"tick")

        if len(slow) > MAX_SLOW_PROBES:
            failures.append(
                f"{len(slow)} of {len(probes)} ordinary SFTP sessions took "
                f"longer than {SLOW_PROBE_SECONDS:.0f}s while the trickling "
                f"peer was attached: {slow[:6]}. The server is being held by "
                f"one peer, over and over, which is the whole of B-40. One "
                f"such session is allowed, and is the window the server "
                f"spends deciding")
        late = [probe for probe in slow if probe[0] > CLOSE_BUDGET]
        if late:
            failures.append(
                f"a session was still made to wait {late[0][2]:.0f}s at "
                f"{late[0][0]:.0f}s into the trickle, long after the server "
                f"should have given up on that peer. One window is the "
                f"budget; this is the loop still being held")
    finally:
        stop_drains.set()
        blaster.stop.set()
        for sink in sinks:
            try:
                sink.close()
            except OSError:
                pass
        for tunnel in tunnels:
            stop_process(tunnel)
        if relay is not None:
            relay.stop.set()
        stop_process(qemu)
        handle.close()

    report = {
        "schema": "xaios.sshd.transmit-rate.v1",
        "status": "pass" if not failures else "fail",
        "architecture": ARCH,
        "checks": checks,
        "failures": failures,
        "guest_log": str(log_path),
    }
    report_path = BUILD / f"qemu-sshd-transmit-rate{SUFFIX}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-sshd-transmit-rate-gate: FAIL {failure}")
        print(f"qemu-sshd-transmit-rate-gate: report={report_path}")
        return 1
    print(f"qemu-sshd-transmit-rate-gate: a peer taking "
          f"{checks['trickle_rate_bytes_per_second']} bytes a second stopped "
          f"being served after {checks['stream_ended_after_s']}s while "
          f"{checks['probes']} ordinary sessions ran, the worst of them "
          f"{checks['worst_probe_seconds']}s; a peer that kept up moved "
          f"{checks['control_bytes']} bytes untouched; report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
