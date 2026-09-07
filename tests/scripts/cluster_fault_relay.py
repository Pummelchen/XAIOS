#!/usr/bin/env python3
"""A relay between cluster nodes that can be told to stop carrying traffic.

Why this exists
---------------

`qemu-cluster-three-node-gate` partitions a cluster by killing an emulator.
That is a real failure and it is the one a LEAVE cannot cover, but it is only
half of what a cluster has to survive, because a killed process stops
answering AND stops sending. The other half is a partition: both machines
alive, each still heartbeating, each hearing nothing from the other, and each
having to decide separately what it is entitled to do. That is the case where
a cluster can produce its worst outcome -- two sides that both believe they
have quorum -- and it cannot be reached by killing anything.

Under QEMU's user network the three guests reach each other by dialling the
gateway on a forwarded port, so the host is already in the path. This puts a
process there that can be told to stop forwarding, one ordered pair at a time.

Topology, and why the direction is a pair rather than a node
------------------------------------------------------------

In the mesh each node dials each other node and sends its own heartbeats on
the connection it opened; it never replies on a connection somebody else
opened. So the connection a->b carries exactly one thing: evidence that a is
alive, delivered to b. One relay listener per ordered pair therefore gives
per-direction control for free, and that is what makes an asymmetric
partition expressible: cut a->b alone and b stops hearing a while a goes on
hearing b. Both nodes are healthy, both are sending, and their views of the
cluster are no longer the same shape -- which is the failure that breaks
quorum logic written as if silence were mutual.

Each node is built with its own port table, so node a dials b on the listener
belonging to the pair (a,b) rather than on b's forwarded port directly. The
gate checks that in the guests' own dial lines, because a relay that is not
in the path is a fault injector that injects nothing and a gate that proves
nothing.

What a cut models, and what it does not
---------------------------------------

A cut here is a link that REJECTS: existing connections through it are reset
(SO_LINGER 0, so the peer sees an RST rather than an orderly close), and new
connections are accepted and immediately reset. That is a switch port going
down with ICMP, or a firewall REJECT rule.

It is not the other kind of partition -- a black hole, where packets are
dropped silently, connect() hangs until the kernel gives up, and a send sits
in a buffer that will never drain. That case is harsher on the sender: the
XAIOS connect path can block for up to ten seconds, which is half the mesh's
silence deadline, and a node stalled there is not heartbeating anyone. The
mesh reports its worst dial for exactly that reason and the gates check it,
but a black-holing relay would test it properly and this one does not. Said
plainly because the difference is invisible in a passing run: a REJECT gives
the sender an error it can act on, and a black hole gives it nothing.

Nor does it reorder, duplicate, corrupt or delay. A TCP relay cannot lose a
byte in the middle of a stream and leave the stream otherwise intact -- doing
that would desynchronise the reader's framing, which real packet loss never
does because TCP retransmits. Loss below the stream is not reachable from
here; it needs two machines and a switch.

Every cut and heal is timestamped and every link counts what it carried, so a
gate can assert that traffic actually stopped on the links it cut and
actually continued on the links it did not. A fault injector nobody measures
is indistinguishable from a fault injector that is broken.
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

# Enough to move a heartbeat (98 bytes) without splitting it needlessly, small
# enough that a cut takes effect within one read rather than after a buffer
# drains. Frames are never reassembled here: this forwards bytes, and the
# guests do their own framing, which is the point -- a relay that understood
# the protocol could hide a framing bug the network would expose.
CHUNK = 4096
# How long an idle pump waits before looking at the cut flag again. A cut also
# resets the connection outright, so this only bounds how long a connection
# that is doing nothing survives a cut it should have noticed.
POLL_S = 0.05


def _reset(sock: socket.socket) -> None:
    """Close with an RST rather than a FIN.

    A FIN is an orderly shutdown, which is what a peer that decided to go away
    sends. A partition is not that, and the difference is visible to the far
    end: an orderly close on a link that is supposed to be broken teaches the
    node under test that the link told it something, which a cut cable never
    does. RST is the closest a userspace relay gets to "this went nowhere".
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


@dataclass
class LinkStats:
    accepted: int = 0
    refused_while_cut: int = 0
    reset_by_cut: int = 0
    bytes_forwarded: int = 0
    events: list[tuple[float, str]] = field(default_factory=list)

    def snapshot(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "refused_while_cut": self.refused_while_cut,
            "reset_by_cut": self.reset_by_cut,
            "bytes_forwarded": self.bytes_forwarded,
            "events": [[round(when, 3), what] for when, what in self.events],
        }


class _Link:
    """One ordered pair: everything node `src` sends to node `dst`."""

    def __init__(self, src: int, dst: int, listen_port: int,
                 target_port: int, bind: str, target_host: str) -> None:
        self.src = src
        self.dst = dst
        self.listen_port = listen_port
        self.target_port = target_port
        self.bind = bind
        self.target_host = target_host
        self.cut = False
        self.stats = LinkStats()
        self.lock = threading.Lock()
        self.live: list[tuple[socket.socket, socket.socket]] = []
        self.listener: socket.socket | None = None
        self.threads: list[threading.Thread] = []
        self.stopping = threading.Event()

    @property
    def key(self) -> str:
        return f"{self.src}->{self.dst}"

    def open(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind, self.listen_port))
        listener.listen(16)
        listener.settimeout(0.2)
        self.listener = listener
        thread = threading.Thread(target=self._accept_loop, daemon=True,
                                  name=f"relay-accept-{self.key}")
        thread.start()
        self.threads.append(thread)

    def _accept_loop(self) -> None:
        assert self.listener is not None
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                cut = self.cut
                if cut:
                    self.stats.refused_while_cut += 1
                else:
                    self.stats.accepted += 1
            if cut:
                # Refusing by resetting rather than by never accepting. Not
                # accepting would leave the dialler's connect() succeeding
                # into the kernel's backlog and then hanging, which is the
                # black-hole case this relay does not claim to model -- and
                # which would silently turn "the link is down" into "the link
                # is slow". It is also the evidence that the far node is still
                # trying: a refused count that stays at zero during a cut
                # means the node on the other side stopped dialling, which is
                # a different failure from the one being tested.
                _reset(client)
                continue
            try:
                upstream = socket.create_connection(
                    (self.target_host, self.target_port), timeout=5.0)
            except OSError:
                _reset(client)
                continue
            client.settimeout(POLL_S)
            upstream.settimeout(POLL_S)
            with self.lock:
                self.live.append((client, upstream))
            thread = threading.Thread(target=self._pump, args=(client,
                                                               upstream),
                                      daemon=True,
                                      name=f"relay-pump-{self.key}")
            thread.start()
            self.threads.append(thread)

    def _pump(self, client: socket.socket, upstream: socket.socket) -> None:
        """Carry bytes in both directions until one end goes or the link is cut.

        Both directions on one connection, even though the mesh only ever
        sends one way on it: a relay that read in one direction only would
        quietly convert a peer that answered on the wrong socket into a peer
        that hung, and the gate would be measuring this file's assumption
        rather than the guests' behaviour.
        """
        pair = [(client, upstream), (upstream, client)]
        try:
            while not self.stopping.is_set():
                with self.lock:
                    if self.cut:
                        return
                for source, sink in pair:
                    try:
                        data = source.recv(CHUNK)
                    except socket.timeout:
                        # Nothing to carry this turn. The timeout is what
                        # makes this loop notice a cut without either end
                        # having sent anything.
                        continue
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        sink.sendall(data)
                    except OSError:
                        return
                    with self.lock:
                        self.stats.bytes_forwarded += len(data)
        finally:
            with self.lock:
                try:
                    self.live.remove((client, upstream))
                except ValueError:
                    pass
            _reset(client)
            _reset(upstream)

    def set_cut(self, cut: bool, when: float) -> None:
        with self.lock:
            if self.cut == cut:
                return
            self.cut = cut
            self.stats.events.append((when, "cut" if cut else "heal"))
            doomed = list(self.live) if cut else []
            if cut:
                self.stats.reset_by_cut += len(doomed)
                self.live = []
        for client, upstream in doomed:
            _reset(client)
            _reset(upstream)

    def close(self) -> None:
        self.stopping.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        with self.lock:
            doomed = list(self.live)
            self.live = []
        for client, upstream in doomed:
            _reset(client)
            _reset(upstream)


class FaultRelay:
    """A set of one-way links that can be cut and healed independently."""

    def __init__(self, bind: str = "127.0.0.1",
                 target_host: str = "127.0.0.1") -> None:
        self.bind = bind
        self.target_host = target_host
        self.links: dict[tuple[int, int], _Link] = {}
        self.started = time.monotonic()

    def add_link(self, src: int, dst: int, listen_port: int,
                 target_port: int) -> None:
        key = (src, dst)
        if key in self.links:
            raise ValueError(f"link {src}->{dst} already exists")
        self.links[key] = _Link(src, dst, listen_port, target_port, self.bind,
                                self.target_host)

    def start(self) -> None:
        for link in self.links.values():
            link.open()

    def stop(self) -> None:
        for link in self.links.values():
            link.close()

    def cut(self, src: int, dst: int) -> None:
        self.links[(src, dst)].set_cut(True, time.monotonic() - self.started)

    def heal(self, src: int, dst: int) -> None:
        self.links[(src, dst)].set_cut(False, time.monotonic() - self.started)

    def cut_both(self, a: int, b: int) -> None:
        """A symmetric partition between two nodes: neither hears the other."""
        self.cut(a, b)
        self.cut(b, a)

    def isolate(self, node: int) -> None:
        """Cut every link into and out of one node."""
        for src, dst in list(self.links):
            if node in (src, dst):
                self.cut(src, dst)

    def silence_outbound(self, node: int) -> None:
        """Cut only what this node sends.

        The asymmetric case: everyone stops hearing it, it goes on hearing
        everyone. It is still alive, still heartbeating, and its own view of
        the cluster is unchanged -- while every other node has already
        written it off.
        """
        for src, dst in list(self.links):
            if src == node:
                self.cut(src, dst)

    def heal_all(self) -> None:
        for src, dst in list(self.links):
            self.heal(src, dst)

    def cut_links(self) -> list[str]:
        return sorted(link.key for link in self.links.values() if link.cut)

    def snapshot(self) -> dict[str, object]:
        return {link.key: {"listen_port": link.listen_port,
                           "target_port": link.target_port,
                           "cut": link.cut,
                           **link.stats.snapshot()}
                for link in self.links.values()}

    def bytes_by_link(self) -> dict[str, int]:
        with_lock = {}
        for link in self.links.values():
            with link.lock:
                with_lock[link.key] = link.stats.bytes_forwarded
        return with_lock


# --------------------------------------------------------------- self test
#
# The relay's own negative control, and it needs no emulator: a sink, a
# client, and the three claims this file makes -- bytes flow, a cut stops
# them and resets what was open, and a heal lets a new connection through. If
# any of those is false then every partition gate built on top of it is
# theatre, and the gate itself cannot tell the difference between "the fault
# injector worked and the cluster behaved" and "nothing happened at all".


def _self_test(port_base: int) -> int:
    received = {"bytes": 0}
    stop = threading.Event()

    sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind(("127.0.0.1", port_base + 1))
    sink.listen(8)
    sink.settimeout(0.2)

    def sink_loop() -> None:
        while not stop.is_set():
            try:
                conn, _ = sink.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(0.2)
            while not stop.is_set():
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                received["bytes"] += len(data)
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=sink_loop, daemon=True).start()

    relay = FaultRelay()
    relay.add_link(1, 2, port_base, port_base + 1)
    relay.start()

    failures: list[str] = []
    try:
        client = socket.create_connection(("127.0.0.1", port_base),
                                          timeout=5.0)
        for _ in range(10):
            client.sendall(b"heartbeat")
            time.sleep(0.02)
        time.sleep(0.5)
        flowed = received["bytes"]
        if flowed == 0:
            failures.append("nothing crossed a healthy link")

        relay.cut(1, 2)
        time.sleep(0.3)
        # Counted before anything else is written, so that what follows is a
        # claim about bytes offered to a cut link rather than about a client
        # that happened to stop writing.
        at_cut = received["bytes"]
        # The open connection must be gone. sendall may take one more write
        # before the RST is noticed, which is TCP and not a relay bug, so the
        # claim is that it fails within a few writes rather than on the first.
        died = False
        for _ in range(20):
            try:
                client.sendall(b"heartbeat")
                time.sleep(0.05)
            except OSError:
                died = True
                break
        if not died:
            failures.append("a connection open across a cut link stayed open")
        time.sleep(0.5)
        if received["bytes"] != at_cut:
            failures.append(
                f"bytes kept arriving after the cut: {at_cut} -> "
                f"{received['bytes']}")

        # And a fresh dial across a cut link must not deliver anything either.
        try:
            refused = socket.create_connection(("127.0.0.1", port_base),
                                               timeout=5.0)
            refused.sendall(b"heartbeat")
            time.sleep(0.4)
            refused.close()
        except OSError:
            pass
        if received["bytes"] != at_cut:
            failures.append("a new connection crossed a cut link")

        relay.heal(1, 2)
        time.sleep(0.2)
        healed = socket.create_connection(("127.0.0.1", port_base),
                                          timeout=5.0)
        healed.sendall(b"heartbeat")
        time.sleep(0.6)
        if received["bytes"] <= at_cut:
            failures.append("nothing crossed the link after the heal")
        healed.close()

        stats = relay.snapshot()["1->2"]
        if stats["refused_while_cut"] < 1:
            failures.append(
                "the relay recorded no refused connection while cut, so a "
                "gate could not tell a partitioned node from a stopped one")
        if stats["reset_by_cut"] < 1:
            failures.append("the relay recorded no connection reset by the cut")
    finally:
        stop.set()
        relay.stop()
        try:
            sink.close()
        except OSError:
            pass

    for message in failures:
        print(f"cluster-fault-relay: FAIL {message}")
    if failures:
        return 1
    print("cluster-fault-relay: self-test passed: bytes crossed a healthy "
          "link, a cut reset what was open and refused what was new, no byte "
          "crossed while cut, and a heal carried traffic again")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--port-base", type=int, default=2951,
                        help="two consecutive free ports for the self test")
    arguments = parser.parse_args()
    if not arguments.self_test:
        parser.error("this module is a library; --self-test is the only "
                     "thing it does on its own")
    return _self_test(arguments.port_base)


if __name__ == "__main__":
    raise SystemExit(main())
