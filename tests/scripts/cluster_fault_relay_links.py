"""The fault-injecting relay's links: one listener per ordered node pair.

Moved verbatim out of `cluster_fault_relay.py` so that neither file has to
carry the whole thing. This half is everything that owns a socket or a
thread: the RST close, the per-link counters, one listener per ordered pair,
and the set of links that can be cut and healed independently. The design
notes for why a link is one direction of one pair stay in the parent, whose
module docstring is its CLI description and therefore had to stay there too.

`cluster_fault_relay.py` imports these names and re-exports them, so a gate
that did `from cluster_fault_relay import FaultRelay` before the split still
gets the same class from the same path. The self test and the command line
are the only things the parent still does on its own.
"""

from __future__ import annotations

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
