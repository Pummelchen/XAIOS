#!/usr/bin/env python3
"""A second cluster node, on the host, so a sealed frame goes somewhere real.

The cluster framing seals a frame for a named receiver, and until now every
test of it handed the bytes from one function to another inside one process.
That proves the framing and nothing about a cluster, which is two nodes or it
is not a cluster.

This is the other node. It opens what the guest sends -- verifying the magic,
version, epoch, sender and HMAC-SHA256 tag -- and seals a genuine reply
addressed back to the guest, with its own nonce. Echoing the frame instead
would not work and should not: a frame sealed for node 2 is not a frame node 1
may open, and a peer that returned one would be asking the guest to accept a
message addressed elsewhere.

Written against the format rather than against the implementation. It is an
independent reading of the wire layout in engine/src/cluster.c, so agreement
between the two says the format is what that file documents, in the same way
mtools reading the FAT writer's output says more than the writer reading it
back.
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import sys

# From cluster.h and the header layout in cluster.c.
HEADER = 48
TAG = 32
MAX_PAYLOAD = 128
MAX_FRAME = HEADER + MAX_PAYLOAD + TAG
MAGIC = 0x5841434C
VERSION = 1

# The key the guest uses. A deployment derives one per direction; this is a
# test whose subject is the transport, and a key generated here would have to
# reach the guest somehow, which is the problem this is not solving.
KEY = bytes([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
    0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
])
PEER_NODE_ID = 2
GUEST_NODE_ID = 1


def tag_for(data: bytes) -> bytes:
    return hmac.new(KEY, data, hashlib.sha256).digest()


def open_frame(frame: bytes) -> dict | None:
    """Verify one frame and return what it says, or None if it does not hold."""
    if len(frame) < HEADER + TAG:
        return None
    magic, version, opcode = struct.unpack_from("<IHH", frame, 0)
    sender, receiver, epoch, nonce = struct.unpack_from("<QQQQ", frame, 8)
    payload_length = struct.unpack_from("<H", frame, 40)[0]
    if magic != MAGIC or version != VERSION:
        return None
    if payload_length > MAX_PAYLOAD or len(frame) != HEADER + payload_length + TAG:
        return None
    if receiver != PEER_NODE_ID or sender != GUEST_NODE_ID:
        return None
    body = frame[:HEADER + payload_length]
    if not hmac.compare_digest(tag_for(body), frame[HEADER + payload_length:]):
        return None
    return {"opcode": opcode, "epoch": epoch, "nonce": nonce,
            "payload": frame[HEADER:HEADER + payload_length]}


def seal_frame(opcode: int, epoch: int, nonce: int, payload: bytes) -> bytes:
    header = bytearray(HEADER)
    struct.pack_into("<IHH", header, 0, MAGIC, VERSION, opcode)
    struct.pack_into("<QQQQ", header, 8, PEER_NODE_ID, GUEST_NODE_ID, epoch,
                     nonce)
    struct.pack_into("<H", header, 40, len(payload))
    body = bytes(header) + payload
    return body + tag_for(body)


# Opcodes, from cluster.h.
JOIN = 1
JOIN_ACK = 2
LEAVE = 4


def read_frame(connection: socket.socket) -> bytes:
    """One frame off the stream, or empty if the far end stopped.

    A stream gives back what it has, not what was asked for, so this reads
    until a whole frame is in hand or the sender pauses. A frame smaller than
    the maximum is complete once the sender stops, so a short second read is
    how it says so rather than blocking for the full timeout every time.
    """
    connection.settimeout(60)
    frame = b""
    while len(frame) < MAX_FRAME:
        try:
            chunk = connection.recv(MAX_FRAME - len(frame))
        except socket.timeout:
            break
        if not chunk:
            break
        frame += chunk
        connection.settimeout(2)
    return frame


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7799
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(4)
    listener.settimeout(240)
    print(f"cluster-peer: listening on {port}", flush=True)

    # Three connections, not one.
    #
    # This used to accept once, answer, and exit, which was right when the
    # guest's whole exercise was a round trip. It has not been for some time:
    # the guest now announces that it is leaving and then rejoins, each on a
    # connection of its own, because a partition a node explains is a
    # different thing from a node that vanishes. Against a peer that had
    # already gone, the second connect could not complete -- so the guest
    # reported `could not reconnect to announce leaving` and the gate failed
    # on every architecture, in the one place nothing was looking: the
    # per-check output said the frame was sealed, crossed, was opened and
    # answered, and only the last line was missing.
    #
    # Serving the whole sequence is also what makes the membership half
    # testable at all. The guest's claim is that ownership returns to what it
    # was once the peer comes back, and there is no peer coming back if this
    # process exits after the first frame.
    exchanges: list[str] = []
    replies = 0
    nonce = 0
    try:
        while len(exchanges) < 3:
            try:
                connection, address = listener.accept()
            except socket.timeout:
                break
            with connection:
                frame = read_frame(connection)
                print(f"cluster-peer: {address[0]} sent {len(frame)} bytes",
                      flush=True)
                if not frame:
                    break
                opened = open_frame(frame)
                if opened is None:
                    print("cluster-peer: the frame did not verify", flush=True)
                    return 1
                print(f"cluster-peer: opened opcode={opened['opcode']} "
                      f"nonce={opened['nonce']} "
                      f"payload={len(opened['payload'])}", flush=True)
                exchanges.append(str(opened["opcode"]))

                if opened["opcode"] == LEAVE:
                    # Nothing goes back. A node that has said it is leaving is
                    # not waiting to be answered, and the guest closes this
                    # socket without reading.
                    print("cluster-peer: the guest announced it is leaving",
                          flush=True)
                    continue

                # The first JOIN is answered with the frame's own opcode and
                # payload, which is what the guest verifies came back
                # unchanged. The rejoin is answered with JOIN_ACK, which is
                # what brings the peer back online on the guest's side.
                rejoining = LEAVE in [int(op) for op in exchanges[:-1]]
                opcode = JOIN_ACK if rejoining else opened["opcode"]
                payload = b"" if rejoining else opened["payload"]
                # Strictly advancing, because that is what the guest's replay
                # check requires of every frame it opens from this node.
                nonce += 1
                reply = seal_frame(opcode, opened["epoch"], nonce, payload)
                connection.sendall(reply)
                replies += 1
                print(f"cluster-peer: sealed a reply of {len(reply)} bytes "
                      f"opcode={opcode} nonce={nonce}", flush=True)
    finally:
        listener.close()

    print(f"cluster-peer: served {len(exchanges)} exchanges "
          f"({'+'.join(exchanges) if exchanges else 'none'}) and sent "
          f"{replies} replies", flush=True)
    return 0 if exchanges else 1


if __name__ == "__main__":
    raise SystemExit(main())
