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


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7799
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(4)
    listener.settimeout(240)
    print(f"cluster-peer: listening on {port}", flush=True)
    try:
        connection, address = listener.accept()
    except socket.timeout:
        print("cluster-peer: no guest connected", flush=True)
        return 1
    with connection:
        connection.settimeout(60)
        frame = b""
        # Read until the peer stops sending or a whole frame is in hand. A
        # stream gives back what it has, not what was asked for.
        while len(frame) < MAX_FRAME:
            try:
                chunk = connection.recv(MAX_FRAME - len(frame))
            except socket.timeout:
                break
            if not chunk:
                break
            frame += chunk
            # A frame smaller than the maximum is complete once the sender
            # stops; give it one short read to say so rather than blocking for
            # the full timeout on every run.
            connection.settimeout(2)
        print(f"cluster-peer: {address[0]} sent {len(frame)} bytes", flush=True)
        if not frame:
            return 1
        opened = open_frame(frame)
        if opened is None:
            print("cluster-peer: the frame did not verify", flush=True)
            return 1
        print(f"cluster-peer: opened opcode={opened['opcode']} "
              f"nonce={opened['nonce']} payload={len(opened['payload'])}",
              flush=True)
        # A reply addressed back to the guest, with this node's own nonce.
        # The guest's receive nonce starts at zero and must advance, so any
        # value above it will do and one is the honest first.
        reply = seal_frame(opened["opcode"], opened["epoch"], 1,
                           opened["payload"])
        connection.sendall(reply)
        print(f"cluster-peer: sealed a reply of {len(reply)} bytes",
              flush=True)
    listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
