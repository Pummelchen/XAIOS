#!/usr/bin/env python3
"""Exercise XAIOS IPv6/TCP over QEMU's framed socket network backend."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import time


CLIENT_MAC = bytes.fromhex("525400aabbcc")
GUEST_MAC = bytes.fromhex("525400123457")
CLIENT_IP = ipaddress.IPv6Address("fd00::2").packed
GUEST_IP = ipaddress.IPv6Address("fd00::15").packed
CLIENT_PORT = 42022
GUEST_PORT = 22


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_segment(seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        CLIENT_PORT,
        GUEST_PORT,
        seq,
        ack,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    pseudo = CLIENT_IP + GUEST_IP + struct.pack("!I3xB", len(header) + len(payload), 6)
    value = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", value) + header[18:] + payload


def ethernet_frame(seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = tcp_segment(seq, ack, flags, payload)
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), 6, 64, CLIENT_IP, GUEST_IP)
    return GUEST_MAC + CLIENT_MAC + struct.pack("!H", 0x86DD) + ipv6 + tcp


def send_frame(sock: socket.socket, frame: bytes) -> None:
    sock.sendall(struct.pack("!I", len(frame)) + frame)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("QEMU socket network closed")
        result.extend(chunk)
    return bytes(result)


def recv_frame(sock: socket.socket) -> bytes:
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size < 14 or size > 65536:
        raise RuntimeError(f"invalid QEMU Ethernet frame size {size}")
    return recv_exact(sock, size)


def parse_guest_tcp(frame: bytes) -> tuple[int, int, int, bytes] | None:
    if len(frame) < 74 or frame[12:14] != b"\x86\xdd" or frame[20] != 6:
        return None
    if frame[22:38] != GUEST_IP or frame[38:54] != CLIENT_IP:
        return None
    payload_length = struct.unpack("!H", frame[18:20])[0]
    tcp = frame[54 : 54 + payload_length]
    if len(tcp) < 20:
        return None
    source_port, destination_port, seq, ack = struct.unpack("!HHII", tcp[:12])
    if source_port != GUEST_PORT or destination_port != CLIENT_PORT:
        return None
    pseudo = GUEST_IP + CLIENT_IP + struct.pack("!I3xB", len(tcp), 6)
    if checksum(pseudo + tcp) != 0:
        raise RuntimeError("guest TCP checksum mismatch")
    header_length = (tcp[12] >> 4) * 4
    if header_length < 20 or header_length > len(tcp):
        raise RuntimeError("guest TCP header length is invalid")
    return seq, ack, tcp[13], tcp[header_length:]


def wait_for_tcp(sock: socket.socket, predicate, timeout: float, verbose: bool):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            frame = recv_frame(sock)
        except socket.timeout:
            continue
        if verbose:
            print(f"received Ethernet frame bytes={len(frame)} hex={frame[:96].hex()}")
        parsed = parse_guest_tcp(frame)
        if parsed is not None and predicate(parsed):
            return parsed
    raise TimeoutError("timed out waiting for guest IPv6/TCP response")


def connect_with_retry(host: str, port: int, timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    while True:
        try:
            sock = socket.create_connection((host, port), timeout=1.0)
            sock.settimeout(2.0)
            return sock
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    client_seq = 0x10203040
    with connect_with_retry(args.host, args.port, args.timeout) as sock:
        send_frame(sock, ethernet_frame(client_seq, 0, 0x02))
        server_seq, ack, flags, _ = wait_for_tcp(
            sock, lambda packet: packet[2] & 0x12 == 0x12, args.timeout,
            args.verbose,
        )
        if ack != client_seq + 1:
            raise RuntimeError("guest SYN-ACK acknowledged the wrong sequence")

        client_seq += 1
        server_next = server_seq + 1
        send_frame(sock, ethernet_frame(client_seq, server_next, 0x10))
        client_banner = b"SSH-2.0-XAIOS_IPv6_Client_Test\r\n"
        send_frame(sock, ethernet_frame(client_seq, server_next, 0x18, client_banner))
        client_seq += len(client_banner)

        server_seq, _, _, payload = wait_for_tcp(
            sock, lambda packet: packet[3].startswith(b"SSH-2.0-XAIOS_"),
            args.timeout, args.verbose,
        )
        retransmit_started = time.monotonic()
        retry_seq, _, _, retry_payload = wait_for_tcp(
            sock,
            lambda packet: packet[0] == server_seq and packet[3] == payload,
            args.timeout,
            args.verbose,
        )
        retransmit_seconds = time.monotonic() - retransmit_started
        if retry_seq != server_seq or retry_payload != payload:
            raise RuntimeError("guest retransmission did not preserve sequence and payload")
        send_frame(
            sock,
            ethernet_frame(client_seq, server_seq + len(payload), 0x10),
        )
        print(
            "IPv6 TCP transfer passed: "
            f"sent={len(client_banner)} received={len(payload)} "
            f"retransmit_seconds={retransmit_seconds:.3f} "
            f"guest_banner={payload.decode().strip()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
