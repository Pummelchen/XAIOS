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
CLIENT_IP_V4 = ipaddress.IPv4Address("10.0.2.100").packed
GUEST_IP_V4 = ipaddress.IPv4Address("10.0.2.15").packed
CLIENT_PORT = 42022
GUEST_PORT = 22


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_segment(
    seq: int, ack: int, flags: int, payload: bytes = b"", valid_checksum: bool = True
) -> bytes:
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
    value = checksum(pseudo + header + payload) if valid_checksum else 0
    return header[:16] + struct.pack("!H", value) + header[18:] + payload


def ethernet_frame(
    seq: int, ack: int, flags: int, payload: bytes = b"", valid_checksum: bool = True
) -> bytes:
    tcp = tcp_segment(seq, ack, flags, payload, valid_checksum)
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), 6, 64, CLIENT_IP, GUEST_IP)
    return GUEST_MAC + CLIENT_MAC + struct.pack("!H", 0x86DD) + ipv6 + tcp


def ipv4_tcp_frame(*, valid_ip_checksum: bool, fragment: bool = False) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        CLIENT_PORT,
        GUEST_PORT,
        0x55667788,
        0,
        5 << 4,
        0x02,
        65535,
        0,
        0,
    )
    pseudo = CLIENT_IP_V4 + GUEST_IP_V4 + struct.pack("!BBH", 0, 6, len(header))
    tcp_checksum = checksum(pseudo + header)
    tcp = header[:16] + struct.pack("!H", tcp_checksum) + header[18:]
    flags_offset = 0x2000 if fragment else 0x4000
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        0x1234,
        flags_offset,
        64,
        6,
        0,
        CLIENT_IP_V4,
        GUEST_IP_V4,
    )
    ip_checksum = checksum(ip) if valid_ip_checksum else 0
    ip = ip[:10] + struct.pack("!H", ip_checksum) + ip[12:]
    return GUEST_MAC + CLIENT_MAC + struct.pack("!H", 0x0800) + ip + tcp


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


def parse_guest_tcp_v4(frame: bytes) -> tuple[int, int, int, bytes] | None:
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    header_length = (ip[0] & 0x0F) * 4
    if ip[0] >> 4 != 4 or header_length < 20 or len(ip) < header_length + 20:
        return None
    if ip[9] != 6 or ip[12:16] != GUEST_IP_V4 or ip[16:20] != CLIENT_IP_V4:
        return None
    total_length = struct.unpack("!H", ip[2:4])[0]
    if total_length < header_length + 20 or total_length > len(ip):
        return None
    if checksum(ip[:header_length]) != 0:
        raise RuntimeError("guest IPv4 header checksum mismatch")
    tcp = ip[header_length:total_length]
    source_port, destination_port, seq, ack = struct.unpack("!HHII", tcp[:12])
    if source_port != GUEST_PORT or destination_port != CLIENT_PORT:
        return None
    pseudo = GUEST_IP_V4 + CLIENT_IP_V4 + struct.pack("!BBH", 0, 6, len(tcp))
    if checksum(pseudo + tcp) != 0:
        raise RuntimeError("guest IPv4 TCP checksum mismatch")
    tcp_header_length = (tcp[12] >> 4) * 4
    if tcp_header_length < 20 or tcp_header_length > len(tcp):
        raise RuntimeError("guest IPv4 TCP header length is invalid")
    return seq, ack, tcp[13], tcp[tcp_header_length:]


def parse_any_guest_tcp(frame: bytes) -> tuple[int, int, int, bytes] | None:
    return parse_guest_tcp(frame) or parse_guest_tcp_v4(frame)


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


def assert_no_tcp(sock: socket.socket, predicate, duration: float) -> None:
    deadline = time.monotonic() + duration
    previous_timeout = sock.gettimeout()
    sock.settimeout(0.1)
    try:
        while time.monotonic() < deadline:
            try:
                parsed = parse_any_guest_tcp(recv_frame(sock))
            except socket.timeout:
                continue
            if parsed is not None and predicate(parsed):
                raise RuntimeError("guest accepted a deliberately malformed TCP/IP frame")
    finally:
        sock.settimeout(previous_timeout)


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
        send_frame(sock, ipv4_tcp_frame(valid_ip_checksum=False))
        assert_no_tcp(sock, lambda packet: packet[2] & 0x12 == 0x12, 0.5)
        send_frame(sock, ipv4_tcp_frame(valid_ip_checksum=True, fragment=True))
        assert_no_tcp(sock, lambda packet: packet[2] & 0x12 == 0x12, 0.5)
        send_frame(
            sock,
            ethernet_frame(client_seq, 0, 0x02, valid_checksum=False),
        )
        assert_no_tcp(sock, lambda packet: packet[2] & 0x12 == 0x12, 0.75)
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
        send_frame(sock, ethernet_frame(client_seq + 0x10000, server_next, 0x04))
        client_banner = b"SSH-2.0-XAIOS_IPv6_Client_Test\r\n"
        split = len(client_banner) // 2
        send_frame(
            sock,
            ethernet_frame(
                client_seq + split, server_next, 0x18, client_banner[split:]
            ),
        )
        wait_for_tcp(
            sock,
            lambda packet: packet[1] == client_seq and not packet[3],
            args.timeout,
            args.verbose,
        )
        send_frame(
            sock,
            ethernet_frame(client_seq, server_next, 0x18, client_banner[:split]),
        )
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
            "ipv4_bad_header=rejected ipv4_fragment=rejected "
            "zero_checksum=rejected invalid_rst=rejected "
            "reordered_input=accepted "
            f"guest_banner={payload.decode().strip()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
