"""Frame I/O, parsing and wait loops for the QEMU network gate.

Split out of ``qemu-ipv6-tcp-client.py`` alongside
``qemu_ipv6_tcp_client_wire``. The wire constants are read through that module
rather than imported by name, because ``main`` rebinds the client address and
port there after parsing argv; the pure ``checksum`` helper is imported by name
because it carries no state.
"""

from __future__ import annotations

import argparse
import socket
import struct
import time

import qemu_ipv6_tcp_client_wire as wire
from qemu_ipv6_tcp_client_wire import checksum


def _assemble_fragments(parts: dict[int, bytes], total: int | None) -> bytes | None:
    if total is None:
        return None
    position = 0
    result = bytearray()
    for offset in sorted(parts):
        if offset != position:
            return None
        result.extend(parts[offset])
        position += len(parts[offset])
    return bytes(result) if position == total else None


def wait_for_udp_echo_v4(
    sock: socket.socket, expected: bytes, timeout: float, verbose: bool
) -> int:
    deadline = time.monotonic() + timeout
    parts: dict[int, bytes] = {}
    total = None
    identification = None
    while time.monotonic() < deadline:
        try:
            frame = recv_frame(sock)
        except socket.timeout:
            continue
        if verbose:
            print(f"received IPv4 candidate bytes={len(frame)}")
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ip_length = struct.unpack("!H", ip[2:4])[0]
        if (
            ip[0] != 0x45
            or ip_length > 1500
            or ip_length > len(ip)
            or ip[9] != 17
            or ip[12:16] != wire.GUEST_IP_V4
            or ip[16:20] != wire.CLIENT_IP_V4
        ):
            continue
        if checksum(ip[:20]) != 0:
            raise RuntimeError("guest fragmented IPv4 header checksum mismatch")
        current_id, flags_offset = struct.unpack("!HH", ip[4:8])
        if (flags_offset & 0x4000) != 0:
            raise RuntimeError("guest set DF on an emitted IPv4 fragment")
        offset = (flags_offset & 0x1FFF) * 8
        more = (flags_offset & 0x2000) != 0
        chunk = ip[20:ip_length]
        if more and len(chunk) % 8 != 0:
            raise RuntimeError("guest emitted misaligned non-final IPv4 fragment")
        if identification is None:
            identification = current_id
        if current_id != identification:
            continue
        parts[offset] = chunk
        if not more:
            total = offset + len(chunk)
        datagram = _assemble_fragments(parts, total)
        if datagram is None:
            continue
        source, destination, length, _ = struct.unpack("!HHHH", datagram[:8])
        if source != wire.GUEST_UDP_PORT or destination != wire.CLIENT_PORT:
            continue
        if length != len(datagram) or datagram[8:] != expected:
            raise RuntimeError("guest fragmented IPv4 UDP echo payload mismatch")
        pseudo = (
            wire.GUEST_IP_V4 + wire.CLIENT_IP_V4 + struct.pack("!BBH", 0, 17, length)
        )
        if checksum(pseudo + datagram) != 0:
            raise RuntimeError("guest fragmented IPv4 UDP checksum mismatch")
        return len(parts)
    raise TimeoutError("timed out waiting for fragmented guest IPv4 UDP echo")


def wait_for_udp_echo_v6(
    sock: socket.socket, expected: bytes, timeout: float, verbose: bool
) -> int:
    deadline = time.monotonic() + timeout
    parts: dict[int, bytes] = {}
    total = None
    identification = None
    while time.monotonic() < deadline:
        try:
            frame = recv_frame(sock)
        except socket.timeout:
            continue
        if verbose:
            print(f"received IPv6 candidate bytes={len(frame)}")
        if len(frame) < 62 or frame[12:14] != b"\x86\xdd":
            continue
        ip6 = frame[14:]
        payload_length = struct.unpack("!H", ip6[4:6])[0]
        if (
            ip6[0] >> 4 != 6
            or 40 + payload_length > 1280
            or 40 + payload_length > len(ip6)
            or ip6[6] != 44
            or ip6[8:24] != wire.GUEST_IP
            or ip6[24:40] != wire.CLIENT_IP
        ):
            continue
        fragment = ip6[40:48]
        next_header, reserved, offset_flags, current_id = struct.unpack(
            "!BBHI", fragment
        )
        if next_header != 17 or reserved != 0 or (offset_flags & 0x0006) != 0:
            raise RuntimeError("guest emitted invalid IPv6 fragment header")
        offset = offset_flags & 0xFFF8
        more = (offset_flags & 1) != 0
        chunk = ip6[48 : 40 + payload_length]
        if more and len(chunk) % 8 != 0:
            raise RuntimeError("guest emitted misaligned non-final IPv6 fragment")
        if identification is None:
            identification = current_id
        if current_id != identification:
            continue
        parts[offset] = chunk
        if not more:
            total = offset + len(chunk)
        datagram = _assemble_fragments(parts, total)
        if datagram is None:
            continue
        source, destination, length, _ = struct.unpack("!HHHH", datagram[:8])
        if source != wire.GUEST_UDP_PORT or destination != wire.CLIENT_PORT:
            continue
        if length != len(datagram) or datagram[8:] != expected:
            raise RuntimeError("guest fragmented IPv6 UDP echo payload mismatch")
        pseudo = wire.GUEST_IP + wire.CLIENT_IP + struct.pack("!I3xB", length, 17)
        if checksum(pseudo + datagram) != 0:
            raise RuntimeError("guest fragmented IPv6 UDP checksum mismatch")
        return len(parts)
    raise TimeoutError("timed out waiting for fragmented guest IPv6 UDP echo")


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
    if frame[22:38] != wire.GUEST_IP or frame[38:54] != wire.CLIENT_IP:
        return None
    payload_length = struct.unpack("!H", frame[18:20])[0]
    tcp = frame[54 : 54 + payload_length]
    if len(tcp) < 20:
        return None
    source_port, destination_port, seq, ack = struct.unpack("!HHII", tcp[:12])
    if source_port != wire.GUEST_PORT or destination_port != wire.CLIENT_PORT:
        return None
    pseudo = wire.GUEST_IP + wire.CLIENT_IP + struct.pack("!I3xB", len(tcp), 6)
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
    if ip[9] != 6 or ip[12:16] != wire.GUEST_IP_V4 or ip[16:20] != wire.CLIENT_IP_V4:
        return None
    total_length = struct.unpack("!H", ip[2:4])[0]
    if total_length < header_length + 20 or total_length > len(ip):
        return None
    if checksum(ip[:header_length]) != 0:
        raise RuntimeError("guest IPv4 header checksum mismatch")
    tcp = ip[header_length:total_length]
    source_port, destination_port, seq, ack = struct.unpack("!HHII", tcp[:12])
    if source_port != wire.GUEST_PORT or destination_port != wire.CLIENT_PORT:
        return None
    pseudo = wire.GUEST_IP_V4 + wire.CLIENT_IP_V4 + struct.pack("!BBH", 0, 6, len(tcp))
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


def wait_for_tcp_v4(sock: socket.socket, predicate, timeout: float, verbose: bool):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            frame = recv_frame(sock)
        except socket.timeout:
            continue
        if verbose:
            print(f"received Ethernet frame bytes={len(frame)} hex={frame[:96].hex()}")
        parsed = parse_guest_tcp_v4(frame)
        if parsed is not None and predicate(parsed):
            return parsed
    raise TimeoutError("timed out waiting for guest IPv4/TCP response")


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


def parse_mac(value: str) -> bytes:
    compact = value.replace(":", "").replace("-", "")
    try:
        result = bytes.fromhex(compact)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid MAC address") from error
    if len(result) != 6 or (result[0] & 1) != 0:
        raise argparse.ArgumentTypeError("MAC address must be a 6-byte unicast address")
    return result
