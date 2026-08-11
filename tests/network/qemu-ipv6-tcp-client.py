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
GUEST_UDP_PORT = 2223
ETHERNET_MIN_FRAME_BYTES = 60


def pad_ethernet_frame(frame: bytes) -> bytes:
    if len(frame) >= ETHERNET_MIN_FRAME_BYTES:
        return frame
    return frame + bytes(ETHERNET_MIN_FRAME_BYTES - len(frame))


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
    return pad_ethernet_frame(
        GUEST_MAC + CLIENT_MAC + struct.pack("!H", 0x86DD) + ipv6 + tcp
    )


def ipv4_tcp_frame(
    *,
    valid_ip_checksum: bool,
    fragment: bool = False,
    seq: int = 0x55667788,
    ack: int = 0,
    flags: int = 0x02,
    identification: int = 0x1234,
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
    pseudo = CLIENT_IP_V4 + GUEST_IP_V4 + struct.pack("!BBH", 0, 6, len(header))
    tcp_checksum = checksum(pseudo + header)
    tcp = header[:16] + struct.pack("!H", tcp_checksum) + header[18:]
    flags_offset = 0x2000 if fragment else 0x4000
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        identification,
        flags_offset,
        64,
        6,
        0,
        CLIENT_IP_V4,
        GUEST_IP_V4,
    )
    ip_checksum = checksum(ip) if valid_ip_checksum else 0
    ip = ip[:10] + struct.pack("!H", ip_checksum) + ip[12:]
    return pad_ethernet_frame(
        GUEST_MAC + CLIENT_MAC + struct.pack("!H", 0x0800) + ip + tcp
    )


def ipv4_tcp_fragments(seq: int, identification: int) -> list[bytes]:
    whole = ipv4_tcp_frame(
        valid_ip_checksum=True, seq=seq, identification=identification
    )
    ethernet = whole[:14]
    ip = whole[14:34]
    total_length = struct.unpack("!H", ip[2:4])[0]
    tcp = whole[34 : 14 + total_length]
    fragments = []
    for offset, payload, more in ((0, tcp[:8], True), (8, tcp[8:], False)):
        fragment_ip = bytearray(ip)
        fragment_ip[2:4] = struct.pack("!H", 20 + len(payload))
        fragment_ip[6:8] = struct.pack(
            "!H", (0x2000 if more else 0) | (offset // 8)
        )
        fragment_ip[10:12] = b"\0\0"
        fragment_ip[10:12] = struct.pack("!H", checksum(bytes(fragment_ip)))
        fragments.append(
            pad_ethernet_frame(ethernet + bytes(fragment_ip) + payload)
        )
    return fragments


def ipv6_tcp_fragments(seq: int, identification: int) -> list[bytes]:
    tcp = tcp_segment(seq, 0, 0x02)
    fragments = []
    for offset, payload, more in ((0, tcp[:8], True), (8, tcp[8:], False)):
        fragment_header = struct.pack(
            "!BBHI", 6, 0, (offset & 0xFFF8) | (1 if more else 0), identification
        )
        ipv6 = struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(fragment_header) + len(payload),
            44,
            64,
            CLIENT_IP,
            GUEST_IP,
        )
        fragments.append(
            pad_ethernet_frame(
                GUEST_MAC
                + CLIENT_MAC
                + struct.pack("!H", 0x86DD)
                + ipv6
                + fragment_header
                + payload
            )
        )
    return fragments


def udp_segment_v4(payload: bytes) -> bytes:
    header = struct.pack(
        "!HHHH", CLIENT_PORT, GUEST_UDP_PORT, 8 + len(payload), 0
    )
    pseudo = CLIENT_IP_V4 + GUEST_IP_V4 + struct.pack(
        "!BBH", 0, 17, len(header) + len(payload)
    )
    value = checksum(pseudo + header + payload)
    if value == 0:
        value = 0xFFFF
    return header[:6] + struct.pack("!H", value) + payload


def udp_segment_v6(payload: bytes) -> bytes:
    header = struct.pack(
        "!HHHH", CLIENT_PORT, GUEST_UDP_PORT, 8 + len(payload), 0
    )
    pseudo = CLIENT_IP + GUEST_IP + struct.pack(
        "!I3xB", len(header) + len(payload), 17
    )
    value = checksum(pseudo + header + payload)
    if value == 0:
        value = 0xFFFF
    return header[:6] + struct.pack("!H", value) + payload


def ipv4_udp_fragments(payload: bytes, identification: int) -> list[bytes]:
    datagram = udp_segment_v4(payload)
    fragments = []
    fragment_payload = 1480
    for offset in range(0, len(datagram), fragment_payload):
        chunk = datagram[offset : offset + fragment_payload]
        more = offset + len(chunk) < len(datagram)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(chunk),
            identification,
            (0x2000 if more else 0) | (offset // 8),
            64,
            17,
            0,
            CLIENT_IP_V4,
            GUEST_IP_V4,
        )
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        fragments.append(
            pad_ethernet_frame(
                GUEST_MAC + CLIENT_MAC + struct.pack("!H", 0x0800) + ip + chunk
            )
        )
    return fragments


def ipv6_udp_fragments(payload: bytes, identification: int) -> list[bytes]:
    datagram = udp_segment_v6(payload)
    fragments = []
    fragment_payload = 1232
    for offset in range(0, len(datagram), fragment_payload):
        chunk = datagram[offset : offset + fragment_payload]
        more = offset + len(chunk) < len(datagram)
        fragment_header = struct.pack(
            "!BBHI", 17, 0, (offset & 0xFFF8) | (1 if more else 0), identification
        )
        ipv6 = struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(fragment_header) + len(chunk),
            44,
            64,
            CLIENT_IP,
            GUEST_IP,
        )
        fragments.append(
            pad_ethernet_frame(
                GUEST_MAC
                + CLIENT_MAC
                + struct.pack("!H", 0x86DD)
                + ipv6
                + fragment_header
                + chunk
            )
        )
    return fragments


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
            or ip[12:16] != GUEST_IP_V4
            or ip[16:20] != CLIENT_IP_V4
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
        if source != GUEST_UDP_PORT or destination != CLIENT_PORT:
            continue
        if length != len(datagram) or datagram[8:] != expected:
            raise RuntimeError("guest fragmented IPv4 UDP echo payload mismatch")
        pseudo = GUEST_IP_V4 + CLIENT_IP_V4 + struct.pack("!BBH", 0, 17, length)
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
            or ip6[8:24] != GUEST_IP
            or ip6[24:40] != CLIENT_IP
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
        if source != GUEST_UDP_PORT or destination != CLIENT_PORT:
            continue
        if length != len(datagram) or datagram[8:] != expected:
            raise RuntimeError("guest fragmented IPv6 UDP echo payload mismatch")
        pseudo = GUEST_IP + CLIENT_IP + struct.pack("!I3xB", length, 17)
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


def main() -> int:
    global CLIENT_MAC, CLIENT_IP, CLIENT_IP_V4, CLIENT_PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--client-mac", type=parse_mac, default=CLIENT_MAC)
    parser.add_argument("--client-ipv6", default="fd00::2")
    parser.add_argument("--client-ipv4", default="10.0.2.100")
    parser.add_argument("--client-port", type=int, default=CLIENT_PORT)
    args = parser.parse_args()
    if not 1 <= args.client_port <= 65535:
        parser.error("--client-port must be between 1 and 65535")
    try:
        client_ip = ipaddress.IPv6Address(args.client_ipv6)
        client_ip_v4 = ipaddress.IPv4Address(args.client_ipv4)
    except ipaddress.AddressValueError as error:
        parser.error(str(error))
    CLIENT_MAC = args.client_mac
    CLIENT_IP = client_ip.packed
    CLIENT_IP_V4 = client_ip_v4.packed
    CLIENT_PORT = args.client_port

    client_seq = 0x10203040
    with connect_with_retry(args.host, args.port, args.timeout) as sock:
        ipv4_udp_payload = bytes((index * 17 + 3) & 0xFF for index in range(1478))
        for frame in ipv4_udp_fragments(ipv4_udp_payload, 0xCAFE):
            send_frame(sock, frame)
        ipv4_outbound_fragments = wait_for_udp_echo_v4(
            sock, ipv4_udp_payload, args.timeout, args.verbose
        )
        if ipv4_outbound_fragments < 2:
            raise RuntimeError("guest did not fragment oversized IPv4 UDP output")

        ipv6_udp_payload = bytes((index * 29 + 7) & 0xFF for index in range(1458))
        for frame in ipv6_udp_fragments(ipv6_udp_payload, 0x0BADF00D):
            send_frame(sock, frame)
        ipv6_outbound_fragments = wait_for_udp_echo_v6(
            sock, ipv6_udp_payload, args.timeout, args.verbose
        )
        if ipv6_outbound_fragments < 2:
            raise RuntimeError("guest did not fragment oversized IPv6 UDP output")

        send_frame(sock, ipv4_tcp_frame(valid_ip_checksum=False))
        assert_no_tcp(sock, lambda packet: packet[2] & 0x12 == 0x12, 0.5)
        send_frame(sock, ipv4_tcp_frame(valid_ip_checksum=True, fragment=True))
        assert_no_tcp(sock, lambda packet: packet[2] & 0x12 == 0x12, 0.5)

        ipv4_fragment_seq = 0x55667900
        ipv4_fragments = ipv4_tcp_fragments(ipv4_fragment_seq, 0x1235)
        send_frame(sock, ipv4_fragments[0])
        send_frame(sock, ipv4_fragments[1])
        ipv4_server_seq, _, _, _ = wait_for_tcp_v4(
            sock,
            lambda packet: packet[2] & 0x12 == 0x12
            and packet[1] == ipv4_fragment_seq + 1,
            args.timeout,
            args.verbose,
        )
        send_frame(
            sock,
            ipv4_tcp_frame(
                valid_ip_checksum=True,
                seq=ipv4_fragment_seq + 1,
                ack=ipv4_server_seq + 1,
                flags=0x14,
                identification=0x1236,
            ),
        )

        ipv6_fragment_seq = client_seq - 0x100
        ipv6_fragments = ipv6_tcp_fragments(ipv6_fragment_seq, 0xA1B2C3D4)
        send_frame(sock, ipv6_fragments[1])
        send_frame(sock, ipv6_fragments[0])
        ipv6_server_seq, _, _, _ = wait_for_tcp(
            sock,
            lambda packet: packet[2] & 0x12 == 0x12
            and packet[1] == ipv6_fragment_seq + 1,
            args.timeout,
            args.verbose,
        )
        send_frame(
            sock,
            ethernet_frame(
                ipv6_fragment_seq + 1, ipv6_server_seq + 1, 0x14
            ),
        )

        send_frame(
            sock,
            ethernet_frame(client_seq, 0, 0x02, valid_checksum=False),
        )
        assert_no_tcp(sock, lambda packet: packet[2] & 0x12 == 0x12, 0.75)
        send_frame(sock, ethernet_frame(client_seq, 0, 0x02))
        server_seq, _, _, _ = wait_for_tcp(
            sock,
            lambda packet: packet[2] & 0x12 == 0x12
            and packet[1] == client_seq + 1,
            args.timeout,
            args.verbose,
        )

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
        send_frame(
            sock,
            ethernet_frame(client_seq, server_seq + len(payload), 0x14),
        )
        time.sleep(0.5)
        print(
            "IPv6 TCP transfer passed: "
            f"sent={len(client_banner)} received={len(payload)} "
            f"retransmit_seconds={retransmit_seconds:.3f} "
            "ipv4_bad_header=rejected incomplete_fragment=held "
            "ipv4_fragments=reassembled ipv6_fragments=reassembled "
            f"outbound_ipv4_fragments={ipv4_outbound_fragments} "
            f"outbound_ipv6_fragments={ipv6_outbound_fragments} "
            "zero_checksum=rejected invalid_rst=rejected "
            "reordered_input=accepted valid_rst=closed "
            f"guest_banner={payload.decode().strip()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
