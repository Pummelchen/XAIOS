"""Ethernet, IPv4/IPv6, TCP and UDP frame builders for the QEMU network gate.

Split out of ``qemu-ipv6-tcp-client.py`` so that no file in the split passes the
repository's 500-line limit. The builders read the client identity at call
time, exactly as they did while sharing a module with ``main``, so the frames
are the ones the single-file script emitted. ``main`` rebinds that identity
through :func:`configure` once it has parsed the command line; the guest
addresses and the guest ports are fixed by the gate's QEMU socket backend.
"""

from __future__ import annotations

import ipaddress
import struct


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


def configure(
    client_mac: bytes, client_ip: bytes, client_ip_v4: bytes, client_port: int
) -> None:
    """Point the frame builders at the client identity parsed from argv."""
    global CLIENT_MAC, CLIENT_IP, CLIENT_IP_V4, CLIENT_PORT
    CLIENT_MAC = client_mac
    CLIENT_IP = client_ip
    CLIENT_IP_V4 = client_ip_v4
    CLIENT_PORT = client_port


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
