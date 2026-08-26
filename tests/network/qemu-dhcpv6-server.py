#!/usr/bin/env python3
"""A DHCPv6 server on the guest's own link, so the client can be proved rather than assumed.

None of the four environments XAIOS boots in runs a DHCPv6 server. QEMU's
user-mode networking answers DHCPv4 and sends router advertisements, but has no
DHCPv6; Fusion and Virtualization.framework were not observed to answer either.
A client that is never answered cannot be distinguished from a client that is
broken -- both produce "no lease" and a boot that carries on -- so leaving it
there would have meant shipping an implementation nothing had ever exercised.

This supplies the missing half. QEMU's stream netdev carries raw Ethernet
frames over a TCP socket, joined to the same hub as the guest's user netdev, so
a process here sits on the guest's link and sees its multicast. That is enough
to answer a SOLICIT properly: parse the client's options, honour Rapid Commit
or not, and hand back an address the guest is then expected to configure.

Two modes, because the client has two paths and only one of them would be
exercised by default:

  --mode rapid   answer SOLICIT with REPLY directly, the two-message exchange
  --mode full    answer SOLICIT with ADVERTISE and wait for the REQUEST, the
                 four-message exchange

Exits non-zero with a reason if the exchange does not complete, so the caller
can tell "the client is wrong" from "the client never spoke".
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

SERVER_MAC = bytes.fromhex("525400d6c6a6")
LINK_LOCAL_SERVER = bytes.fromhex("fe800000000000000000000000000099")
OFFERED_ADDRESS = bytes.fromhex("20010db8000000000000000000000042")
OFFERED_DNS = bytes.fromhex("20010db8000000000000000000000001")

CLIENT_PORT = 546
SERVER_PORT = 547

SOLICIT = 1
ADVERTISE = 2
REQUEST = 3
REPLY = 7

OPT_CLIENTID = 1
OPT_SERVERID = 2
OPT_IA_NA = 3
OPT_IAADDR = 5
OPT_ELAPSED_TIME = 8
OPT_RAPID_COMMIT = 14
OPT_DNS_SERVERS = 23

# DUID-LL, Ethernet, this server's MAC.
SERVER_DUID = struct.pack("!HH", 3, 1) + SERVER_MAC

PREFERRED_LIFETIME = 3600
VALID_LIFETIME = 7200


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


def ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for value in struct.unpack(f"!{len(data) // 2}H", data):
        total += value
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp6_checksum(src: bytes, dst: bytes, payload: bytes) -> int:
    pseudo = src + dst + struct.pack("!I3xB", len(payload), 17)
    value = ones_complement(pseudo + payload)
    # A computed zero must be transmitted as 0xffff over IPv6; zero means
    # "no checksum", which IPv6 does not permit.
    return value if value != 0 else 0xFFFF


def parse_options(blob: bytes) -> list[tuple[int, bytes]]:
    options = []
    offset = 0
    while offset + 4 <= len(blob):
        code, length = struct.unpack("!HH", blob[offset:offset + 4])
        if offset + 4 + length > len(blob):
            raise RuntimeError(f"option {code} claims {length} bytes past the end")
        options.append((code, blob[offset + 4:offset + 4 + length]))
        offset += 4 + length
    if offset != len(blob):
        raise RuntimeError("options do not tile the message exactly")
    return options


def build_option(code: int, payload: bytes) -> bytes:
    return struct.pack("!HH", code, len(payload)) + payload


def build_reply(message_type: int, transaction_id: bytes, client_duid: bytes,
                iaid: int, rapid_commit: bool) -> bytes:
    ia_address = build_option(
        OPT_IAADDR,
        OFFERED_ADDRESS + struct.pack("!II", PREFERRED_LIFETIME, VALID_LIFETIME),
    )
    ia_na = build_option(OPT_IA_NA, struct.pack("!III", iaid, 1800, 2880) + ia_address)
    options = (
        build_option(OPT_CLIENTID, client_duid)
        + build_option(OPT_SERVERID, SERVER_DUID)
        + ia_na
        + build_option(OPT_DNS_SERVERS, OFFERED_DNS)
    )
    if rapid_commit:
        options += build_option(OPT_RAPID_COMMIT, b"")
    return bytes([message_type]) + transaction_id + options


def build_frame(client_mac: bytes, client_ip: bytes, message: bytes) -> bytes:
    udp = struct.pack("!HHHH", SERVER_PORT, CLIENT_PORT, 8 + len(message), 0) + message
    checksum = udp6_checksum(LINK_LOCAL_SERVER, client_ip, udp)
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    ipv6 = struct.pack(
        "!IHBB16s16s", 6 << 28, len(udp), 17, 64, LINK_LOCAL_SERVER, client_ip
    )
    return client_mac + SERVER_MAC + struct.pack("!H", 0x86DD) + ipv6 + udp


def parse_client_message(frame: bytes) -> tuple | None:
    """Return (message_type, xid, client_mac, client_ip, options) for a DHCPv6 message."""
    if len(frame) < 14 + 40 + 8 + 4:
        return None
    if frame[12:14] != b"\x86\xdd":
        return None
    if frame[20] != 17:
        return None
    src_ip = frame[22:38]
    udp = frame[54:]
    if len(udp) < 8:
        return None
    src_port, dst_port, udp_length = struct.unpack("!HHH", udp[:6])
    if src_port != CLIENT_PORT or dst_port != SERVER_PORT:
        return None
    if udp_length < 8 or udp_length - 8 > len(udp) - 8:
        return None
    message = udp[8:udp_length]
    if len(message) < 4:
        return None
    return message[0], message[1:4], frame[6:12], src_ip, parse_options(message[4:])


def find_option(options: list[tuple[int, bytes]], code: int) -> bytes | None:
    for option_code, payload in options:
        if option_code == code:
            return payload
    return None


def check_client_message(message_type: int, options: list[tuple[int, bytes]],
                         expect_server_id: bool) -> tuple[bytes, int]:
    """Validate what the client sent and return (client DUID, IAID).

    The point of a gate is to reject a wrong message, not to accept anything
    that parses, so the requirements RFC 8415 places on the client are checked
    here rather than assumed.
    """
    client_duid = find_option(options, OPT_CLIENTID)
    if not client_duid:
        raise RuntimeError(f"message type {message_type} carried no Client Identifier")
    if find_option(options, OPT_ELAPSED_TIME) is None:
        raise RuntimeError(f"message type {message_type} carried no Elapsed Time")
    server_id = find_option(options, OPT_SERVERID)
    if expect_server_id:
        if server_id is None:
            raise RuntimeError("REQUEST carried no Server Identifier")
        if server_id != SERVER_DUID:
            raise RuntimeError("REQUEST echoed a Server Identifier this server never sent")
    elif server_id is not None:
        raise RuntimeError("SOLICIT carried a Server Identifier, which it must not")
    ia_na = find_option(options, OPT_IA_NA)
    if ia_na is None or len(ia_na) < 12:
        raise RuntimeError(f"message type {message_type} carried no usable IA_NA")
    return client_duid, struct.unpack("!I", ia_na[:4])[0]


def serve(host: str, port: int, mode: str, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(2.0)

    advertised_to: bytes | None = None
    solicit_xid: bytes | None = None

    while time.monotonic() < deadline:
        try:
            frame = recv_frame(sock)
        except socket.timeout:
            continue
        try:
            parsed = parse_client_message(frame)
        except RuntimeError as error:
            print(f"dhcpv6-server: malformed client message: {error}")
            return 1
        if parsed is None:
            continue
        message_type, xid, client_mac, client_ip, options = parsed

        if message_type == SOLICIT:
            client_duid, iaid = check_client_message(message_type, options, False)
            wants_rapid = find_option(options, OPT_RAPID_COMMIT) is not None
            if not wants_rapid:
                print("dhcpv6-server: SOLICIT did not ask for rapid commit")
                return 1
            if mode == "rapid":
                send_frame(sock, build_frame(
                    client_mac, client_ip,
                    build_reply(REPLY, xid, client_duid, iaid, True)))
                print("dhcpv6-server: answered SOLICIT with REPLY (rapid commit)")
                return 0
            send_frame(sock, build_frame(
                client_mac, client_ip,
                build_reply(ADVERTISE, xid, client_duid, iaid, False)))
            print("dhcpv6-server: answered SOLICIT with ADVERTISE")
            advertised_to = client_duid
            solicit_xid = xid
            continue

        if message_type == REQUEST:
            if advertised_to is None:
                print("dhcpv6-server: REQUEST arrived before any ADVERTISE")
                return 1
            client_duid, iaid = check_client_message(message_type, options, True)
            if client_duid != advertised_to:
                print("dhcpv6-server: REQUEST came from a different client")
                return 1
            # RFC 8415 treats SOLICIT and the REQUEST that follows as one
            # exchange, so the transaction id must not have moved.
            if xid != solicit_xid:
                print("dhcpv6-server: REQUEST used a new transaction id")
                return 1
            ia_na = find_option(options, OPT_IA_NA)
            if ia_na is None or len(ia_na) < 12 + 4 + 24:
                print("dhcpv6-server: REQUEST did not name the offered address")
                return 1
            requested = ia_na[16:32]
            if requested != OFFERED_ADDRESS:
                print("dhcpv6-server: REQUEST named an address that was never offered")
                return 1
            send_frame(sock, build_frame(
                client_mac, client_ip,
                build_reply(REPLY, xid, client_duid, iaid, False)))
            print("dhcpv6-server: answered REQUEST with REPLY")
            return 0

    print("dhcpv6-server: no usable client message arrived before the deadline")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", choices=("rapid", "full"), default="rapid")
    parser.add_argument("--timeout", type=float, default=60.0)
    arguments = parser.parse_args()
    try:
        return serve(arguments.host, arguments.port, arguments.mode,
                     arguments.timeout)
    except (OSError, RuntimeError) as error:
        print(f"dhcpv6-server: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
