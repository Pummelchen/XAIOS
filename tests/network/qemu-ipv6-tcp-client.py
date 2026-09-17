#!/usr/bin/env python3
"""Exercise XAIOS IPv6/TCP over QEMU's framed socket network backend.

The frame builders live in ``qemu_ipv6_tcp_client_wire`` and the frame I/O,
parsing and wait loops in ``qemu_ipv6_tcp_client_proto``; this driver owns the
command line, the exchange sequence and the summary it prints. The two modules
sit beside this file, which is what running it as a script puts on ``sys.path``.
"""

from __future__ import annotations

import argparse
import ipaddress
import time

import qemu_ipv6_tcp_client_wire as wire
from qemu_ipv6_tcp_client_proto import (
    assert_no_tcp,
    connect_with_retry,
    parse_mac,
    send_frame,
    wait_for_tcp,
    wait_for_tcp_v4,
    wait_for_udp_echo_v4,
    wait_for_udp_echo_v6,
)
from qemu_ipv6_tcp_client_wire import (
    ethernet_frame,
    ipv4_tcp_fragments,
    ipv4_tcp_frame,
    ipv4_udp_fragments,
    ipv6_tcp_fragments,
    ipv6_udp_fragments,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--client-mac", type=parse_mac, default=wire.CLIENT_MAC)
    parser.add_argument("--client-ipv6", default="fd00::2")
    parser.add_argument("--client-ipv4", default="10.0.2.100")
    parser.add_argument("--client-port", type=int, default=wire.CLIENT_PORT)
    args = parser.parse_args()
    if not 1 <= args.client_port <= 65535:
        parser.error("--client-port must be between 1 and 65535")
    try:
        client_ip = ipaddress.IPv6Address(args.client_ipv6)
        client_ip_v4 = ipaddress.IPv4Address(args.client_ipv4)
    except ipaddress.AddressValueError as error:
        parser.error(str(error))
    wire.configure(
        args.client_mac, client_ip.packed, client_ip_v4.packed, args.client_port
    )

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
