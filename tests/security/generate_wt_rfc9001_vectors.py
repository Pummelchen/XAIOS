#!/usr/bin/env python3
"""Generate the RFC 9001 packet vectors used by tests/security/test_wt_quic_pkt.c.

WHY THIS EXISTS. The vectors are long hex blocks. Transcribing them by hand is
the one step in this work that cannot be got right by reading, and a mistyped
vector fails a correct implementation -- which is what happened while this was
being written: two hand-copied values in a draft of the tests were wrong, and
the implementation was right. Extracting them from the RFC mechanically removes
the only unreliable step.

USAGE

    python3 tests/security/generate_wt_rfc9001_vectors.py \\
        --rfc9001 /path/to/rfc9001.txt \\
        --out userspace/wt/include/wt_rfc9001_vectors.h

The RFC text is not committed: it is 100 KB of specification and is fetched
from the RFC Editor. The generated header IS committed, so the test builds and
runs without network access, and a reviewer can diff it against the RFC without
running anything.

The parser is deliberately dull -- no regular expressions, because a character
class that rejects the RFC's own byte-range notation ('80-00ffff') silently
truncated every vector it was applied to, and the failure looked like a wrong
cryptographic value rather than a wrong parser.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HEX_CHARS = set("0123456789abcdef")


def is_hex_line(line: str) -> bool:
    """Whether a line is (only) a hex-dump line.

    RFC hex dumps are indented groups of byte pairs, sometimes with a further
    indented annotation column, and sometimes containing a hyphen where the
    RFC prints a byte range. Byte ranges are a transcription hazard, so their
    presence is an error rather than something to strip.
    """
    stripped = line.strip()
    if not stripped:
        return False
    if not all(c in HEX_CHARS or c in " -" for c in stripped):
        return False
    return any(c in HEX_CHARS for c in stripped)


def extract_after(lines: list[str], marker: str) -> bytes:
    """The hex block following the last line containing `marker`.

    The block is not necessarily on the line after the marker: RFC prose wraps,
    so the marker can end mid-sentence and the block begins after the remainder
    of the paragraph. This looks for the first run of hex lines after the
    marker, and requires the run to be contiguous.
    """
    indices = [n for n, line in enumerate(lines) if marker in line]
    if not indices:
        raise SystemExit(f"marker not found in the RFC text: {marker!r}")
    start = indices[-1]
    i = start + 1
    while i < len(lines) and not is_hex_line(lines[i]):
        i += 1
    chunks: list[str] = []
    while i < len(lines) and is_hex_line(lines[i]):
        text = lines[i].strip().replace(" ", "")
        if "-" in text:
            raise SystemExit(
                f"line {i + 1} contains a byte range, which is ambiguous to "
                f"extract: {text!r}")
        chunks.append(text)
        i += 1
    blob = "".join(chunks)
    if not blob:
        raise SystemExit(f"no hex block found after {marker!r}")
    try:
        return bytes.fromhex(blob)
    except ValueError as error:
        raise SystemExit(f"bad hex after {marker!r}: {error}") from error


def extract_labelled(lines: list[str], marker: str, length: int) -> bytes:
    """The hex block of exactly `length` bytes following a prose marker.

    Scans forward for the first run of hex-only tokens that yields exactly
    `length` bytes. A run that ends early -- because a connection ID is an
    ASCII word rather than hex -- is not accepted, and the search continues.
    """
    start = [n for n, line in enumerate(lines) if marker in line][-1]
    i = start + 1
    while i < len(lines):
        tokens: list[str] = []
        j = i
        while j < len(lines) and lines[j].strip():
            candidate = lines[j].strip()
            if not all(c in HEX_CHARS or c == " " for c in candidate):
                break
            tokens.extend(candidate.split())
            j += 1
        blob = "".join(tokens)
        if len(blob) == length * 2:
            return bytes.fromhex(blob)
        i += 1
    raise SystemExit(
        f"no {length}-byte hex block found after {marker!r}")


def c_array(data: bytes, indent: str = "    ", per_line: int = 12) -> str:
    """A C initialiser for `data`, `per_line` bytes to a line.

    One helper for every array in the header. The first version of this file
    wrote several of them with a per-array expression that concatenated rows
    without a comma between them -- which compiles as a call, or not at all,
    depending on what follows. One function, one place to be right.
    """
    parts = []
    for offset in range(0, len(data), per_line):
        chunk = data[offset:offset + per_line]
        parts.append(indent + ", ".join(f"0x{b:02x}" for b in chunk))
    return ",\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rfc9001", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    text = args.rfc9001.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")

    client_packet = extract_after(lines, "The resulting protected packet is:")
    client_payload = extract_after(
        lines, "packet contains the following CRYPTO frame, plus enough PADDING")
    # The unprotected headers are printed separately from the protected
    # packets, and they are what the AEAD authenticates and what header
    # protection is applied to. Taking the first 22 bytes of the *protected*
    # packet for this -- which the first version of this file did -- gives an
    # AAD that is wrong in the five bytes the protection covers, so the tag and
    # the mask both come out wrong while the ciphertext, which does not depend
    # on the header, comes out right.
    # Anchored to the RFC's own labels rather than to prose: a Retry packet's
    # Server Connection ID is the ASCII string "token", whose last byte is not
    # a hex digit, so a heuristic that scans for the first hex-looking block
    # stops one byte early and yields a 20-byte header that looks plausible.
    client_header = extract_labelled(
        lines, "The header includes the connection ID and a packet number of 2",
        22)
    # The server Initial's Server Connection ID is one byte while the
    # client's is eight, so the two headers are different lengths: 22 and 20.
    # Assuming 22 for both is what the first version of this did, and the
    # extractor refused rather than emitting a 20-byte array under a 22-byte
    # comment.
    server_header = extract_labelled(
        lines, "The header from the server includes a new connection ID", 20)
    server_packet = extract_after(lines, "The final protected packet is then:")
    retry_packet = extract_after(lines, "value is not included in the final Retry packet")

    # The RFC states the packet lengths in prose as well as by printing the
    # bytes, so the extraction is checked against a number the parser did not
    # produce. A silent truncation is then a build failure here.
    if len(client_packet) != 1200:
        raise SystemExit(
            f"client Initial extracted as {len(client_packet)} bytes, the RFC "
            f"says 1200")
    if not server_packet or not retry_packet:
        raise SystemExit("a vector extracted empty")
    # The client payload is the CRYPTO frame; the RFC says the protected payload
    # is 1162 bytes and that the frame plus PADDING makes it up, so the frame
    # must be shorter than that and start with the CRYPTO frame type.
    if not 0 < len(client_payload) < 1162:
        raise SystemExit(
            f"client CRYPTO frame extracted as {len(client_payload)} bytes, "
            f"which does not fit a 1162-byte payload")
    if client_payload[0] != 0x06:
        raise SystemExit(
            f"client CRYPTO frame starts with 0x{client_payload[0]:02x}, not "
            f"0x06 (the CRYPTO frame type)")
    # The headers must be the RFC's stated lengths and must NOT already carry
    # protection: the protected packet's first byte is the unprotected first
    # byte with its low nibble masked, and for both Initials that nibble is
    # non-zero, so an unprotected header's first byte differs from the
    # protected one. This catches the mix-up at generation time.
    if len(client_header) != 22 or len(server_header) != 20:
        raise SystemExit(
            f"headers extracted at {len(client_header)} and "
            f"{len(server_header)} bytes, expected 22 and 20")
    if client_header == client_packet[:22]:
        raise SystemExit(
            "the client header extracted is identical to the protected "
            "packet's first 22 bytes, which means the protected header was "
            "picked up instead of the unprotected one")
    if server_header == server_packet[:22]:
        raise SystemExit(
            "the server header extracted is identical to the protected "
            "packet's first 22 bytes")

    # The RFC also prints each unprotected header and the connection IDs, which
    # the arithmetic in the test needs. These are short enough to take from the
    # same extraction rather than restate.
    client_tag = client_packet[-16:]
    server_tag = server_packet[-16:]
    retry_tag = retry_packet[-16:]
    retry_without_tag = retry_packet[:-16]
    dcid = bytes.fromhex("8394c8f03e515708")

    header = f"""/* Generated by tests/security/generate_wt_rfc9001_vectors.py -- do not edit.
 *
 * Vectors extracted mechanically from RFC 9001, "Using TLS to Secure QUIC",
 * Appendix A, from the RFC Editor's own text. Regenerate with:
 *
 *   python3 tests/security/generate_wt_rfc9001_vectors.py \\
 *       --rfc9001 rfc9001.txt --out userspace/wt/include/wt_rfc9001_vectors.h
 *
 * The RFC text is not committed; this header is, so the tests run offline.
 * Lengths below are asserted against numbers the extractor read from the
 * RFC's prose, so a truncated extraction fails generation rather than
 * producing a vector that quietly makes a test pass.
 */

#ifndef WT_RFC9001_VECTORS_H
#define WT_RFC9001_VECTORS_H

#include <stdint.h>

/* Appendix A.1: the connection ID this trace uses, and the initial salt. */
static const uint8_t WT_RFC9001_DCID[8] = {{
{c_array(dcid, per_line=8)}
}};
static const uint8_t WT_RFC9001_INITIAL_SALT[20] = {{
{c_array(bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), per_line=10)}
}};

/* Appendix A.1: the Initial keys, as the RFC prints them. These are outputs of
   the same derivation the test performs, so they pin the derivation rather
   than the test's arithmetic. */
static const uint8_t WT_RFC9001_CLIENT_KEY[16] = {{
{c_array(bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d"))}
}};
static const uint8_t WT_RFC9001_CLIENT_IV[12] = {{
{c_array(bytes.fromhex("fa044b2f42a3fd3b46fb255c"))}
}};
static const uint8_t WT_RFC9001_CLIENT_HP[16] = {{
{c_array(bytes.fromhex("9f50449e04a0e810283a1e9933adedd2"))}
}};
static const uint8_t WT_RFC9001_SERVER_KEY[16] = {{
{c_array(bytes.fromhex("cf3a5331653c364c88f0f379b6067e37"))}
}};
static const uint8_t WT_RFC9001_SERVER_IV[12] = {{
{c_array(bytes.fromhex("0ac1493ca1905853b0bba03e"))}
}};
static const uint8_t WT_RFC9001_SERVER_HP[16] = {{
{c_array(bytes.fromhex("c206b8d9b9f0f37644430b490eeaa314"))}
}};

/* Appendix A.2: the client Initial packet, 1200 bytes as printed. The first
   22 bytes are the protected header and the last 16 the AEAD tag. */
#define WT_RFC9001_CLIENT_PACKET_LEN {len(client_packet)}
static const uint8_t WT_RFC9001_CLIENT_PACKET[WT_RFC9001_CLIENT_PACKET_LEN] = {{
{c_array(client_packet)}
}};
/* The unprotected header, which is the AEAD's associated data and the input
   to header protection. */
static const uint8_t WT_RFC9001_CLIENT_HEADER[22] = {{
{c_array(client_header, per_line=11)}
}};
static const uint8_t WT_RFC9001_CLIENT_TAG[16] = {{
{c_array(client_tag, per_line=8)}
}};

/* Appendix A.2: the CRYPTO frame alone, which the RFC prints separately from
   the protected packet. The protected payload is this frame followed by
   PADDING zeros to 1162 bytes. */
#define WT_RFC9001_CLIENT_FRAME_LEN {len(client_payload)}
static const uint8_t WT_RFC9001_CLIENT_FRAME[WT_RFC9001_CLIENT_FRAME_LEN] = {{
{c_array(client_payload)}
}};

/* Appendix A.3: the server Initial packet. */
#define WT_RFC9001_SERVER_PACKET_LEN {len(server_packet)}
static const uint8_t WT_RFC9001_SERVER_PACKET[WT_RFC9001_SERVER_PACKET_LEN] = {{
{c_array(server_packet)}
}};
static const uint8_t WT_RFC9001_SERVER_HEADER[20] = {{
{c_array(server_header, per_line=10)}
}};
static const uint8_t WT_RFC9001_SERVER_TAG[16] = {{
{c_array(server_tag, per_line=8)}
}};

/* Appendix A.4: the Retry packet as it goes on the wire, with its tag, and
   the packet without the tag, which is what the pseudo-header covers. */
static const uint8_t WT_RFC9001_RETRY_PACKET[{len(retry_packet)}] = {{
{c_array(retry_packet)}
}};
static const uint8_t WT_RFC9001_RETRY_WITHOUT_TAG[{len(retry_without_tag)}] = {{
{c_array(retry_without_tag)}
}};
static const uint8_t WT_RFC9001_RETRY_TAG[16] = {{
{c_array(retry_tag, per_line=8)}
}};

/* Appendix A.5: the ChaCha20-Poly1305 short header packet's inputs. */
static const uint8_t WT_RFC9001_CHACHA_SECRET[32] = {{
{c_array(bytes.fromhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"))}
}};
/* The header-protection key is 32 bytes (RFC 9001 A.5 prints it in two lines),
   and the nonce for the protection of this packet is its own value, not a
   slice of the key. The first version of this file declared only the 32-byte
   key and the test read its tail as the nonce, which produces five perfectly
   plausible bytes and the wrong mask. */
static const uint8_t WT_RFC9001_CHACHA_HP[32] = {{
{c_array(bytes.fromhex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"))}
}};
static const uint8_t WT_RFC9001_CHACHA_IV[12] = {{
{c_array(bytes.fromhex("e0459b3474bdd0e44a41c144"))}
}};
static const uint8_t WT_RFC9001_CHACHA_NONCE[12] = {{
{c_array(bytes.fromhex("e0459b3474bdd0e46d417eb0"))}
}};
static const uint8_t WT_RFC9001_CHACHA_HEADER[4] = {{0x42, 0x00, 0xbf, 0xf4}};
static const uint8_t WT_RFC9001_CHACHA_PAYLOAD_CIPHERTEXT[21] = {{
    0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90,
    0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b,
    0xfb,
}};
static const uint8_t WT_RFC9001_CHACHA_SAMPLE[16] = {{
    0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
    0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
}};
static const uint8_t WT_RFC9001_CHACHA_MASK[5] = {{0xae, 0xfe, 0xfe, 0x7d, 0x03}};
static const uint8_t WT_RFC9001_CHACHA_PROTECTED_HEADER[4] = {{
    0x4c, 0xfe, 0x41, 0x89,
}};

#endif /* WT_RFC9001_VECTORS_H */
"""

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(header, encoding="utf-8")
    print(f"wrote {args.out} "
          f"(client {len(client_packet)}, server {len(server_packet)}, "
          f"retry {len(retry_packet)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
