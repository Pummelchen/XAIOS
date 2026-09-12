#!/usr/bin/env python3
"""Generate the RFC 8448 key-schedule vectors used by tests/security/test_wt_tls.c.

Same reasoning as generate_wt_rfc9001_vectors.py: the vectors are long hex
blocks, and transcribing them by hand is the one step here that cannot be got
right by reading. Two hand-copied values in a draft of these tests were wrong
while the implementation was right, which is what this removes.

USAGE

    python3 tests/security/generate_wt_rfc8448_vectors.py \\
        --rfc8448 rfc8448.txt \\
        --out userspace/wt/include/wt_rfc8448_vectors.h

The RFC text is not committed; the generated header is, so the tests build and
run offline.

The parser is regex-free and anchored to the RFC's own labels. It extracts a
named "value (N octets):" block, and also the "(same as ...)" references, so a
value the RFC prints once and refers to later is taken from the one place it is
written.
"""

from __future__ import annotations

import argparse
from pathlib import Path

HEX_CHARS = set("0123456789abcdef")


def is_hex_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if not all(c in HEX_CHARS or c == " " for c in stripped):
        return False
    return any(c in HEX_CHARS for c in stripped)


def extract_field(lines: list[str], marker: str, field: str,
                  length: int) -> bytes:
    """The hex of `field` in the block that follows the line with `marker`.

    RFC 8448 prints a block per computation containing several labelled values
    -- "salt", "IKM", "hash", "info", "expanded" -- so taking the first hex run
    after the marker picks up whichever happens to come first. The field is
    named explicitly and the paragraph it must appear in is bounded by the next
    blank line after the marker, so a value is taken from the computation it
    belongs to.
    """
    indices = [n for n, line in enumerate(lines) if marker in line]
    if not indices:
        raise SystemExit(f"marker not found: {marker!r}")
    # The FIRST occurrence, not the last. RFC 8448 prints four more handshakes
    # after section 3, and each refers back to this one with "(same as ...)"
    # rather than repeating the bytes -- so the last occurrence of a step label
    # is a line with no values under it, which is how this first failed.
    start = indices[0] + 1
    # RFC 8448 separates the fields of one computation with blank lines, so the
    # block cannot be bounded by a blank line. It is bounded by the next
    # "{client}" or "{server}" step marker instead, which is where the RFC
    # starts the next computation. Fields are named, so a wider block is safe:
    # the wrong field cannot be picked up by accident, only a field that is not
    # there at all.
    end = start
    while end < len(lines):
        if "{client}" in lines[end] or "{server}" in lines[end]:
            break
        end += 1
    block = lines[start:end]

    for n, line in enumerate(block):
        # A field label is the whole line up to its colon, so the match is
        # anchored: "hash (32 octets):" is a substring of RFC 8448's
        # "binder hash (32 octets):", and a plain substring test would take the
        # binder hash if it were printed first in the block. Anchoring on the
        # label rather than on the line's end matters because the hex continues
        # on the following lines, so the label's line does not end in a colon.
        label = line.strip().split(":")[0].strip() + ":"
        if label != field:
            continue
        # The hex may begin on this line or wrap onto the following ones.
        tokens: list[str] = []
        head = line.split(field, 1)[1]
        for candidate in [head] + block[n + 1:]:
            stripped = candidate.strip()
            if not stripped:
                break
            if not all(c in HEX_CHARS or c == " " for c in stripped):
                break
            tokens.extend(stripped.split())
        blob = "".join(tokens)
        if len(blob) == length * 2:
            return bytes.fromhex(blob)
        raise SystemExit(
            f"field {field!r} after {marker!r} has {len(blob) // 2} bytes, "
            f"expected {length}")
    raise SystemExit(
        f"field {field!r} not found in the block after {marker!r}; the RFC's "
        f"labels have changed and the extracted vectors would be wrong")


def c_array(data: bytes, per_line: int = 10, indent: str = "    ") -> str:
    parts = []
    for offset in range(0, len(data), per_line):
        chunk = data[offset:offset + per_line]
        parts.append(indent + ", ".join(f"0x{b:02x}" for b in chunk))
    return ",\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rfc8448", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    lines = args.rfc8448.read_text(encoding="utf-8", errors="replace").split("\n")

    # Section 3, the simple 1-RTT handshake. Each value is anchored to the line
    # that prints it, and the "(same as ...)" references are taken from the one
    # place the RFC writes the bytes out.
    early = extract_field(lines, 'extract secret "early"', "secret (32 octets):", 32)
    handshake = extract_field(lines, 'extract secret "handshake"', "secret (32 octets):", 32)
    master = extract_field(lines, 'extract secret "master"', "secret (32 octets):", 32)
    ecdhe = extract_field(lines, 'extract secret "handshake"', "IKM (32 octets):", 32)
    derived_early = extract_field(
        lines, 'derive secret for handshake "tls13 derived"',
        "expanded (32 octets):", 32)
    derived_handshake = extract_field(
        lines, 'derive secret for master "tls13 derived"',
        "expanded (32 octets):", 32)
    th_sh = extract_field(lines, 'derive secret "tls13 c hs traffic"',
                  "hash (32 octets):", 32)
    th_ap = extract_field(lines, 'derive secret "tls13 c ap traffic"',
                  "hash (32 octets):", 32)
    c_hs = extract_field(lines, 'derive secret "tls13 c hs traffic"',
                  "expanded (32 octets):", 32)
    s_hs = extract_field(lines, 'derive secret "tls13 s hs traffic"',
                  "expanded (32 octets):", 32)
    c_ap = extract_field(lines, 'derive secret "tls13 c ap traffic"',
                  "expanded (32 octets):", 32)
    s_ap = extract_field(lines, 'derive secret "tls13 s ap traffic"',
                  "expanded (32 octets):", 32)
    exp_master = extract_field(lines, 'derive secret "tls13 exp master"',
                  "expanded (32 octets):", 32)
    # The resumption master secret is taken from a DIFFERENT transcript -- the
    # one through the client's Finished, which is the last hash the trace
    # prints. Deriving it from the server's Finished, as the first version of
    # the key schedule did, gives a well-formed value that is not this one.
    res_master = extract_field(lines, 'derive secret "tls13 res master"',
                               "expanded (32 octets):", 32)
    th_client_finished = extract_field(
        lines, 'derive secret "tls13 res master"', "hash (32 octets):", 32)

    # The two "derived" values are different, and each is printed twice in the
    # RFC -- once as the "expanded" output of its own step and once as the
    # "salt" of the next extraction. This guard catches the parser matching the
    # same block for both, which is the failure that would otherwise pass every
    # length check. It is a conflation check and not a proof of correctness:
    # two distinct wrong blocks would satisfy it. The Python oracle is what
    # makes the extracted values trustworthy.
    if derived_early == derived_handshake:
        raise SystemExit(
            "the two 'derived' values extracted are identical, which means the "
            "parser matched the same block twice")

    header = f'''/* Generated by tests/security/generate_wt_rfc8448_vectors.py -- do not edit.
 *
 * Key-schedule values extracted mechanically from RFC 8448, "Example Handshake
 * Traces for TLS 1.3", section 3. Regenerate with:
 *
 *   python3 tests/security/generate_wt_rfc8448_vectors.py \\
 *       --rfc8448 rfc8448.txt --out userspace/wt/include/wt_rfc8448_vectors.h
 *
 * The RFC text is not committed; this header is, so the tests run offline.
 * Every array here is a value the RFC prints. The test also checks the
 * intermediate steps against tests/security/verify_wt_rfc8448_key_schedule.py,
 * which recomputes them in Python so the C and the vectors are not the same
 * opinion twice.
 */

#ifndef WT_RFC8448_VECTORS_H
#define WT_RFC8448_VECTORS_H

#include <stdint.h>

/* The ECDHE shared secret this trace uses, which is the IKM of the handshake
   extraction. */
static const uint8_t WT_RFC8448_ECDHE[32] = {{
{c_array(ecdhe)}
}};

static const uint8_t WT_RFC8448_EARLY_SECRET[32] = {{
{c_array(early)}
}};
static const uint8_t WT_RFC8448_DERIVED_FROM_EARLY[32] = {{
{c_array(derived_early)}
}};
static const uint8_t WT_RFC8448_HANDSHAKE_SECRET[32] = {{
{c_array(handshake)}
}};
static const uint8_t WT_RFC8448_DERIVED_FROM_HANDSHAKE[32] = {{
{c_array(derived_handshake)}
}};
static const uint8_t WT_RFC8448_MASTER_SECRET[32] = {{
{c_array(master)}
}};

/* The transcript hashes the RFC prints for the two points the traffic secrets
   are taken at. */
static const uint8_t WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO[32] = {{
{c_array(th_sh)}
}};
static const uint8_t WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED[32] = {{
{c_array(th_ap)}
}};

static const uint8_t WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC[32] = {{
{c_array(c_hs)}
}};
static const uint8_t WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC[32] = {{
{c_array(s_hs)}
}};
static const uint8_t WT_RFC8448_CLIENT_APPLICATION_TRAFFIC[32] = {{
{c_array(c_ap)}
}};
static const uint8_t WT_RFC8448_SERVER_APPLICATION_TRAFFIC[32] = {{
{c_array(s_ap)}
}};
static const uint8_t WT_RFC8448_EXPORTER_MASTER[32] = {{
{c_array(exp_master)}
}};

/* The transcript through the CLIENT's Finished, and the resumption master
   secret derived from it. These are a different transcript from the exporter's
   above, which is the whole reason res master is a separate argument. */
static const uint8_t WT_RFC8448_TRANSCRIPT_AFTER_CLIENT_FINISHED[32] = {{
{c_array(th_client_finished)}
}};
static const uint8_t WT_RFC8448_RESUMPTION_MASTER[32] = {{
{c_array(res_master)}
}};

#endif /* WT_RFC8448_VECTORS_H */
'''

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(header, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
