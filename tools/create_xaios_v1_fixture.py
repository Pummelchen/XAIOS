#!/usr/bin/env python3
"""Create the deterministic model-v1 fixture used by QEMU correctness gates."""

import argparse
import struct
from pathlib import Path


MAGIC = 0x4941494D
VERSION = 1
HEADER_BYTES = 80
QUANTIZATION_Q88 = 8
FLAG_CPU_ONLY = 1
TOKENIZER_BYTE_TABLE = 1
RUNTIME_DETERMINISTIC_FIXTURE = 1


def fnv1a64(content: bytes) -> int:
    value = 14695981039346656037
    for byte in content:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def fixture_bytes() -> bytes:
    weights = bytes([0x5A, 0x03, 0xAA, 0xBB, 0xCC, 0xDD]) + bytes(26)
    tokenizer = bytes(range(256))
    weights_offset = HEADER_BYTES
    tokenizer_offset = weights_offset + len(weights)
    payload_hash = fnv1a64(weights + tokenizer)
    header = struct.pack(
        "<IHHHHIIIQQQQQQBB6s",
        MAGIC,
        VERSION,
        HEADER_BYTES,
        QUANTIZATION_Q88,
        0,
        FLAG_CPU_ONLY,
        TOKENIZER_BYTE_TABLE,
        RUNTIME_DETERMINISTIC_FIXTURE,
        weights_offset,
        len(weights),
        tokenizer_offset,
        len(tokenizer),
        4096,
        payload_hash,
        0x5A,
        0x03,
        bytes(6),
    )
    if len(header) != HEADER_BYTES:
        raise ValueError("fixture header size mismatch")
    return header + weights + tokenizer


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a deterministic XAIOS model-v1 QEMU fixture"
    )
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_bytes(fixture_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
