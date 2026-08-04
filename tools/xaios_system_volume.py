#!/usr/bin/env python3
"""Build and inspect deterministic XAIOS bootable A/B system volumes."""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MAGIC = b"XAIOS-SYSTEM-V2\0"
VERSION = 2
METADATA_BYTES = 4096
PRIMARY_OFFSET = 0
BACKUP_OFFSET = 4096
SLOT0_LBA = 64
SLOT_SECTORS = 32768
SECTOR_BYTES = 512
VOLUME_SECTORS = SLOT0_LBA + 2 * SLOT_SECTORS
SIGNATURE_BYTES = 320
NO_SLOT = 0xFFFFFFFF
DESCRIPTOR = struct.Struct("<IIQQQ32s320s128s")
HEADER_PREFIX = struct.Struct("<16sIIQIIII")
TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
TEST_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)


def canonical_signature(generation: int, digest: bytes) -> bytes:
    unsigned = (
        f"xaios-update:v2:gen={generation}:sha256={digest.hex()}:"
        f"key={TEST_PUBLIC_KEY.hex()}"
    ).encode("ascii")
    signature = Ed25519PrivateKey.from_private_bytes(TEST_SEED).sign(unsigned)
    return unsigned + b":sig=" + signature.hex().encode("ascii")


def descriptor(slot: int, image: bytes, generation: int) -> bytes:
    digest = hashlib.sha256(image).digest()
    signature = canonical_signature(generation, digest)
    if len(signature) >= SIGNATURE_BYTES:
        raise ValueError("system signature exceeds descriptor capacity")
    signature = signature + b"\0" * (SIGNATURE_BYTES - len(signature))
    return DESCRIPTOR.pack(
        1,
        0,
        generation,
        SLOT0_LBA + slot * SLOT_SECTORS,
        len(image),
        digest,
        signature,
        b"\0" * 128,
    )


def metadata(
    slot_a: bytes,
    slot_b: bytes,
    generation_a: int,
    generation_b: int,
    active: int,
    pending: int,
    pending_attempted: int,
    sequence: int,
) -> bytes:
    prefix = HEADER_PREFIX.pack(
        MAGIC,
        VERSION,
        METADATA_BYTES,
        sequence,
        active,
        pending,
        pending_attempted,
        0,
    )
    body = prefix + descriptor(0, slot_a, generation_a) + descriptor(
        1, slot_b, generation_b
    )
    body += b"\0" * (METADATA_BYTES - len(body) - 32)
    return body + hashlib.sha256(body).digest()


def create(args: argparse.Namespace) -> None:
    slot_a = args.slot_a.read_bytes()
    slot_b = args.slot_b.read_bytes() if args.slot_b else slot_a
    limit = SLOT_SECTORS * SECTOR_BYTES
    if not slot_a or not slot_b or len(slot_a) > limit or len(slot_b) > limit:
        raise ValueError(f"slot images must be between 1 and {limit} bytes")
    if args.active not in (0, 1):
        raise ValueError("active slot must be 0 or 1")
    if args.pending not in (NO_SLOT, 0, 1):
        raise ValueError("pending slot must be none, 0, or 1")
    if args.pending == args.active:
        raise ValueError("pending slot must differ from active slot")
    meta = metadata(
        slot_a,
        slot_b,
        args.generation_a,
        args.generation_b,
        args.active,
        args.pending,
        int(args.pending_attempted),
        args.sequence,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as output:
        output.truncate(VOLUME_SECTORS * SECTOR_BYTES)
        output.seek(PRIMARY_OFFSET)
        output.write(meta)
        output.seek(BACKUP_OFFSET)
        output.write(meta)
        output.seek(SLOT0_LBA * SECTOR_BYTES)
        output.write(slot_a)
        output.seek((SLOT0_LBA + SLOT_SECTORS) * SECTOR_BYTES)
        output.write(slot_b)


def parse_metadata(data: bytes) -> dict[str, object]:
    if len(data) != METADATA_BYTES:
        raise ValueError("short system metadata")
    if hashlib.sha256(data[:-32]).digest() != data[-32:]:
        raise ValueError("system metadata checksum mismatch")
    magic, version, size, sequence, active, pending, attempted, flags = (
        HEADER_PREFIX.unpack_from(data)
    )
    if magic != MAGIC or version != VERSION or size != METADATA_BYTES:
        raise ValueError("unsupported system metadata")
    if sequence == 0:
        raise ValueError("system metadata sequence must be non-zero")
    if active not in (0, 1):
        raise ValueError("invalid active system slot")
    if pending not in (NO_SLOT, 0, 1) or pending == active:
        raise ValueError("invalid pending system slot")
    if attempted not in (0, 1):
        raise ValueError("invalid pending-attempted state")
    slots = []
    offset = HEADER_PREFIX.size
    for index in range(2):
        values = DESCRIPTOR.unpack_from(data, offset)
        offset += DESCRIPTOR.size
        try:
            signature = values[6].split(b"\0", 1)[0].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("non-ASCII system signature") from error
        valid = values[0]
        if valid not in (0, 1):
            raise ValueError(f"invalid slot {index} validity")
        if valid and (
            values[2] == 0
            or values[3] != SLOT0_LBA + index * SLOT_SECTORS
            or values[4] == 0
            or values[4] > SLOT_SECTORS * SECTOR_BYTES
            or not signature
        ):
            raise ValueError(f"invalid slot {index} descriptor")
        slots.append(
            {
                "slot": index,
                "valid": valid,
                "generation": values[2],
                "offset_lba": values[3],
                "image_size": values[4],
                "sha256": values[5].hex(),
                "signature": signature,
            }
        )
    return {
        "sequence": sequence,
        "active": active,
        "pending": pending,
        "pending_attempted": attempted,
        "flags": flags,
        "slots": slots,
    }


def read_best_metadata(image: BinaryIO) -> tuple[dict[str, object], str]:
    candidates: list[tuple[dict[str, object], str]] = []
    errors: list[str] = []
    for offset, name in ((PRIMARY_OFFSET, "primary"), (BACKUP_OFFSET, "backup")):
        image.seek(offset)
        try:
            candidates.append((parse_metadata(image.read(METADATA_BYTES)), name))
        except ValueError as error:
            errors.append(f"{name}: {error}")
    if not candidates:
        raise ValueError("no valid system metadata copy (" + "; ".join(errors) + ")")
    candidates.sort(
        key=lambda candidate: (
            int(candidate[0]["sequence"]),
            candidate[1] == "primary",
        ),
        reverse=True,
    )
    return candidates[0]


def verify(args: argparse.Namespace) -> None:
    with args.image.open("rb") as image:
        if args.image.stat().st_size < VOLUME_SECTORS * SECTOR_BYTES:
            raise ValueError("truncated system volume")
        selected_info, selected_copy = read_best_metadata(image)
        public = Ed25519PrivateKey.from_private_bytes(TEST_SEED).public_key()
        for slot in selected_info["slots"]:
            if not slot["valid"]:
                continue
            image.seek(int(slot["offset_lba"]) * SECTOR_BYTES)
            payload = image.read(int(slot["image_size"]))
            if len(payload) != int(slot["image_size"]):
                raise ValueError(f"slot {slot['slot']} payload is truncated")
            digest = hashlib.sha256(payload).hexdigest()
            if digest != slot["sha256"]:
                raise ValueError(f"slot {slot['slot']} payload checksum mismatch")
            signed, signature_hex = str(slot["signature"]).rsplit(":sig=", 1)
            expected = (
                f"xaios-update:v2:gen={slot['generation']}:sha256={slot['sha256']}:"
                f"key={TEST_PUBLIC_KEY.hex()}"
            )
            if signed != expected:
                raise ValueError(f"slot {slot['slot']} signature metadata mismatch")
            public.verify(bytes.fromhex(signature_hex), signed.encode("ascii"))
    print(
        "system-volume: verified "
        f"active={selected_info['active']} pending={selected_info['pending']} "
        f"attempted={selected_info['pending_attempted']} "
        f"sequence={selected_info['sequence']} metadata={selected_copy}"
    )


def slot_value(value: str) -> int:
    return NO_SLOT if value == "none" else int(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("output", type=Path)
    create_parser.add_argument("slot_a", type=Path)
    create_parser.add_argument("--slot-b", type=Path)
    create_parser.add_argument("--generation-a", type=int, default=1)
    create_parser.add_argument("--generation-b", type=int, default=2)
    create_parser.add_argument("--active", type=int, default=0)
    create_parser.add_argument("--pending", type=slot_value, default=NO_SLOT)
    create_parser.add_argument("--pending-attempted", action="store_true")
    create_parser.add_argument("--sequence", type=int, default=1)
    create_parser.set_defaults(function=create)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("image", type=Path)
    verify_parser.set_defaults(function=verify)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
