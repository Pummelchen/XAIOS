#!/usr/bin/env python3
"""Structures, constants and record types of the XAIOS xaiFS volume v1.

This is the shared floor of the host implementation: the on-disk format's
scalar bounds, the byte-level primitives, the record dataclasses and the
record-list bookkeeping both halves use. `xai_fs_manifest` builds and signs
logical manifests, `xai_fs_codec` packs the records into superblock and catalog
bytes, `xai_fs_write` and `xai_fs_read` hold the two halves of `XaiFs`, and
`xaios_xai_fs` is the command-line facade over all of them.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import struct
from typing import Iterable, Optional


MAGIC = b"XAIOSV1\0"
CATALOG_MAGIC = b"XAICAT1\0"
VERSION_MAJOR = 1
VERSION_MINOR = 0
ENDIAN_LITTLE = 1
HASH_SHA256 = 1
SUPERBLOCK_SIZE = 4096
BLOCK_SIZE = 4096
CATALOG_HEADER_SIZE = 256
PACKAGE_RECORD_SIZE = 384
CHUNK_RECORD_SIZE = 128
MIN_CHUNK_SIZE = 2 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
DATA_START = 1024 * 1024

PACKAGE_STAGING = 1
PACKAGE_ACTIVE = 2
PACKAGE_QUARANTINED = 3

CHUNK_COMPLETE = 1
CHUNK_ZERO = 2
CHUNK_FREE = 4

TARGETS = (
    "portable",
    "apple-neon",
    "apple-accelerate",
    "intel-avx2",
    "intel-avx512-vnni",
    "intel-amx",
)

_ZERO_DIGESTS: dict[int, bytes] = {}


class XaiFsIntegrityError(ValueError):
    """Identifies the package and logical chunk that failed verification."""

    def __init__(self, package_id: bytes, logical_offset: Optional[int], reason: str):
        self.package_id = package_id
        self.logical_offset = logical_offset
        self.reason = reason
        location = "manifest" if logical_offset is None else str(logical_offset)
        super().__init__(f"package {package_id.hex()} {location}: {reason}")


def _align(value: int, alignment: int = BLOCK_SIZE) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("invalid alignment")
    result = (value + alignment - 1) & ~(alignment - 1)
    if result >= 1 << 64:
        raise OverflowError("aligned offset exceeds 64 bits")
    return result


def _checked_end(offset: int, length: int, limit: int) -> int:
    if offset < 0 or length < 0 or limit < 0:
        raise ValueError("negative range")
    end = offset + length
    if end >= 1 << 64 or end < offset or end > limit:
        raise ValueError("range exceeds volume")
    return end


def _pwrite_all(fd: int, data: bytes | bytearray | memoryview, offset: int) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.pwrite(fd, view[written:], offset + written)
        if count <= 0:
            raise IOError("short volume write")
        written += count


def _fixed_ascii(value: str, size: int, field: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be ASCII") from error
    if not encoded or len(encoded) > size or b"\0" in encoded:
        raise ValueError(f"{field} must be 1..{size} ASCII bytes")
    return encoded.ljust(size, b"\0")


def _zero_digest(length: int) -> bytes:
    cached = _ZERO_DIGESTS.get(length)
    if cached is not None:
        return cached
    digest = hashlib.sha256()
    block = bytes(min(length, 1024 * 1024))
    remaining = length
    while remaining:
        count = min(remaining, len(block))
        digest.update(block[:count])
        remaining -= count
    result = digest.digest()
    _ZERO_DIGESTS[length] = result
    return result


def _private_key_from_seed(seed: bytes):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must contain exactly 32 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as error:
        raise RuntimeError(
            "Ed25519 signing requires the Python cryptography package"
        ) from error
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_bytes(private_key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (ImportError, InvalidSignature, ValueError):
        return False


@dataclasses.dataclass(frozen=True)
class ManifestChunk:
    logical_offset: int
    length: int
    checksum: bytes
    zero: bool = False

    def __post_init__(self) -> None:
        if self.logical_offset < 0 or self.length <= 0 or len(self.checksum) != 32:
            raise ValueError("invalid manifest chunk")
        if self.zero and self.checksum != _zero_digest(self.length):
            raise ValueError("sparse-zero chunk checksum is incorrect")


@dataclasses.dataclass(frozen=True)
class PackageManifest:
    model_uuid: bytes
    source_revision: bytes
    architecture_id: str
    target_id: str
    logical_size: int
    chunk_size: int
    chunks: tuple[ManifestChunk, ...]
    package_id: bytes
    signer_public_key: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.model_uuid) != 16 or not any(self.model_uuid):
            raise ValueError("model UUID must contain 16 nonzero bytes")
        if len(self.source_revision) != 32 or not any(self.source_revision):
            raise ValueError("source revision must contain 32 nonzero bytes")
        _fixed_ascii(self.architecture_id, 32, "architecture ID")
        if self.target_id not in TARGETS:
            raise ValueError("unknown package target")
        if self.logical_size <= 0 or self.logical_size >= 1 << 64:
            raise ValueError("invalid logical package size")
        _validate_chunk_size(self.chunk_size)
        if len(self.package_id) != 32 or len(self.signer_public_key) != 32:
            raise ValueError("invalid package identity or signer key")
        if len(self.signature) != 64:
            raise ValueError("invalid Ed25519 signature")
        _validate_logical_chunks(self.logical_size, self.chunk_size, self.chunks)
        if package_identity(
            self.model_uuid,
            self.source_revision,
            self.architecture_id,
            self.target_id,
            self.logical_size,
            self.chunk_size,
            self.chunks,
        ) != self.package_id:
            raise ValueError("package identity does not match the logical manifest")

    def verify_signature(self) -> bool:
        return verify_ed25519(self.signer_public_key, self.signature, self.package_id)

    def to_json(self) -> dict[str, object]:
        return {
            "schema": "xaios.xaifs.package-manifest.v1",
            "model_uuid": self.model_uuid.hex(),
            "source_revision": self.source_revision.hex(),
            "architecture_id": self.architecture_id,
            "target_id": self.target_id,
            "logical_size": self.logical_size,
            "chunk_size": self.chunk_size,
            "package_id": self.package_id.hex(),
            "signer_public_key": self.signer_public_key.hex(),
            "signature": self.signature.hex(),
            "chunks": [
                {
                    "logical_offset": chunk.logical_offset,
                    "length": chunk.length,
                    "sha256": chunk.checksum.hex(),
                    "zero": chunk.zero,
                }
                for chunk in self.chunks
            ],
        }

    @classmethod
    def from_json(cls, value: dict[str, object]) -> "PackageManifest":
        if value.get("schema") != "xaios.xaifs.package-manifest.v1":
            raise ValueError("unsupported package manifest schema")
        raw_chunks = value.get("chunks")
        if not isinstance(raw_chunks, list):
            raise ValueError("package manifest chunks must be a list")
        chunks = []
        for raw in raw_chunks:
            if not isinstance(raw, dict):
                raise ValueError("invalid package manifest chunk")
            chunks.append(
                ManifestChunk(
                    int(raw["logical_offset"]),
                    int(raw["length"]),
                    bytes.fromhex(str(raw["sha256"])),
                    bool(raw.get("zero", False)),
                )
            )
        return cls(
            bytes.fromhex(str(value["model_uuid"])),
            bytes.fromhex(str(value["source_revision"])),
            str(value["architecture_id"]),
            str(value["target_id"]),
            int(value["logical_size"]),
            int(value["chunk_size"]),
            tuple(chunks),
            bytes.fromhex(str(value["package_id"])),
            bytes.fromhex(str(value["signer_public_key"])),
            bytes.fromhex(str(value["signature"])),
        )


@dataclasses.dataclass
class _ChunkRecord:
    record_id: int
    logical_offset: int
    physical_offset: int
    length: int
    flags: int
    checksum: bytes
    extent_length: int


@dataclasses.dataclass
class _PackageRecord:
    state: int
    flags: int
    record_id: int
    model_uuid: bytes
    package_id: bytes
    signer_public_key: bytes
    signature: bytes
    source_revision: bytes
    logical_size: int
    chunk_size: int
    chunk_start: int
    chunk_count: int
    architecture_id: str
    target_id: str


@dataclasses.dataclass(frozen=True)
class Extent:
    logical_offset: int
    physical_offset: int
    length: int
    zero: bool


def chunk_size_for(logical_size: int) -> int:
    """The chunk size a package of this size should be written with.

    A chunk is the unit of three separate things, and they do not want the
    same answer, which is why this is a policy and not a constant.

    It is the unit of verification: a read of any part of a chunk hashes the
    whole chunk, because that is what the checksum covers. Small chunks are
    better for reading a little.

    It is the unit of the catalog, and the catalog is rewritten in full on
    every commit -- a new copy at a fresh offset, then the superblock flips to
    it. At 128 bytes a chunk, a 500 GB package cut into 2 MiB chunks carries a
    32 MB catalog, and an ingest that commits per chunk rewrites it a quarter
    of a million times: eight terabytes of catalog to land half a terabyte of
    weights. The same package at 16 MiB chunks carries a 4 MB catalog and
    commits 32k times, which is 128 GB. Sixty-four times less, from one
    number.

    So: small chunks while a package is small enough for the catalog not to
    matter, growing as it does, capped where the format caps. The format's cap
    is 64 MiB, which holds the chunk count under 65536 out to four terabytes;
    past that it binds again and the catalog grows with the package. Raising it
    further is a one-line change on both sides -- nothing is sized by it -- but
    it costs partial reads, which hash a whole chunk to return any of it, so it
    is not worth doing before something needs it.
    """
    if logical_size < 8 * 1024 * 1024 * 1024:
        return MIN_CHUNK_SIZE
    if logical_size < 32 * 1024 * 1024 * 1024:
        return 4 * 1024 * 1024
    if logical_size < 128 * 1024 * 1024 * 1024:
        return 8 * 1024 * 1024
    if logical_size < 1024 * 1024 * 1024 * 1024:
        return 16 * 1024 * 1024
    if logical_size < 4 * 1024 * 1024 * 1024 * 1024:
        return 32 * 1024 * 1024
    return MAX_CHUNK_SIZE


def _validate_chunk_size(chunk_size: int) -> None:
    if (
        chunk_size < MIN_CHUNK_SIZE
        or chunk_size > MAX_CHUNK_SIZE
        or chunk_size & (chunk_size - 1)
    ):
        raise ValueError("chunk size must be a 2..64 MiB power of two")


def _validate_logical_chunks(
    logical_size: int, chunk_size: int, chunks: Iterable[ManifestChunk]
) -> None:
    expected = 0
    count = 0
    for chunk in chunks:
        if chunk.logical_offset != expected:
            raise ValueError("manifest chunks must be contiguous and ordered")
        if chunk.length > chunk_size:
            raise ValueError("manifest chunk exceeds configured chunk size")
        expected = _checked_end(expected, chunk.length, logical_size)
        count += 1
    if expected != logical_size or count == 0:
        raise ValueError("manifest chunks do not cover the logical package")


def package_identity(
    model_uuid: bytes,
    source_revision: bytes,
    architecture_id: str,
    target_id: str,
    logical_size: int,
    chunk_size: int,
    chunks: Iterable[ManifestChunk],
) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"xaios.model.volume.package.v1\0")
    digest.update(model_uuid)
    digest.update(source_revision)
    digest.update(_fixed_ascii(architecture_id, 32, "architecture ID"))
    digest.update(_fixed_ascii(target_id, 32, "target ID"))
    digest.update(struct.pack("<QQ", logical_size, chunk_size))
    for chunk in chunks:
        flags = CHUNK_ZERO if chunk.zero else 0
        digest.update(struct.pack("<QQI", chunk.logical_offset, chunk.length, flags))
        digest.update(chunk.checksum)
    return digest.digest()


def _coalesce_extents(extents: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted(extents)
    result = []
    for offset, length in ordered:
        if not result or result[-1][0] + result[-1][1] < offset:
            result.append((offset, length))
        else:
            start, current = result[-1]
            result[-1] = (start, max(start + current, offset + length) - start)
    return result


def _reindex_records(
    records: list[_PackageRecord], chunks: list[_ChunkRecord]
) -> None:
    free = [chunk for chunk in chunks if chunk.flags & CHUNK_FREE]
    owned = [chunk for chunk in chunks if not chunk.flags & CHUNK_FREE]
    rebuilt = list(free)
    for record in records:
        record_chunks = [chunk for chunk in owned if chunk.record_id == record.record_id]
        record_chunks.sort(key=lambda chunk: chunk.logical_offset)
        record.chunk_start = len(rebuilt)
        record.chunk_count = len(record_chunks)
        rebuilt.extend(record_chunks)
    chunks[:] = rebuilt
