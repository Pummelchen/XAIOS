#!/usr/bin/env python3
"""Crash-consistent host implementation of the XAIOS xaiFS volume v1.

The module is intentionally file-offset based. Host files are the reference
backend; the kernel uses the same binary format through a VirtIO block reader.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import fcntl
import hashlib
import json
import os
import stat
import struct
import sys
import uuid
from pathlib import Path
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
MAX_CHUNK_SIZE = 16 * 1024 * 1024
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


def _validate_chunk_size(chunk_size: int) -> None:
    if (
        chunk_size < MIN_CHUNK_SIZE
        or chunk_size > MAX_CHUNK_SIZE
        or chunk_size & (chunk_size - 1)
    ):
        raise ValueError("chunk size must be a 2..16 MiB power of two")


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


def sign_manifest(
    model_uuid: bytes,
    source_revision: bytes,
    architecture_id: str,
    target_id: str,
    logical_size: int,
    chunk_size: int,
    chunks: Iterable[ManifestChunk],
    signing_seed: bytes,
) -> PackageManifest:
    chunk_tuple = tuple(chunks)
    _validate_logical_chunks(logical_size, chunk_size, chunk_tuple)
    identity = package_identity(
        model_uuid,
        source_revision,
        architecture_id,
        target_id,
        logical_size,
        chunk_size,
        chunk_tuple,
    )
    private_key = _private_key_from_seed(signing_seed)
    return PackageManifest(
        model_uuid,
        source_revision,
        architecture_id,
        target_id,
        logical_size,
        chunk_size,
        chunk_tuple,
        identity,
        _public_bytes(private_key),
        private_key.sign(identity),
    )


def manifest_for_file(
    package: Path,
    model_uuid: bytes,
    source_revision: bytes,
    architecture_id: str,
    target_id: str,
    chunk_size: int,
    signing_seed: bytes,
) -> PackageManifest:
    _validate_chunk_size(chunk_size)
    logical_size = package.stat().st_size
    if logical_size <= 0:
        raise ValueError("package is empty")
    chunks = []
    with package.open("rb") as source:
        offset = 0
        while offset < logical_size:
            data = source.read(min(chunk_size, logical_size - offset))
            if not data:
                raise IOError("short package read")
            chunks.append(ManifestChunk(offset, len(data), hashlib.sha256(data).digest()))
            offset += len(data)
    return sign_manifest(
        model_uuid,
        source_revision,
        architecture_id,
        target_id,
        logical_size,
        chunk_size,
        chunks,
        signing_seed,
    )


def sparse_zero_manifest(
    logical_size: int,
    chunk_size: int,
    model_uuid: bytes,
    source_revision: bytes,
    architecture_id: str,
    target_id: str,
    signing_seed: bytes,
) -> PackageManifest:
    _validate_chunk_size(chunk_size)
    chunks = []
    for offset in range(0, logical_size, chunk_size):
        length = min(chunk_size, logical_size - offset)
        chunks.append(ManifestChunk(offset, length, _zero_digest(length), True))
    return sign_manifest(
        model_uuid,
        source_revision,
        architecture_id,
        target_id,
        logical_size,
        chunk_size,
        chunks,
        signing_seed,
    )


class XaiFs:
    def __init__(self, path: Path, read_only: bool = False) -> None:
        self.path = path
        self.read_only = read_only
        self.fd = os.open(path, os.O_RDONLY if read_only else os.O_RDWR)
        self.backing_size = os.fstat(self.fd).st_size
        self.volume_size = self.backing_size
        self.active_slot = 0
        self.generation = 0
        self.catalog_generation = 0
        self.chunk_size = 0
        self.volume_uuid = bytes(16)
        self.catalog_offset = 0
        self.catalog_length = 0
        self.data_tail = DATA_START
        self.records: list[_PackageRecord] = []
        self.chunks: list[_ChunkRecord] = []
        self._open()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "XaiFs":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @classmethod
    def format(
        cls,
        path: Path,
        volume_size: int,
        chunk_size: int = 4 * 1024 * 1024,
        volume_uuid: Optional[bytes] = None,
    ) -> "XaiFs":
        _validate_chunk_size(chunk_size)
        if volume_size < 4 * chunk_size or volume_size >= 1 << 64:
            raise ValueError("xaiFS volume is too small or exceeds 64 bits")
        identity = volume_uuid or uuid.uuid4().bytes
        if len(identity) != 16 or not any(identity):
            raise ValueError("volume UUID must contain 16 nonzero bytes")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.ftruncate(fd, volume_size)
            catalog_offset = 2 * SUPERBLOCK_SIZE
            provisional = _encode_catalog(1, identity, [], [], DATA_START)
            data_tail = max(DATA_START, _align(catalog_offset + len(provisional)))
            catalog = _encode_catalog(1, identity, [], [], data_tail)
            _pwrite_all(fd, catalog, catalog_offset)
            catalog_hash = hashlib.sha256(catalog).digest()
            superblock = _encode_superblock(
                chunk_size,
                volume_size,
                1,
                catalog_offset,
                len(catalog),
                1,
                data_tail,
                identity,
                catalog_hash,
            )
            _pwrite_all(fd, superblock, 0)
            _pwrite_all(fd, superblock, SUPERBLOCK_SIZE)
            os.fsync(fd)
        finally:
            os.close(fd)
        return cls(path)

    def _open(self) -> None:
        candidates = []
        for slot in (0, 1):
            try:
                candidate = _read_candidate(self.fd, self.backing_size, slot)
                candidates.append((candidate[0]["generation"], slot, *candidate))
            except ValueError:
                continue
        if not candidates:
            raise ValueError("no valid xaifs superblock/catalog pair")
        candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
        if (
            len(candidates) > 1
            and candidates[0][0] == candidates[1][0]
            and candidates[0][2]["catalog_hash"] != candidates[1][2]["catalog_hash"]
        ):
            raise ValueError("equal-generation superblocks disagree")
        _, slot, superblock, catalog, records, chunks = candidates[0]
        self.active_slot = slot
        self.volume_size = superblock["volume_size"]
        self.generation = superblock["generation"]
        self.catalog_generation = catalog["generation"]
        self.chunk_size = superblock["chunk_size"]
        self.volume_uuid = superblock["volume_uuid"]
        self.catalog_offset = superblock["catalog_offset"]
        self.catalog_length = superblock["catalog_length"]
        self.data_tail = catalog["data_tail"]
        self.records = records
        self.chunks = chunks

    def _ensure_writable(self) -> None:
        if self.read_only:
            raise PermissionError("xaiFS volume is mounted read-only")

    def _publish(
        self,
        records: list[_PackageRecord],
        chunks: list[_ChunkRecord],
        data_tail: int,
        fail_before_superblock: bool = False,
        volume_size: Optional[int] = None,
    ) -> None:
        self._ensure_writable()
        published_size = self.volume_size if volume_size is None else volume_size
        if published_size > self.backing_size:
            raise ValueError("logical volume exceeds its backing device")
        catalog_generation = self.catalog_generation + 1
        generation = self.generation + 1
        catalog_offset = _align(data_tail)
        provisional = _encode_catalog(
            catalog_generation, self.volume_uuid, records, chunks, 0
        )
        final_tail = _align(catalog_offset + len(provisional))
        _checked_end(catalog_offset, len(provisional), published_size)
        catalog = _encode_catalog(
            catalog_generation, self.volume_uuid, records, chunks, final_tail
        )
        _pwrite_all(self.fd, catalog, catalog_offset)
        os.fsync(self.fd)
        if fail_before_superblock:
            raise InterruptedError("simulated power loss before superblock publication")
        slot = 1 - self.active_slot
        superblock = _encode_superblock(
            self.chunk_size,
            published_size,
            generation,
            catalog_offset,
            len(catalog),
            catalog_generation,
            final_tail,
            self.volume_uuid,
            hashlib.sha256(catalog).digest(),
        )
        _pwrite_all(self.fd, superblock, slot * SUPERBLOCK_SIZE)
        os.fsync(self.fd)
        self.active_slot = slot
        self.generation = generation
        self.catalog_generation = catalog_generation
        self.catalog_offset = catalog_offset
        self.catalog_length = len(catalog)
        self.data_tail = final_tail
        self.volume_size = published_size
        self.records = records
        self.chunks = chunks

    def list_packages(self) -> list[dict[str, object]]:
        return [self.inspect(record.package_id) for record in self.records]

    def _find_record(self, package: bytes | str) -> _PackageRecord:
        package_id = bytes.fromhex(package) if isinstance(package, str) else package
        matches = [record for record in self.records if record.package_id == package_id]
        if len(matches) != 1:
            raise KeyError("package not found")
        return matches[0]

    def _record_chunks(self, record: _PackageRecord) -> list[_ChunkRecord]:
        end = record.chunk_start + record.chunk_count
        if end > len(self.chunks):
            raise ValueError("package chunk range is invalid")
        result = self.chunks[record.chunk_start:end]
        if any(chunk.record_id != record.record_id for chunk in result):
            raise ValueError("package chunk ownership is invalid")
        return result

    def inspect(self, package: bytes | str) -> dict[str, object]:
        record = self._find_record(package)
        chunks = self._record_chunks(record)
        state_names = {
            PACKAGE_STAGING: "staging",
            PACKAGE_ACTIVE: "active",
            PACKAGE_QUARANTINED: "quarantined",
        }
        return {
            "package_id": record.package_id.hex(),
            "model_uuid": record.model_uuid.hex(),
            "architecture_id": record.architecture_id,
            "target_id": record.target_id,
            "state": state_names[record.state],
            "logical_size": record.logical_size,
            "chunk_size": record.chunk_size,
            "chunk_count": record.chunk_count,
            "complete_chunks": sum(bool(chunk.flags & CHUNK_COMPLETE) for chunk in chunks),
            "sparse_zero_chunks": sum(bool(chunk.flags & CHUNK_ZERO) for chunk in chunks),
            "signature_present": any(record.signer_public_key) and any(record.signature),
        }

    def _allocate_extent(
        self, length: int, chunks: list[_ChunkRecord], data_tail: int
    ) -> tuple[int, int]:
        required = _align(length)
        for index, chunk in enumerate(chunks):
            if chunk.flags & CHUNK_FREE and chunk.extent_length >= required:
                physical = chunk.physical_offset
                remaining = chunk.extent_length - required
                if remaining:
                    chunks[index] = _ChunkRecord(
                        0,
                        0,
                        physical + required,
                        remaining,
                        CHUNK_COMPLETE | CHUNK_FREE,
                        bytes(32),
                        remaining,
                    )
                else:
                    del chunks[index]
                return physical, data_tail
        physical = _align(data_tail, self.chunk_size)
        end = _checked_end(physical, required, self.volume_size)
        return physical, end

    def stage_begin(self, manifest: PackageManifest) -> bytes:
        self._ensure_writable()
        if manifest.chunk_size != self.chunk_size:
            raise ValueError("package chunk size does not match the volume")
        if not manifest.verify_signature():
            raise ValueError("package manifest signature is invalid")
        if any(record.package_id == manifest.package_id for record in self.records):
            raise ValueError("package is already registered")
        records = [dataclasses.replace(record) for record in self.records]
        chunks = [dataclasses.replace(chunk) for chunk in self.chunks]
        record_id = max((record.record_id for record in records), default=0) + 1
        data_tail = self.data_tail
        owned = []
        for expected in manifest.chunks:
            flags = CHUNK_COMPLETE | CHUNK_ZERO if expected.zero else 0
            physical = 0
            extent_length = 0
            if not expected.zero:
                physical, data_tail = self._allocate_extent(expected.length, chunks, data_tail)
                extent_length = _align(expected.length)
            owned.append(
                _ChunkRecord(
                    record_id,
                    expected.logical_offset,
                    physical,
                    expected.length,
                    flags,
                    expected.checksum,
                    extent_length,
                )
            )
        _reindex_records(records, chunks)
        chunk_start = len(chunks)
        chunks.extend(owned)
        records.append(
            _PackageRecord(
                PACKAGE_STAGING,
                0,
                record_id,
                manifest.model_uuid,
                manifest.package_id,
                manifest.signer_public_key,
                manifest.signature,
                manifest.source_revision,
                manifest.logical_size,
                manifest.chunk_size,
                chunk_start,
                len(owned),
                manifest.architecture_id,
                manifest.target_id,
            )
        )
        self._publish(records, chunks, data_tail)
        return manifest.package_id

    def pwrite(self, package: bytes | str, offset: int, data: bytes) -> None:
        self._ensure_writable()
        record = self._find_record(package)
        if record.state != PACKAGE_STAGING:
            raise PermissionError("activated packages are immutable")
        matches = [
            chunk
            for chunk in self._record_chunks(record)
            if chunk.logical_offset == offset
        ]
        if len(matches) != 1:
            raise ValueError("write offset is not a chunk boundary")
        chunk = matches[0]
        if chunk.flags & CHUNK_ZERO:
            if data != bytes(chunk.length):
                raise ValueError("sparse-zero chunk must remain zero")
            return
        if len(data) != chunk.length or hashlib.sha256(data).digest() != chunk.checksum:
            raise ValueError("chunk length or checksum mismatch")
        if chunk.flags & CHUNK_COMPLETE:
            return
        _pwrite_all(self.fd, data, chunk.physical_offset)
        os.fsync(self.fd)
        records = [dataclasses.replace(item) for item in self.records]
        chunks = [dataclasses.replace(item) for item in self.chunks]
        for item in chunks:
            if item.record_id == record.record_id and item.logical_offset == offset:
                item.flags |= CHUNK_COMPLETE
                break
        self._publish(records, chunks, self.data_tail)

    def pwrite_from_file(self, package: bytes | str, source_path: Path) -> None:
        record = self._find_record(package)
        if source_path.stat().st_size != record.logical_size:
            raise ValueError("source package size changed")
        with source_path.open("rb") as source:
            for chunk in self._record_chunks(record):
                if chunk.flags & CHUNK_COMPLETE:
                    continue
                source.seek(chunk.logical_offset)
                data = source.read(chunk.length)
                if len(data) != chunk.length:
                    raise IOError("short package source read")
                self.pwrite(record.package_id, chunk.logical_offset, data)

    def pread(self, package: bytes | str, offset: int, length: int) -> bytes:
        record = self._find_record(package)
        if record.state == PACKAGE_QUARANTINED:
            raise PermissionError("quarantined packages are unavailable")
        _checked_end(offset, length, record.logical_size)
        if length == 0:
            return b""
        result = bytearray()
        remaining = length
        cursor = offset
        for chunk in self._record_chunks(record):
            chunk_end = chunk.logical_offset + chunk.length
            if cursor >= chunk_end or cursor < chunk.logical_offset:
                continue
            if not chunk.flags & CHUNK_COMPLETE:
                raise IOError("requested staging chunk is incomplete")
            within = cursor - chunk.logical_offset
            count = min(remaining, chunk.length - within)
            if chunk.flags & CHUNK_ZERO:
                result.extend(bytes(count))
            else:
                data = os.pread(self.fd, count, chunk.physical_offset + within)
                if len(data) != count:
                    raise IOError("short volume read")
                result.extend(data)
            cursor += count
            remaining -= count
            if remaining == 0:
                break
        if remaining:
            raise ValueError("package extent map has a gap")
        return bytes(result)

    def extent_map(self, package: bytes | str) -> list[Extent]:
        record = self._find_record(package)
        if record.state == PACKAGE_QUARANTINED:
            raise PermissionError("quarantined packages are unavailable")
        return [
            Extent(
                chunk.logical_offset,
                chunk.physical_offset,
                chunk.length,
                bool(chunk.flags & CHUNK_ZERO),
            )
            for chunk in self._record_chunks(record)
        ]

    def prefetch(self, package: bytes | str, offset: int, length: int) -> None:
        _checked_end(offset, length, self._find_record(package).logical_size)
        if not hasattr(os, "posix_fadvise") or length == 0:
            return
        end = offset + length
        for extent in self.extent_map(package):
            extent_end = extent.logical_offset + extent.length
            if extent.zero or extent_end <= offset or extent.logical_offset >= end:
                continue
            start = max(offset, extent.logical_offset)
            finish = min(end, extent_end)
            os.posix_fadvise(
                self.fd,
                extent.physical_offset + start - extent.logical_offset,
                finish - start,
                os.POSIX_FADV_WILLNEED,
            )

    def _verify_record(self, record: _PackageRecord) -> None:
        chunks = self._record_chunks(record)
        manifest_chunks = []
        for chunk in chunks:
            if not chunk.flags & CHUNK_COMPLETE:
                raise XaiFsIntegrityError(
                    record.package_id, chunk.logical_offset, "chunk is incomplete"
                )
            if chunk.flags & CHUNK_ZERO:
                digest = _zero_digest(chunk.length)
            else:
                digest = hashlib.sha256()
                remaining = chunk.length
                cursor = chunk.physical_offset
                while remaining:
                    data = os.pread(self.fd, min(remaining, 1024 * 1024), cursor)
                    if not data:
                        raise IOError("short chunk verification read")
                    digest.update(data)
                    remaining -= len(data)
                    cursor += len(data)
                digest = digest.digest()
            if digest != chunk.checksum:
                raise XaiFsIntegrityError(
                    record.package_id, chunk.logical_offset, "chunk checksum mismatch"
                )
            manifest_chunks.append(
                ManifestChunk(
                    chunk.logical_offset,
                    chunk.length,
                    chunk.checksum,
                    bool(chunk.flags & CHUNK_ZERO),
                )
            )
        identity = package_identity(
            record.model_uuid,
            record.source_revision,
            record.architecture_id,
            record.target_id,
            record.logical_size,
            record.chunk_size,
            manifest_chunks,
        )
        if identity != record.package_id or not verify_ed25519(
            record.signer_public_key, record.signature, identity
        ):
            raise XaiFsIntegrityError(
                record.package_id, None, "identity or Ed25519 signature is invalid"
            )

    def stage_verify(self, package: bytes | str) -> None:
        self._verify_record(self._find_record(package))

    def activate(
        self, package: bytes | str, fail_before_superblock: bool = False
    ) -> None:
        self._ensure_writable()
        record = self._find_record(package)
        if record.state != PACKAGE_STAGING:
            raise ValueError("package is not staged")
        self.stage_verify(record.package_id)
        for other in self.records:
            if other.state == PACKAGE_ACTIVE and other.model_uuid == record.model_uuid:
                raise ValueError("an active package already owns this model UUID")
        records = [dataclasses.replace(item) for item in self.records]
        for item in records:
            if item.record_id == record.record_id:
                item.state = PACKAGE_ACTIVE
                break
        chunks = [dataclasses.replace(item) for item in self.chunks]
        self._publish(records, chunks, self.data_tail, fail_before_superblock)

    def remove(self, package: bytes | str, allow_active: bool = False) -> None:
        self._ensure_writable()
        record = self._find_record(package)
        if record.state == PACKAGE_ACTIVE and not allow_active:
            raise PermissionError("active package removal requires explicit deactivation")
        owned_ids = {
            (chunk.record_id, chunk.logical_offset)
            for chunk in self._record_chunks(record)
        }
        records = [item for item in self.records if item.record_id != record.record_id]
        retained = []
        free = []
        for chunk in self.chunks:
            if (chunk.record_id, chunk.logical_offset) not in owned_ids:
                if chunk.flags & CHUNK_FREE:
                    free.append((chunk.physical_offset, chunk.extent_length))
                else:
                    retained.append(dataclasses.replace(chunk))
            elif chunk.physical_offset and chunk.extent_length:
                free.append((chunk.physical_offset, chunk.extent_length))
        for physical, length in _coalesce_extents(free):
            retained.append(
                _ChunkRecord(
                    0,
                    0,
                    physical,
                    length,
                    CHUNK_COMPLETE | CHUNK_FREE,
                    bytes(32),
                    length,
                )
            )
        _reindex_records(records, retained)
        self._publish(records, retained, self.data_tail)

    def recover(self, drop_incomplete: bool = False) -> dict[str, int]:
        if drop_incomplete:
            self._ensure_writable()
        incomplete = []
        for record in self.records:
            if record.state == PACKAGE_STAGING and any(
                not chunk.flags & CHUNK_COMPLETE
                for chunk in self._record_chunks(record)
            ):
                incomplete.append(record.package_id)
        if drop_incomplete:
            for package_id in incomplete:
                self.remove(package_id)
        return {
            "generation": self.generation,
            "catalog_generation": self.catalog_generation,
            "active_packages": sum(record.state == PACKAGE_ACTIVE for record in self.records),
            "staging_packages": sum(record.state == PACKAGE_STAGING for record in self.records),
            "quarantined_packages": sum(
                record.state == PACKAGE_QUARANTINED for record in self.records
            ),
            "incomplete_staging": len(incomplete),
        }

    def usage(self) -> dict[str, int | str]:
        allocated = sum(
            chunk.extent_length
            for chunk in self.chunks
            if not chunk.flags & CHUNK_FREE
        )
        reusable = sum(
            chunk.extent_length for chunk in self.chunks if chunk.flags & CHUNK_FREE
        )
        staging = 0
        for record in self.records:
            if record.state == PACKAGE_STAGING:
                staging += sum(
                    chunk.extent_length for chunk in self._record_chunks(record)
                )
        tail_free = self.volume_size - self.data_tail
        return {
            "schema": "xaios.xaifs.usage.v1",
            "volume_uuid": self.volume_uuid.hex(),
            "format_version": f"{VERSION_MAJOR}.{VERSION_MINOR}",
            "total_bytes": self.volume_size,
            "backing_bytes": self.backing_size,
            "allocated_data_bytes": allocated,
            "reusable_extent_bytes": reusable,
            "tail_free_bytes": tail_free,
            "available_bytes": reusable + tail_free,
            "committed_metadata_and_extent_bytes": self.data_tail - allocated,
            "reclaimable_staging_bytes": staging,
            "package_count": len(self.records),
            "active_packages": sum(
                record.state == PACKAGE_ACTIVE for record in self.records
            ),
            "staging_packages": sum(
                record.state == PACKAGE_STAGING for record in self.records
            ),
            "quarantined_packages": sum(
                record.state == PACKAGE_QUARANTINED for record in self.records
            ),
            "free_extent_count": sum(
                bool(chunk.flags & CHUNK_FREE) for chunk in self.chunks
            ),
        }

    def grow(self, new_size: int, fail_before_superblock: bool = False) -> None:
        self._ensure_writable()
        if new_size < self.volume_size:
            raise ValueError("shrink_not_supported")
        if new_size == self.volume_size:
            return
        if new_size >= 1 << 64:
            raise ValueError("volume size exceeds 64 bits")
        if new_size < self.data_tail:
            raise ValueError("grown volume would not contain committed metadata")
        if new_size > self.backing_size:
            os.ftruncate(self.fd, new_size)
            os.fsync(self.fd)
            self.backing_size = new_size
        records = [dataclasses.replace(record) for record in self.records]
        chunks = [dataclasses.replace(chunk) for chunk in self.chunks]
        self._publish(
            records,
            chunks,
            self.data_tail,
            fail_before_superblock=fail_before_superblock,
            volume_size=new_size,
        )

    def scrub(self, quarantine: bool = True) -> dict[str, object]:
        if quarantine:
            self._ensure_writable()
        errors = []
        checked_bytes = 0
        skipped_staging = 0
        damaged_ids = set()
        for record in self.records:
            owned = self._record_chunks(record)
            if record.state == PACKAGE_STAGING and any(
                not chunk.flags & CHUNK_COMPLETE for chunk in owned
            ):
                skipped_staging += 1
                continue
            checked_bytes += record.logical_size
            try:
                self._verify_record(record)
            except XaiFsIntegrityError as error:
                damaged_ids.add(record.record_id)
                errors.append(
                    {
                        "package_id": error.package_id.hex(),
                        "logical_offset": error.logical_offset,
                        "reason": error.reason,
                    }
                )
        newly_quarantined = 0
        if damaged_ids and quarantine:
            records = [dataclasses.replace(record) for record in self.records]
            for record in records:
                if (
                    record.record_id in damaged_ids
                    and record.state != PACKAGE_QUARANTINED
                ):
                    record.state = PACKAGE_QUARANTINED
                    newly_quarantined += 1
            if newly_quarantined:
                self._publish(
                    records,
                    [dataclasses.replace(chunk) for chunk in self.chunks],
                    self.data_tail,
                )
        return {
            "schema": "xaios.xaifs.scrub.v1",
            "status": "corrupt" if errors else "clean",
            "generation": self.generation,
            "checked_packages": len(self.records) - skipped_staging,
            "checked_bytes": checked_bytes,
            "skipped_incomplete_staging": skipped_staging,
            "newly_quarantined": newly_quarantined,
            "errors": errors,
        }

    def trim_plan(self) -> list[dict[str, int]]:
        extents = [
            (chunk.physical_offset, chunk.extent_length)
            for chunk in self.chunks
            if chunk.flags & CHUNK_FREE
        ]
        if self.data_tail < self.volume_size:
            extents.append((self.data_tail, self.volume_size - self.data_tail))
        return [
            {"offset": offset, "length": length}
            for offset, length in _coalesce_extents(extents)
            if length
        ]

    def trim(
        self,
        discard=None,
        *,
        dry_run: bool = False,
        requested_range: Optional[tuple[int, int]] = None,
        granularity: int = BLOCK_SIZE,
        maximum_request: int = 1024 * 1024 * 1024,
        cancelled=None,
    ) -> dict[str, object]:
        if not dry_run:
            self._ensure_writable()
        if (
            granularity <= 0
            or granularity & (granularity - 1)
            or maximum_request < granularity
            or maximum_request % granularity
        ):
            raise ValueError("invalid discard geometry")
        generation = self.generation
        free = [
            (item["offset"], item["length"])
            for item in self.trim_plan()
        ]
        if requested_range is not None:
            requested_offset, requested_length = requested_range
            requested_end = _checked_end(
                requested_offset, requested_length, self.volume_size
            )
            if requested_length == 0 or not any(
                requested_offset >= offset
                and requested_end <= offset + length
                for offset, length in free
            ):
                raise PermissionError("requested discard range is not entirely free")
            free = [(requested_offset, requested_length)]
        requests = []
        for offset, length in free:
            start = _align(offset, granularity)
            end = (offset + length) & ~(granularity - 1)
            while start < end:
                count = min(end - start, maximum_request)
                requests.append({"offset": start, "length": count})
                start += count
        result: dict[str, object] = {
            "schema": "xaios.xaifs.trim.v1",
            "status": "planned" if dry_run else "complete",
            "volume_uuid": self.volume_uuid.hex(),
            "generation": generation,
            "ranges_planned": len(requests),
            "bytes_planned": sum(item["length"] for item in requests),
            "ranges_trimmed": 0,
            "bytes_trimmed": 0,
            "requests": requests,
        }
        if dry_run or not requests:
            return result
        if discard is None:
            discard = _host_discard(self.fd)
        if discard is None:
            result["status"] = "unsupported"
            return result
        os.fsync(self.fd)
        for request in requests:
            if cancelled is not None and cancelled():
                result["status"] = "cancelled"
                break
            if self.generation != generation:
                raise RuntimeError("filesystem generation changed during trim")
            discard(request["offset"], request["length"])
            result["ranges_trimmed"] = int(result["ranges_trimmed"]) + 1
            result["bytes_trimmed"] = int(result["bytes_trimmed"]) + request["length"]
        return result

    def repair_superblock(self, confirm_volume_uuid: bytes | str) -> bool:
        self._ensure_writable()
        confirmation = (
            bytes.fromhex(confirm_volume_uuid)
            if isinstance(confirm_volume_uuid, str)
            else confirm_volume_uuid
        )
        if confirmation != self.volume_uuid:
            raise PermissionError("volume UUID confirmation mismatch")
        valid = []
        for slot in (0, 1):
            try:
                valid.append((slot, _read_candidate(self.fd, self.backing_size, slot)))
            except ValueError:
                pass
        if len(valid) == 2:
            return False
        if len(valid) != 1:
            raise ValueError("corrupt_unrepairable")
        source_slot, candidate = valid[0]
        if candidate[0]["volume_uuid"] != self.volume_uuid:
            raise ValueError("selected superblock identity changed")
        target_slot = 1 - source_slot
        raw = os.pread(self.fd, SUPERBLOCK_SIZE, source_slot * SUPERBLOCK_SIZE)
        if len(raw) != SUPERBLOCK_SIZE:
            raise IOError("short superblock repair read")
        _pwrite_all(self.fd, raw, target_slot * SUPERBLOCK_SIZE)
        os.fsync(self.fd)
        _read_candidate(self.fd, self.backing_size, target_slot)
        return True

    @classmethod
    def fsck(cls, path: Path, verify_data: bool = False) -> dict[str, object]:
        fd = os.open(path, os.O_RDONLY)
        try:
            backing_size = os.fstat(fd).st_size
            valid = []
            invalid = []
            for slot in (0, 1):
                try:
                    valid.append((slot, _read_candidate(fd, backing_size, slot)))
                except ValueError as error:
                    invalid.append({"slot": slot, "reason": str(error)})
        finally:
            os.close(fd)
        if not valid:
            return {
                "schema": "xaios.xaifs.fsck.v1",
                "status": "corrupt_unrepairable",
                "valid_superblocks": 0,
                "invalid_superblocks": invalid,
                "errors": ["no valid superblock/catalog generation"],
            }
        valid.sort(key=lambda item: (item[1][0]["generation"], item[0]), reverse=True)
        selected = valid[0][1]
        errors = []
        checked_bytes = 0
        if verify_data:
            with cls(path, read_only=True) as volume:
                for record in volume.records:
                    if record.state == PACKAGE_STAGING and any(
                        not chunk.flags & CHUNK_COMPLETE
                        for chunk in volume._record_chunks(record)
                    ):
                        continue
                    checked_bytes += record.logical_size
                    try:
                        volume._verify_record(record)
                    except XaiFsIntegrityError as error:
                        errors.append(
                            {
                                "package_id": error.package_id.hex(),
                                "logical_offset": error.logical_offset,
                                "reason": error.reason,
                            }
                        )
        status = "corrupt_unrepairable" if errors else (
            "repairable" if len(valid) == 1 else "clean"
        )
        return {
            "schema": "xaios.xaifs.fsck.v1",
            "status": status,
            "volume_uuid": selected[0]["volume_uuid"].hex(),
            "generation": selected[0]["generation"],
            "catalog_generation": selected[1]["generation"],
            "valid_superblocks": len(valid),
            "invalid_superblocks": invalid,
            "package_count": len(selected[2]),
            "chunk_count": len(selected[3]),
            "checked_bytes": checked_bytes,
            "errors": errors,
        }

    def sync(self) -> None:
        os.fsync(self.fd)


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


def _host_discard(fd: int):
    mode = os.fstat(fd).st_mode
    if stat.S_ISBLK(mode) and os.name == "posix" and sys.platform.startswith("linux"):
        def block_discard(offset: int, length: int) -> None:
            fcntl.ioctl(fd, 0x1277, struct.pack("QQ", offset, length))

        return block_discard
    if stat.S_ISREG(mode) and sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        fallocate = getattr(libc, "fallocate", None)
        if fallocate is None:
            return None
        fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong,
                              ctypes.c_longlong]
        fallocate.restype = ctypes.c_int

        def punch_hole(offset: int, length: int) -> None:
            if fallocate(fd, 0x03, offset, length) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))

        return punch_hole
    return None


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


def _encode_superblock(
    chunk_size: int,
    volume_size: int,
    generation: int,
    catalog_offset: int,
    catalog_length: int,
    catalog_generation: int,
    data_tail: int,
    volume_uuid: bytes,
    catalog_hash: bytes,
) -> bytes:
    raw = bytearray(SUPERBLOCK_SIZE)
    raw[:8] = MAGIC
    struct.pack_into("<HHBBH", raw, 8, VERSION_MAJOR, VERSION_MINOR, ENDIAN_LITTLE, HASH_SHA256, 0)
    struct.pack_into(
        "<QQQQQQQQ",
        raw,
        16,
        SUPERBLOCK_SIZE,
        BLOCK_SIZE,
        chunk_size,
        volume_size,
        generation,
        catalog_offset,
        catalog_length,
        catalog_generation,
    )
    struct.pack_into("<Q", raw, 80, data_tail)
    raw[88:104] = volume_uuid
    raw[104:136] = catalog_hash
    raw[136:168] = hashlib.sha256(raw).digest()
    return bytes(raw)


def _decode_superblock(raw: bytes, actual_size: int) -> dict[str, object]:
    if len(raw) != SUPERBLOCK_SIZE or raw[:8] != MAGIC:
        raise ValueError("invalid xaifs superblock")
    expected_hash = raw[136:168]
    checked = bytearray(raw)
    checked[136:168] = bytes(32)
    if hashlib.sha256(checked).digest() != expected_hash:
        raise ValueError("superblock checksum mismatch")
    major, minor, endian, hash_algorithm, flags = struct.unpack_from("<HHBBH", raw, 8)
    values = struct.unpack_from("<QQQQQQQQQ", raw, 16)
    if (
        major != VERSION_MAJOR
        or minor != VERSION_MINOR
        or endian != ENDIAN_LITTLE
        or hash_algorithm != HASH_SHA256
        or flags != 0
        or values[0] != SUPERBLOCK_SIZE
        or values[1] != BLOCK_SIZE
        or values[3] > actual_size
        or values[3] < 4 * values[2]
        or values[4] == 0
        or values[7] == 0
        or not any(raw[88:104])
        or any(raw[168:])
    ):
        raise ValueError("unsupported or malformed superblock")
    _validate_chunk_size(values[2])
    if values[5] & (BLOCK_SIZE - 1) or values[6] == 0:
        raise ValueError("unaligned or empty catalog")
    _checked_end(values[5], values[6], actual_size)
    if values[8] < DATA_START or values[8] > actual_size:
        raise ValueError("invalid allocator tail")
    return {
        "chunk_size": values[2],
        "volume_size": values[3],
        "generation": values[4],
        "catalog_offset": values[5],
        "catalog_length": values[6],
        "catalog_generation": values[7],
        "data_tail": values[8],
        "volume_uuid": raw[88:104],
        "catalog_hash": raw[104:136],
    }


def _encode_catalog(
    generation: int,
    volume_uuid: bytes,
    records: list[_PackageRecord],
    chunks: list[_ChunkRecord],
    data_tail: int,
) -> bytes:
    record_offset = CATALOG_HEADER_SIZE
    chunk_offset = record_offset + len(records) * PACKAGE_RECORD_SIZE
    length = chunk_offset + len(chunks) * CHUNK_RECORD_SIZE
    raw = bytearray(length)
    raw[:8] = CATALOG_MAGIC
    struct.pack_into("<HHBBH", raw, 8, VERSION_MAJOR, VERSION_MINOR, ENDIAN_LITTLE, HASH_SHA256, 0)
    struct.pack_into("<QQ", raw, 16, CATALOG_HEADER_SIZE, generation)
    raw[32:48] = volume_uuid
    struct.pack_into(
        "<QQQQQQQQQQQ",
        raw,
        48,
        PACKAGE_RECORD_SIZE,
        len(records),
        CHUNK_RECORD_SIZE,
        len(chunks),
        record_offset,
        chunk_offset,
        length,
        0,
        data_tail,
        sum(bool(chunk.flags & CHUNK_FREE) for chunk in chunks),
        0,
    )
    for index, record in enumerate(records):
        start = record_offset + index * PACKAGE_RECORD_SIZE
        struct.pack_into("<IIQ", raw, start, record.state, record.flags, record.record_id)
        raw[start + 16 : start + 32] = record.model_uuid
        raw[start + 32 : start + 64] = record.package_id
        raw[start + 64 : start + 96] = record.signer_public_key
        raw[start + 96 : start + 160] = record.signature
        raw[start + 160 : start + 192] = record.source_revision
        struct.pack_into(
            "<QQQQ",
            raw,
            start + 192,
            record.logical_size,
            record.chunk_size,
            record.chunk_start,
            record.chunk_count,
        )
        raw[start + 224 : start + 256] = _fixed_ascii(record.architecture_id, 32, "architecture ID")
        raw[start + 256 : start + 288] = _fixed_ascii(record.target_id, 32, "target ID")
    for index, chunk in enumerate(chunks):
        start = chunk_offset + index * CHUNK_RECORD_SIZE
        struct.pack_into(
            "<QQQQII",
            raw,
            start,
            chunk.record_id,
            chunk.logical_offset,
            chunk.physical_offset,
            chunk.length,
            chunk.flags,
            0,
        )
        raw[start + 40 : start + 72] = chunk.checksum
        struct.pack_into("<Q", raw, start + 72, chunk.extent_length)
    checked = bytearray(raw[:CATALOG_HEADER_SIZE])
    checked[144:176] = bytes(32)
    raw[144:176] = hashlib.sha256(checked).digest()
    return bytes(raw)


def _decode_ascii(raw: bytes, field: str) -> str:
    value = raw.split(b"\0", 1)[0]
    if not value or any(raw[len(value) + 1 :]):
        raise ValueError(f"invalid {field}")
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"invalid {field}") from error


def _decode_catalog(
    raw: bytes, volume_uuid: bytes, volume_size: int
) -> tuple[list[_PackageRecord], list[_ChunkRecord], dict[str, int]]:
    if len(raw) < CATALOG_HEADER_SIZE or raw[:8] != CATALOG_MAGIC:
        raise ValueError("invalid catalog header")
    major, minor, endian, hash_algorithm, flags = struct.unpack_from("<HHBBH", raw, 8)
    header_size, generation = struct.unpack_from("<QQ", raw, 16)
    values = struct.unpack_from("<QQQQQQQQQQQ", raw, 48)
    if (
        major != VERSION_MAJOR
        or minor != VERSION_MINOR
        or endian != ENDIAN_LITTLE
        or hash_algorithm != HASH_SHA256
        or flags != 0
        or header_size != CATALOG_HEADER_SIZE
        or generation == 0
        or raw[32:48] != volume_uuid
        or values[0] != PACKAGE_RECORD_SIZE
        or values[2] != CHUNK_RECORD_SIZE
        or values[4] != CATALOG_HEADER_SIZE
        or values[6] != len(raw)
        or values[7] != 0
        or values[8] < DATA_START
        or values[8] > volume_size
        or values[10] != 0
        or any(raw[176:CATALOG_HEADER_SIZE])
    ):
        raise ValueError("unsupported or malformed catalog")
    checked = bytearray(raw[:CATALOG_HEADER_SIZE])
    expected = bytes(checked[144:176])
    checked[144:176] = bytes(32)
    if hashlib.sha256(checked).digest() != expected:
        raise ValueError("catalog header checksum mismatch")
    record_count = values[1]
    chunk_count = values[3]
    record_offset = values[4]
    chunk_offset = values[5]
    expected_chunk_offset = record_offset + record_count * PACKAGE_RECORD_SIZE
    expected_length = expected_chunk_offset + chunk_count * CHUNK_RECORD_SIZE
    if expected_chunk_offset >= 1 << 64 or expected_length != len(raw) or chunk_offset != expected_chunk_offset:
        raise ValueError("catalog directory range is invalid")
    records = []
    for index in range(record_count):
        start = record_offset + index * PACKAGE_RECORD_SIZE
        state, record_flags, record_id = struct.unpack_from("<IIQ", raw, start)
        logical_size, chunk_size, chunk_start, owned_count = struct.unpack_from("<QQQQ", raw, start + 192)
        if (
            state not in (PACKAGE_STAGING, PACKAGE_ACTIVE, PACKAGE_QUARANTINED)
            or record_flags != 0
            or record_id == 0
            or not any(raw[start + 16 : start + 32])
            or not any(raw[start + 32 : start + 64])
            or not any(raw[start + 64 : start + 96])
            or not any(raw[start + 96 : start + 160])
            or not any(raw[start + 160 : start + 192])
            or chunk_start + owned_count > chunk_count
            or chunk_start + owned_count >= 1 << 64
            or logical_size == 0
            or any(raw[start + 288 : start + PACKAGE_RECORD_SIZE])
        ):
            raise ValueError("invalid package record")
        _validate_chunk_size(chunk_size)
        target_id = _decode_ascii(raw[start + 256 : start + 288], "target ID")
        if target_id not in TARGETS:
            raise ValueError("unknown package target")
        records.append(
            _PackageRecord(
                state,
                record_flags,
                record_id,
                raw[start + 16 : start + 32],
                raw[start + 32 : start + 64],
                raw[start + 64 : start + 96],
                raw[start + 96 : start + 160],
                raw[start + 160 : start + 192],
                logical_size,
                chunk_size,
                chunk_start,
                owned_count,
                _decode_ascii(raw[start + 224 : start + 256], "architecture ID"),
                target_id,
            )
        )
    chunks = []
    for index in range(chunk_count):
        start = chunk_offset + index * CHUNK_RECORD_SIZE
        record_id, logical, physical, length, chunk_flags, reserved = struct.unpack_from("<QQQQII", raw, start)
        extent_length = struct.unpack_from("<Q", raw, start + 72)[0]
        checksum = raw[start + 40 : start + 72]
        if (
            reserved != 0
            or chunk_flags & ~(CHUNK_COMPLETE | CHUNK_ZERO | CHUNK_FREE)
            or any(raw[start + 80 : start + CHUNK_RECORD_SIZE])
            or length == 0
        ):
            raise ValueError("invalid chunk record")
        if chunk_flags & CHUNK_FREE:
            if record_id != 0 or logical != 0 or physical == 0 or checksum != bytes(32) or extent_length != length:
                raise ValueError("invalid free extent")
        else:
            if record_id == 0 or not any(checksum):
                raise ValueError("invalid package chunk")
            if chunk_flags & CHUNK_ZERO:
                if physical != 0 or extent_length != 0 or not chunk_flags & CHUNK_COMPLETE:
                    raise ValueError("invalid sparse-zero chunk")
            else:
                if (
                    physical < DATA_START
                    or physical & (BLOCK_SIZE - 1)
                    or extent_length < length
                    or extent_length & (BLOCK_SIZE - 1)
                ):
                    raise ValueError("invalid physical chunk extent")
                if _checked_end(physical, extent_length, volume_size) > values[8]:
                    raise ValueError("physical chunk exceeds the allocator tail")
        chunks.append(_ChunkRecord(record_id, logical, physical, length, chunk_flags, checksum, extent_length))
    free_count = sum(bool(chunk.flags & CHUNK_FREE) for chunk in chunks)
    if free_count != values[9]:
        raise ValueError("catalog free-extent count mismatch")
    record_ids = [record.record_id for record in records]
    package_ids = [record.package_id for record in records]
    if len(set(record_ids)) != len(record_ids) or len(set(package_ids)) != len(package_ids):
        raise ValueError("duplicate package record identity")
    active_models = [
        record.model_uuid for record in records if record.state == PACKAGE_ACTIVE
    ]
    if len(set(active_models)) != len(active_models):
        raise ValueError("multiple active packages own one model UUID")
    claimed_chunk_indexes: set[int] = set()
    for record in records:
        owned = chunks[record.chunk_start : record.chunk_start + record.chunk_count]
        indexes = set(range(record.chunk_start, record.chunk_start + record.chunk_count))
        if claimed_chunk_indexes & indexes:
            raise ValueError("package chunk ranges overlap")
        claimed_chunk_indexes.update(indexes)
        if any(chunk.record_id != record.record_id for chunk in owned):
            raise ValueError("package chunk ownership mismatch")
        if record.state == PACKAGE_ACTIVE and any(
            not chunk.flags & CHUNK_COMPLETE for chunk in owned
        ):
            raise ValueError("active package contains an incomplete chunk")
        manifest = tuple(
            ManifestChunk(chunk.logical_offset, chunk.length, chunk.checksum, bool(chunk.flags & CHUNK_ZERO))
            for chunk in owned
        )
        _validate_logical_chunks(record.logical_size, record.chunk_size, manifest)
        if package_identity(
            record.model_uuid,
            record.source_revision,
            record.architecture_id,
            record.target_id,
            record.logical_size,
            record.chunk_size,
            manifest,
        ) != record.package_id:
            raise ValueError("catalog package identity mismatch")
        if not verify_ed25519(
            record.signer_public_key, record.signature, record.package_id
        ):
            raise ValueError("catalog package signature mismatch")
    owned_indexes = {
        index for index, chunk in enumerate(chunks) if not chunk.flags & CHUNK_FREE
    }
    if claimed_chunk_indexes != owned_indexes:
        raise ValueError("catalog contains unclaimed package chunks")
    extents = sorted(
        (chunk.physical_offset, chunk.physical_offset + chunk.extent_length)
        for chunk in chunks
        if chunk.physical_offset
    )
    if any(left[1] > right[0] for left, right in zip(extents, extents[1:])):
        raise ValueError("physical chunk extents overlap")
    return records, chunks, {"generation": generation, "data_tail": values[8]}


def _read_candidate(
    fd: int, backing_size: int, slot: int
) -> tuple[
    dict[str, object],
    dict[str, int],
    list[_PackageRecord],
    list[_ChunkRecord],
]:
    raw = os.pread(fd, SUPERBLOCK_SIZE, slot * SUPERBLOCK_SIZE)
    superblock = _decode_superblock(raw, backing_size)
    catalog_raw = os.pread(
        fd, superblock["catalog_length"], superblock["catalog_offset"]
    )
    if len(catalog_raw) != superblock["catalog_length"]:
        raise ValueError("short catalog read")
    if hashlib.sha256(catalog_raw).digest() != superblock["catalog_hash"]:
        raise ValueError("catalog checksum mismatch")
    records, chunks, catalog = _decode_catalog(
        catalog_raw, superblock["volume_uuid"], superblock["volume_size"]
    )
    if catalog["generation"] != superblock["catalog_generation"]:
        raise ValueError("catalog generation mismatch")
    if catalog["data_tail"] != superblock["data_tail"]:
        raise ValueError("allocator tail disagrees between metadata copies")
    if any(record.chunk_size != superblock["chunk_size"] for record in records):
        raise ValueError("package chunk size does not match the volume")
    catalog_start = superblock["catalog_offset"]
    catalog_end = catalog_start + superblock["catalog_length"]
    for chunk in chunks:
        if not chunk.physical_offset:
            continue
        chunk_end = chunk.physical_offset + chunk.extent_length
        if chunk.physical_offset < catalog_end and chunk_end > catalog_start:
            raise ValueError("physical chunk overlaps the committed catalog")
    return superblock, catalog, records, chunks


def _load_manifest(path: Path) -> PackageManifest:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return PackageManifest.from_json(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage XAIOS xaifs v1 files")
    commands = parser.add_subparsers(dest="command", required=True)
    format_parser = commands.add_parser("format")
    format_parser.add_argument("volume", type=Path)
    format_parser.add_argument("--size", type=int, required=True)
    format_parser.add_argument("--chunk-size", type=int, default=4 * 1024 * 1024)
    format_parser.add_argument("--volume-uuid")
    format_parser.add_argument("--confirm-path", required=True)
    list_parser = commands.add_parser("list")
    list_parser.add_argument("volume", type=Path)
    stage = commands.add_parser("stage")
    stage.add_argument("volume", type=Path)
    stage.add_argument("package", type=Path)
    stage.add_argument("manifest", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("volume", type=Path)
    inspect.add_argument("package_id")
    verify = commands.add_parser("verify")
    verify.add_argument("volume", type=Path)
    verify.add_argument("package_id")
    activate = commands.add_parser("activate")
    activate.add_argument("volume", type=Path)
    activate.add_argument("package_id")
    remove = commands.add_parser("remove")
    remove.add_argument("volume", type=Path)
    remove.add_argument("package_id")
    remove.add_argument("--confirm-package", required=True)
    remove.add_argument("--allow-active", action="store_true")
    recover = commands.add_parser("recover")
    recover.add_argument("volume", type=Path)
    recover.add_argument("--drop-incomplete", action="store_true")
    recover.add_argument("--confirm-volume")
    usage = commands.add_parser("usage")
    usage.add_argument("volume", type=Path)
    resize = commands.add_parser("resize")
    resize.add_argument("volume", type=Path)
    resize.add_argument("--grow-to", type=int, required=True)
    resize.add_argument("--confirm-volume", required=True)
    resize_plan = commands.add_parser("resize-plan")
    resize_plan.add_argument("volume", type=Path)
    resize_plan.add_argument("--grow-to", type=int, required=True)
    fsck = commands.add_parser("fsck")
    fsck.add_argument("volume", type=Path)
    fsck.add_argument("--verify-data", action="store_true")
    repair = commands.add_parser("repair-superblock")
    repair.add_argument("volume", type=Path)
    repair.add_argument("--confirm-volume", required=True)
    scrub = commands.add_parser("scrub")
    scrub.add_argument("volume", type=Path)
    scrub.add_argument("--check-only", action="store_true")
    scrub.add_argument("--confirm-volume")
    trim = commands.add_parser("trim-plan")
    trim.add_argument("volume", type=Path)
    trim_run = commands.add_parser("trim")
    trim_run.add_argument("volume", type=Path)
    trim_run.add_argument("--dry-run", action="store_true")
    trim_run.add_argument("--range", dest="trim_range")
    trim_run.add_argument("--granularity", type=int, default=BLOCK_SIZE)
    trim_run.add_argument("--maximum-request", type=int,
                          default=1024 * 1024 * 1024)
    trim_run.add_argument("--confirm-volume")
    args = parser.parse_args()
    try:
        if args.command == "format":
            if os.path.abspath(args.confirm_path) != os.path.abspath(args.volume):
                raise PermissionError("format target confirmation mismatch")
            volume_uuid = bytes.fromhex(args.volume_uuid) if args.volume_uuid else None
            with XaiFs.format(
                args.volume, args.size, args.chunk_size, volume_uuid
            ) as volume:
                result = volume.usage()
            check = XaiFs.fsck(args.volume)
            if check["status"] != "clean":
                raise IOError("formatted volume failed read-back verification")
            result["format_verification"] = check["status"]
        elif args.command == "fsck":
            result = XaiFs.fsck(args.volume, args.verify_data)
        else:
            read_only = args.command in (
                "list", "inspect", "verify", "usage", "resize-plan", "trim-plan"
            ) or (args.command == "scrub" and args.check_only) or (
                args.command == "trim" and args.dry_run
            )
            with XaiFs(args.volume, read_only=read_only) as volume:
                volume_hex = volume.volume_uuid.hex()
                if args.command == "list":
                    result = volume.list_packages()
                elif args.command == "stage":
                    manifest = _load_manifest(args.manifest)
                    package_id = volume.stage_begin(manifest)
                    volume.pwrite_from_file(package_id, args.package)
                    result = volume.inspect(package_id)
                elif args.command == "inspect":
                    result = volume.inspect(args.package_id)
                elif args.command == "verify":
                    volume.stage_verify(args.package_id)
                    result = {
                        "schema": "xaios.xaifs.verify.v1",
                        "status": "verified",
                        "package_id": args.package_id,
                    }
                elif args.command == "activate":
                    volume.activate(args.package_id)
                    result = volume.inspect(args.package_id)
                elif args.command == "remove":
                    if args.confirm_package.lower() != args.package_id.lower():
                        raise PermissionError("package confirmation mismatch")
                    volume.remove(args.package_id, allow_active=args.allow_active)
                    result = {
                        "schema": "xaios.xaifs.remove.v1",
                        "status": "removed",
                        "package_id": args.package_id,
                    }
                elif args.command == "usage":
                    result = volume.usage()
                elif args.command == "resize-plan":
                    if args.grow_to < volume.volume_size:
                        result = {
                            "schema": "xaios.xaifs.resize-plan.v1",
                            "status": "shrink_not_supported",
                            "current_bytes": volume.volume_size,
                            "requested_bytes": args.grow_to,
                        }
                    else:
                        result = {
                            "schema": "xaios.xaifs.resize-plan.v1",
                            "status": "grow" if args.grow_to > volume.volume_size else "unchanged",
                            "current_bytes": volume.volume_size,
                            "requested_bytes": args.grow_to,
                            "additional_bytes": args.grow_to - volume.volume_size,
                        }
                elif args.command == "resize":
                    if args.confirm_volume.lower() != volume_hex:
                        raise PermissionError("volume UUID confirmation mismatch")
                    volume.grow(args.grow_to)
                    result = volume.usage()
                elif args.command == "repair-superblock":
                    repaired = volume.repair_superblock(args.confirm_volume)
                    result = {
                        "schema": "xaios.xaifs.repair.v1",
                        "status": "repaired" if repaired else "clean",
                        "volume_uuid": volume_hex,
                    }
                elif args.command == "scrub":
                    if not args.check_only and (
                        args.confirm_volume is None
                        or args.confirm_volume.lower() != volume_hex
                    ):
                        raise PermissionError("volume UUID confirmation mismatch")
                    result = volume.scrub(quarantine=not args.check_only)
                elif args.command == "trim-plan":
                    result = {
                        "schema": "xaios.xaifs.trim-plan.v1",
                        "volume_uuid": volume_hex,
                        "generation": volume.generation,
                        "ranges": volume.trim_plan(),
                    }
                elif args.command == "trim":
                    if not args.dry_run and (
                        args.confirm_volume is None
                        or args.confirm_volume.lower() != volume_hex
                    ):
                        raise PermissionError("volume UUID confirmation mismatch")
                    requested = None
                    if args.trim_range:
                        parts = args.trim_range.split(":", 1)
                        if len(parts) != 2:
                            raise ValueError("trim range must be OFFSET:LENGTH")
                        requested = (int(parts[0], 0), int(parts[1], 0))
                    result = volume.trim(
                        dry_run=args.dry_run,
                        requested_range=requested,
                        granularity=args.granularity,
                        maximum_request=args.maximum_request,
                    )
                else:
                    if args.drop_incomplete and (
                        args.confirm_volume is None
                        or args.confirm_volume.lower() != volume_hex
                    ):
                        raise PermissionError("volume UUID confirmation mismatch")
                    result = volume.recover(args.drop_incomplete)
        print(json.dumps(result, sort_keys=True, indent=2))
        status = result.get("status") if isinstance(result, dict) else None
        if status in ("repairable", "corrupt", "corrupt_unrepairable"):
            return 1
        if status in ("unsupported", "shrink_not_supported"):
            return 3
        return 0
    except PermissionError as error:
        result = {
            "schema": "xaios.xaifs.error.v1",
            "status": "unsafe_target",
            "error": str(error),
        }
        exit_code = 2
    except (ValueError, OverflowError) as error:
        result = {
            "schema": "xaios.xaifs.error.v1",
            "status": "invalid_request",
            "error": str(error),
        }
        exit_code = 2
    except OSError as error:
        result = {
            "schema": "xaios.xaifs.error.v1",
            "status": "io_error",
            "error": str(error),
        }
        exit_code = 4
    print(json.dumps(result, sort_keys=True, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
