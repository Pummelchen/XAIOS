#!/usr/bin/env python3
"""Superblock and catalog encode/decode for the xaiFS v1 on-disk format.

The structures these functions pack and unpack live in `xai_fs_format`. The C
reader in `engine/src/xai_fs.c` and the C writer in
`engine/src/xai_fs_writer.c` read and produce exactly these bytes, and
`_read_candidate` here is what the crash-safety gate imports to read a volume
the way `XaiFs` does.
"""

from __future__ import annotations

import hashlib
import os
import struct

from xai_fs_format import (
    BLOCK_SIZE,
    CATALOG_HEADER_SIZE,
    CATALOG_MAGIC,
    CHUNK_COMPLETE,
    CHUNK_FREE,
    CHUNK_RECORD_SIZE,
    CHUNK_ZERO,
    DATA_START,
    ENDIAN_LITTLE,
    HASH_SHA256,
    MAGIC,
    PACKAGE_ACTIVE,
    PACKAGE_QUARANTINED,
    PACKAGE_RECORD_SIZE,
    PACKAGE_STAGING,
    SUPERBLOCK_SIZE,
    TARGETS,
    VERSION_MAJOR,
    VERSION_MINOR,
    ManifestChunk,
    _ChunkRecord,
    _PackageRecord,
    _checked_end,
    _fixed_ascii,
    _validate_chunk_size,
    _validate_logical_chunks,
    package_identity,
    verify_ed25519,
)


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
