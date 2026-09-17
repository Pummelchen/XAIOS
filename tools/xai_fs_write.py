#!/usr/bin/env python3
"""The writer half of `XaiFs`, and the host discard helper.

`XaiFsWriteMixin` carries every method that allocates an extent, writes a
chunk or publishes a catalog; `xai_fs_read` and `xai_fs_verify` carry the rest.
The command-line facade composes them back into `XaiFs`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import fcntl
import hashlib
import os
import stat
import struct
import sys
import uuid
from pathlib import Path
from typing import Optional

from xai_fs_codec import _encode_catalog, _encode_superblock
from xai_fs_format import (
    BLOCK_SIZE,
    CHUNK_COMPLETE,
    CHUNK_FREE,
    CHUNK_ZERO,
    DATA_START,
    PACKAGE_ACTIVE,
    PACKAGE_STAGING,
    SUPERBLOCK_SIZE,
    PackageManifest,
    _ChunkRecord,
    _PackageRecord,
    _align,
    _checked_end,
    _coalesce_extents,
    _pwrite_all,
    _reindex_records,
    _validate_chunk_size,
)


class XaiFsWriteMixin:
    """Every method that mutates a volume, plus the
    allocation and publication primitives they share."""

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

    def _data_high_water(self, chunks: list[_ChunkRecord]) -> int:
        """The highest byte any extent occupies, which the catalog must clear.

        data_tail used to mean both "where to allocate next" and "where the
        catalog ends", and conflating them is what leaked a catalog per commit.
        This is the first half on its own.
        """
        highest = DATA_START
        for chunk in chunks:
            if chunk.flags & CHUNK_ZERO and chunk.extent_length == 0:
                continue
            end = chunk.physical_offset + chunk.extent_length
            if end > highest:
                highest = end
        return highest

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
        provisional = _encode_catalog(
            catalog_generation, self.volume_uuid, records, chunks, 0
        )
        # Two catalog slots directly above the data, used alternately, rather
        # than a fresh one at the end of the volume every time.
        #
        # Writing each new catalog past the last one and then moving data_tail
        # over it meant every commit permanently consumed a catalog's worth of
        # volume that nothing reclaimed: measured at 8192 bytes a commit, which
        # is 23799 commits before a 256 MB volume is full and something like
        # 131 GB stranded behind a 500 GB package ingested a chunk at a time.
        #
        # The new catalog must never land on the live one -- a reader following
        # the old superblock has to keep finding the old catalog until the
        # superblock flips -- so two slots is the minimum, and it is enough.
        data_floor = _align(self._data_high_water(chunks))
        first = data_floor
        second = _align(first + len(provisional))
        catalog_offset = second if self.catalog_offset == first else first
        final_tail = _align(second + len(provisional))
        _checked_end(catalog_offset, len(provisional), published_size)
        _checked_end(second, len(provisional), published_size)
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
