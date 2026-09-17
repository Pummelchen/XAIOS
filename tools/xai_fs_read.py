#!/usr/bin/env python3
"""The reader half of `XaiFs`: open, read, inspect, recover, fsck and repair.

`XaiFsWriteMixin` and `XaiFsVerifyMixin` carry the other halves; the
command-line facade composes them back into `XaiFs`.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

from xai_fs_codec import _read_candidate
from xai_fs_format import (
    CHUNK_COMPLETE,
    CHUNK_FREE,
    CHUNK_ZERO,
    DATA_START,
    PACKAGE_ACTIVE,
    PACKAGE_QUARANTINED,
    PACKAGE_STAGING,
    SUPERBLOCK_SIZE,
    VERSION_MAJOR,
    VERSION_MINOR,
    Extent,
    XaiFsIntegrityError,
    _PackageRecord,
    _ChunkRecord,
    _checked_end,
    _pwrite_all,
)


class XaiFsReadMixin:
    """The lifecycle, read, inspection and fsck methods of
    a volume."""

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
        verified_chunks = 0
        partial_packages = 0
        if verify_data:
            with cls(path, read_only=True) as volume:
                for record in volume.records:
                    chunks = volume._record_chunks(record)
                    incomplete = [
                        chunk
                        for chunk in chunks
                        if not chunk.flags & CHUNK_COMPLETE
                    ]
                    if record.state == PACKAGE_STAGING and incomplete:
                        # A package caught mid-ingest: some chunks committed,
                        # the rest never written. Skipping it outright, as
                        # this used to, is what makes a crash test vacuous --
                        # the interesting case is precisely a volume where
                        # some chunk claims to be complete. So verify the
                        # ones that make the claim and let the rest be
                        # missing, which is the property that matters: a
                        # chunk is either absent or right, never half
                        # written.
                        partial_packages += 1
                        for chunk in chunks:
                            if not chunk.flags & CHUNK_COMPLETE:
                                continue
                            checked_bytes += chunk.length
                            verified_chunks += 1
                            try:
                                volume._verify_chunk(record, chunk)
                            except XaiFsIntegrityError as error:
                                errors.append(
                                    {
                                        "package_id": error.package_id.hex(),
                                        "logical_offset": error.logical_offset,
                                        "reason": error.reason,
                                    }
                                )
                        continue
                    checked_bytes += record.logical_size
                    verified_chunks += len(chunks)
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
            "verified_chunks": verified_chunks,
            "partial_packages": partial_packages,
            "errors": errors,
        }

    def sync(self) -> None:
        os.fsync(self.fd)
