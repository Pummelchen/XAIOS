#!/usr/bin/env python3
"""Chunk and package verification, shared by the writer and the reader.

`xai_fs_write`'s `activate` calls `stage_verify`, and `xai_fs_read`'s `fsck` and
`scrub` call the per-chunk and whole-package checks, so this mixin sits between
the two halves in the `XaiFs` composition.
"""

from __future__ import annotations

import hashlib
import os

from xai_fs_format import (
    CHUNK_COMPLETE,
    CHUNK_ZERO,
    ManifestChunk,
    XaiFsIntegrityError,
    _ChunkRecord,
    _PackageRecord,
    _zero_digest,
    package_identity,
    verify_ed25519,
)


class XaiFsVerifyMixin:
    """Verify one chunk's bytes against its record, and
    one package's chunks, identity and signature."""

    def _verify_chunk(self, record: _PackageRecord, chunk: _ChunkRecord) -> None:
        """Hash one chunk's bytes on the volume and compare to its record."""
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

    def _verify_record(self, record: _PackageRecord) -> None:
        chunks = self._record_chunks(record)
        manifest_chunks = []
        for chunk in chunks:
            if not chunk.flags & CHUNK_COMPLETE:
                raise XaiFsIntegrityError(
                    record.package_id, chunk.logical_offset, "chunk is incomplete"
                )
            self._verify_chunk(record, chunk)
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
