#!/usr/bin/env python3
"""Logical package manifests for xaiFS: build, chunk, sign.

The manifest types and the identity hash they are checked against live in
`xai_fs_format`; this module is the layer that turns a package file or a
sparse-zero request into a signed `PackageManifest`. It is separated from
`xai_fs_format` only to keep both files under the repository's 500-line limit.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, Optional

from xai_fs_format import (
    ManifestChunk,
    PackageManifest,
    _private_key_from_seed,
    _public_bytes,
    _validate_chunk_size,
    _validate_logical_chunks,
    _zero_digest,
    chunk_size_for,
    package_identity,
)


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
    chunk_size: Optional[int] = None,
    signing_seed: bytes = b"",
) -> PackageManifest:
    logical_size = package.stat().st_size
    # A caller that names a chunk size gets it -- fixtures pin theirs so their
    # hashes stay put. A caller that does not gets the one that suits the
    # package, which is the case that matters for anything large.
    if chunk_size is None:
        chunk_size = chunk_size_for(logical_size)
    _validate_chunk_size(chunk_size)
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
