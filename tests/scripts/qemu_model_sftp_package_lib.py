#!/usr/bin/env python3
"""Package manifests and register commands for the xaiFS model SFTP gate.

Moved verbatim out of `qemu-model-sftp-gate.py`. `staging_path` names the
staging extent a fixture is uploaded to, `dynamic_manifest` signs a manifest
for a generated model, and `register_command` renders the `xaiosctl model
register` line the guest runs for it. They share the run context -- the
repository root and the verification chunk size -- with
`qemu_model_sftp_gate_lib.py`.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from qemu_model_sftp_gate_lib import MODEL_CHUNK_SIZE, ROOT

sys.path.insert(0, str(ROOT / "tools"))

from xaios_xai_fs import manifest_for_file


def staging_path(source: Path) -> str:
    manifest = manifest_for_file(
        source,
        bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        hashlib.sha256(b"c-sftp-staging-fixture").digest(),
        "sftp-staging-test",
        "portable",
        MODEL_CHUNK_SIZE,
        bytes((index * 3 + 1) & 0xFF for index in range(32)),
    )
    return f"/models/.staging/{manifest.package_id.hex()}"


def dynamic_manifest(source: Path, identity: str, seed: int):
    return manifest_for_file(
        source,
        hashlib.sha256(f"{identity}-uuid".encode()).digest()[:16],
        hashlib.sha256(f"{identity}-revision".encode()).digest(),
        "storage-stress-test",
        "portable",
        MODEL_CHUNK_SIZE,
        bytes((index * 5 + seed) & 0xFF for index in range(32)),
    )


def register_command(manifest, operation_id: int) -> str:
    return (
        f"xaiosctl model register {manifest.package_id.hex()} "
        f"--model-uuid {manifest.model_uuid.hex()} "
        f"--signer-key {manifest.signer_public_key.hex()} "
        f"--signature {manifest.signature.hex()} "
        f"--source-revision {manifest.source_revision.hex()} "
        f"--architecture {manifest.architecture_id} "
        f"--target {manifest.target_id} --size {manifest.logical_size} "
        f"--operation-id {operation_id} --json"
    )

