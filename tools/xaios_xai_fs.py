#!/usr/bin/env python3
"""Crash-consistent host implementation of the XAIOS xaiFS volume v1.

The module is intentionally file-offset based. Host files are the reference
backend; the kernel uses the same binary format through a VirtIO block reader.

This file is the command-line entry point and the module other code imports.
The implementation sits beside it: `xai_fs_format` (constants, primitives,
records and structures), `xai_fs_manifest` (build and sign a package manifest),
`xai_fs_codec` (superblock and catalog encode/decode), `xai_fs_verify` (chunk
and package verification), and `xai_fs_write` and `xai_fs_read` (the two halves
of `XaiFs`, composed below).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from xai_fs_format import MAX_CHUNK_SIZE as _FORMAT_MAX_CHUNK_SIZE
from xai_fs_format import MIN_CHUNK_SIZE as _FORMAT_MIN_CHUNK_SIZE
from xai_fs_format import (
    MAGIC, CATALOG_MAGIC, VERSION_MAJOR, VERSION_MINOR, ENDIAN_LITTLE,
    HASH_SHA256, SUPERBLOCK_SIZE, BLOCK_SIZE, CATALOG_HEADER_SIZE,
    PACKAGE_RECORD_SIZE, CHUNK_RECORD_SIZE, DATA_START, PACKAGE_STAGING,
    PACKAGE_ACTIVE, PACKAGE_QUARANTINED, CHUNK_COMPLETE, CHUNK_ZERO,
    CHUNK_FREE, TARGETS, XaiFsIntegrityError, _align, _checked_end,
    _pwrite_all, _fixed_ascii, _zero_digest, _private_key_from_seed,
    _public_bytes, verify_ed25519, ManifestChunk, PackageManifest,
    _ChunkRecord, _PackageRecord, Extent, chunk_size_for,
    _validate_chunk_size, _validate_logical_chunks, package_identity,
    _coalesce_extents, _reindex_records,
)
from xai_fs_manifest import (
    sign_manifest, manifest_for_file, sparse_zero_manifest,
)
from xai_fs_codec import (
    _encode_superblock, _decode_superblock, _encode_catalog, _decode_ascii,
    _decode_catalog, _read_candidate,
)
from xai_fs_verify import (
    XaiFsVerifyMixin,
)
from xai_fs_write import (
    XaiFsWriteMixin, _host_discard,
)
from xai_fs_read import (
    XaiFsReadMixin,
)

# The format's chunk-size bounds. `xai_fs_format` owns the values; these two
# assignments are the tool's statement of them, which
# tests/repository/check-xai-fs-chunk-bounds.py reads by name and compares with
# the C writer, the C reader and docs/MODELFS-FORMAT.md. The check below keeps
# them from drifting away from the module that enforces them.
MIN_CHUNK_SIZE = 2 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
if (MIN_CHUNK_SIZE, MAX_CHUNK_SIZE) != (
    _FORMAT_MIN_CHUNK_SIZE,
    _FORMAT_MAX_CHUNK_SIZE,
):
    raise RuntimeError(
        "xaios_xai_fs: chunk bounds disagree with xai_fs_format"
    )


class XaiFs(XaiFsWriteMixin, XaiFsVerifyMixin, XaiFsReadMixin):
    """The writer, verifier and reader halves of a xaiFS volume, composed here
    so that the name other code imports stays a single class."""


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
