import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xaios_xai_fs import (
    BLOCK_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    PACKAGE_ACTIVE,
    SUPERBLOCK_SIZE,
    ManifestChunk,
    XaiFs,
    XaiFsIntegrityError,
    PackageManifest,
    chunk_size_for,
    manifest_for_file,
    sign_manifest,
    sparse_zero_manifest,
)


MIB = 1024 * 1024
GIB = 1024 * MIB
CHUNK_SIZE = 2 * MIB
VOLUME_SIZE = 64 * MIB
SEED = bytes(range(32))
VOLUME_UUID = bytes.fromhex("00112233445566778899aabbccddeeff")


class XaiFsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.volume_path = self.root / "models.img"

    def tearDown(self):
        self.temporary.cleanup()

    def source_and_manifest(self, tag: int = 1, size: int = CHUNK_SIZE + 8192):
        source = self.root / f"package-{tag}.bin"
        block = bytes(((index + tag) & 0xFF) for index in range(4096))
        with source.open("wb") as stream:
            remaining = size
            while remaining:
                data = block[: min(len(block), remaining)]
                stream.write(data)
                remaining -= len(data)
        manifest = manifest_for_file(
            source,
            tag.to_bytes(16, "little"),
            hashlib.sha256(f"revision-{tag}".encode()).digest(),
            "qwen-test",
            "portable",
            CHUNK_SIZE,
            SEED,
        )
        return source, manifest

    def format(self, size: int = VOLUME_SIZE, chunk_size: int = CHUNK_SIZE):
        return XaiFs.format(
            self.volume_path,
            size,
            chunk_size,
            VOLUME_UUID,
        )

    def stage_complete(self, volume: XaiFs, tag: int = 1):
        source, manifest = self.source_and_manifest(tag)
        package_id = volume.stage_begin(manifest)
        volume.pwrite_from_file(package_id, source)
        volume.stage_verify(package_id)
        return source, manifest, package_id

    def test_streaming_lifecycle_resume_activation_and_read_only_mount(self):
        source, manifest = self.source_and_manifest()
        with self.format() as volume:
            package_id = volume.stage_begin(manifest)
            with source.open("rb") as stream:
                first = stream.read(CHUNK_SIZE)
            volume.pwrite(package_id, 0, first)
            self.assertEqual(volume.inspect(package_id)["complete_chunks"], 1)

        with XaiFs(self.volume_path) as volume:
            volume.pwrite_from_file(package_id, source)
            volume.stage_verify(package_id)
            volume.activate(package_id)
            self.assertEqual(volume.inspect(package_id)["state"], "active")
            expected = source.read_bytes()[CHUNK_SIZE - 32 : CHUNK_SIZE + 32]
            self.assertEqual(volume.pread(package_id, CHUNK_SIZE - 32, 64), expected)
            with self.assertRaises(PermissionError):
                volume.pwrite(package_id, 0, first)

        with XaiFs(self.volume_path, read_only=True) as volume:
            self.assertEqual(volume.pread(package_id, 0, 32), source.read_bytes()[:32])
            with self.assertRaises(PermissionError):
                volume.remove(package_id, allow_active=True)
        self.assertEqual(XaiFs.fsck(self.volume_path, True)["status"], "clean")

    def test_activation_power_loss_keeps_previous_staging_generation(self):
        with self.format() as volume:
            _, _, package_id = self.stage_complete(volume)
            generation = volume.generation
            with self.assertRaises(InterruptedError):
                volume.activate(package_id, fail_before_superblock=True)

        with XaiFs(self.volume_path) as recovered:
            self.assertEqual(recovered.generation, generation)
            self.assertEqual(recovered.inspect(package_id)["state"], "staging")
            recovered.activate(package_id)
            self.assertEqual(recovered.inspect(package_id)["state"], "active")

    def test_corruption_quarantines_only_the_damaged_package(self):
        with self.format() as volume:
            source_one, _, package_one = self.stage_complete(volume, 1)
            volume.activate(package_one)
            source_two, _, package_two = self.stage_complete(volume, 2)
            volume.activate(package_two)
            damaged = volume.extent_map(package_one)[0]
            os.pwrite(volume.fd, b"\xff", damaged.physical_offset)
            os.fsync(volume.fd)
            result = volume.scrub()
            self.assertEqual(result["status"], "corrupt")
            self.assertEqual(result["newly_quarantined"], 1)
            self.assertEqual(result["errors"][0]["logical_offset"], 0)
            self.assertEqual(volume.inspect(package_one)["state"], "quarantined")
            with self.assertRaises(PermissionError):
                volume.pread(package_one, 0, 1)
            self.assertEqual(volume.pread(package_two, 0, 32), source_two.read_bytes()[:32])
            with self.assertRaises(XaiFsIntegrityError):
                volume.stage_verify(package_one)
            self.assertEqual(source_one.stat().st_size, volume.inspect(package_one)["logical_size"])
        self.assertEqual(
            XaiFs.fsck(self.volume_path, verify_data=True)["status"],
            "corrupt_unrepairable",
        )

    def test_redundant_superblock_fallback_and_confirmed_repair(self):
        with self.format() as volume:
            volume_uuid = volume.volume_uuid
        with self.volume_path.open("r+b", buffering=0) as stream:
            stream.seek(100)
            value = stream.read(1)
            stream.seek(100)
            stream.write(bytes([value[0] ^ 1]))
            os.fsync(stream.fileno())

        before = self.volume_path.stat().st_mtime_ns
        report = XaiFs.fsck(self.volume_path)
        after = self.volume_path.stat().st_mtime_ns
        self.assertEqual(report["status"], "repairable")
        self.assertEqual(before, after)
        with XaiFs(self.volume_path) as volume:
            with self.assertRaises(PermissionError):
                volume.repair_superblock(bytes(16))
            self.assertTrue(volume.repair_superblock(volume_uuid))
            self.assertFalse(volume.repair_superblock(volume_uuid))
        self.assertEqual(XaiFs.fsck(self.volume_path)["status"], "clean")

    def test_grow_is_transactional_and_shrink_is_rejected(self):
        with self.format() as volume:
            with self.assertRaises(InterruptedError):
                volume.grow(96 * MIB, fail_before_superblock=True)
        with XaiFs(self.volume_path) as recovered:
            self.assertEqual(recovered.volume_size, VOLUME_SIZE)
            self.assertEqual(recovered.backing_size, 96 * MIB)
            recovered.grow(96 * MIB)
            self.assertEqual(recovered.volume_size, 96 * MIB)
            with self.assertRaisesRegex(ValueError, "shrink_not_supported"):
                recovered.grow(VOLUME_SIZE)
        self.assertEqual(XaiFs.fsck(self.volume_path)["status"], "clean")

    def test_removed_staging_extents_are_coalesced_and_reused(self):
        with self.format() as volume:
            _, first_manifest = self.source_and_manifest(1, CHUNK_SIZE)
            first = volume.stage_begin(first_manifest)
            first_extent = volume.extent_map(first)[0].physical_offset
            volume.remove(first)
            _, second_manifest = self.source_and_manifest(2, CHUNK_SIZE)
            second = volume.stage_begin(second_manifest)
            self.assertEqual(volume.extent_map(second)[0].physical_offset, first_extent)
            self.assertGreaterEqual(volume.usage()["available_bytes"], 1)

    def test_sparse_128_gib_volume_and_package_above_100_gib(self):
        volume_size = 128 * GIB
        logical_size = 100 * GIB + 2 * BLOCK_SIZE
        chunk_size = 16 * MIB
        manifest = sparse_zero_manifest(
            logical_size,
            chunk_size,
            bytes.fromhex("102132435465768798a9bacbdcedfe0f"),
            hashlib.sha256(b"sparse-100-gib").digest(),
            "capacity-test",
            "portable",
            SEED,
        )
        with self.format(volume_size, chunk_size) as volume:
            package_id = volume.stage_begin(manifest)
            volume.stage_verify(package_id)
            volume.activate(package_id)
            offsets = (
                0,
                4 * GIB - BLOCK_SIZE,
                4 * GIB + BLOCK_SIZE,
                64 * GIB,
                100 * GIB - BLOCK_SIZE,
                100 * GIB + BLOCK_SIZE,
                logical_size - BLOCK_SIZE,
            )
            for offset in offsets:
                self.assertEqual(volume.pread(package_id, offset, BLOCK_SIZE), bytes(BLOCK_SIZE))
            self.assertEqual(volume.inspect(package_id)["logical_size"], logical_size)
            self.assertLess(self.volume_path.stat().st_blocks * 512, 64 * MIB)
        report = XaiFs.fsck(self.volume_path, verify_data=True)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["checked_bytes"], logical_size)

    def test_manifest_and_metadata_validation_fail_closed(self):
        chunks = (ManifestChunk(0, CHUNK_SIZE, hashlib.sha256(bytes(CHUNK_SIZE)).digest(), True),)
        valid = sign_manifest(
            bytes.fromhex("11223344556677889900aabbccddeeff"),
            hashlib.sha256(b"revision").digest(),
            "validation-test",
            "portable",
            CHUNK_SIZE,
            CHUNK_SIZE,
            chunks,
            SEED,
        )
        invalid = PackageManifest(
            valid.model_uuid,
            valid.source_revision,
            valid.architecture_id,
            valid.target_id,
            valid.logical_size,
            valid.chunk_size,
            valid.chunks,
            valid.package_id,
            valid.signer_public_key,
            bytes(64),
        )
        with self.format() as volume:
            with self.assertRaisesRegex(ValueError, "signature"):
                volume.stage_begin(invalid)
            volume.stage_begin(valid)
            with self.assertRaises(ValueError):
                volume.pread(valid.package_id, (1 << 64) - 1, 2)
        with self.volume_path.open("r+b", buffering=0) as stream:
            for slot in (0, 1):
                stream.seek(slot * SUPERBLOCK_SIZE)
                stream.write(b"BROKEN!!")
            os.fsync(stream.fileno())
        self.assertEqual(
            XaiFs.fsck(self.volume_path)["status"], "corrupt_unrepairable"
        )

    def test_manifest_json_round_trip_and_trim_safety(self):
        _, manifest = self.source_and_manifest(7, CHUNK_SIZE)
        self.assertEqual(PackageManifest.from_json(manifest.to_json()), manifest)
        with self.format() as volume:
            package_id = volume.stage_begin(manifest)
            extent = volume.extent_map(package_id)[0]
            volume.remove(package_id)
            calls = []
            result = volume.trim(
                lambda offset, length: calls.append((offset, length)),
                requested_range=(extent.physical_offset, extent.length),
                maximum_request=MIB,
            )
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["bytes_trimmed"], extent.length)
            self.assertEqual(calls, [
                (extent.physical_offset, MIB),
                (extent.physical_offset + MIB, MIB),
            ])
            with self.assertRaises(PermissionError):
                volume.trim(
                    lambda _offset, _length: None,
                    requested_range=(0, BLOCK_SIZE),
                )
        with XaiFs(self.volume_path, read_only=True) as volume:
            self.assertEqual(volume.trim(dry_run=True)["status"], "planned")

    def test_admin_cli_confirmations_and_stable_json_status(self):
        tool = Path(__file__).parents[2] / "tools" / "xaios_xai_fs.py"
        command = [
            sys.executable,
            str(tool),
            "format",
            str(self.volume_path),
            "--size",
            str(VOLUME_SIZE),
            "--chunk-size",
            str(CHUNK_SIZE),
        ]
        rejected = subprocess.run(
            command + ["--confirm-path", str(self.root / "wrong.img")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(json.loads(rejected.stdout)["status"], "unsafe_target")
        created = subprocess.run(
            command + ["--confirm-path", str(self.volume_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        created_json = json.loads(created.stdout)
        self.assertEqual(created_json["format_verification"], "clean")
        volume_uuid = created_json["volume_uuid"]
        wrong_resize = subprocess.run(
            [
                sys.executable,
                str(tool),
                "resize",
                str(self.volume_path),
                "--grow-to",
                str(96 * MIB),
                "--confirm-volume",
                "00" * 16,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(wrong_resize.returncode, 2)
        self.assertEqual(json.loads(wrong_resize.stdout)["status"], "unsafe_target")
        trim = subprocess.run(
            [
                sys.executable,
                str(tool),
                "trim",
                str(self.volume_path),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(trim.returncode, 0, trim.stderr)
        self.assertEqual(json.loads(trim.stdout)["status"], "planned")
        self.assertEqual(len(volume_uuid), 32)


if __name__ == "__main__":
    unittest.main()


class ChunkSizePolicyTest(unittest.TestCase):
    """The chunk size a package gets, and why the answer changes with size.

    A chunk is the unit of verification, of allocation, and of the catalog --
    and the catalog is rewritten whole on every commit, so its size is the one
    that decides whether ingesting half a terabyte is possible at all.
    """

    def test_small_packages_keep_the_smallest_chunk(self):
        # Below the point where the catalog costs anything, smaller chunks are
        # strictly better: a partial read hashes one chunk, not more.
        self.assertEqual(chunk_size_for(4096), MIN_CHUNK_SIZE)
        self.assertEqual(chunk_size_for(2 * 1024**3), MIN_CHUNK_SIZE)

    def test_chunk_size_never_leaves_the_format(self):
        for size in (0, 1, 4096, 2 * 1024**3, 500 * 1024**3, 4 * 1024**4):
            chunk = chunk_size_for(size)
            self.assertGreaterEqual(chunk, MIN_CHUNK_SIZE)
            self.assertLessEqual(chunk, MAX_CHUNK_SIZE)
            self.assertEqual(chunk & (chunk - 1), 0)

    def test_it_grows_and_never_shrinks(self):
        sizes = [1 << bit for bit in range(12, 45)]
        chunks = [chunk_size_for(size) for size in sizes]
        self.assertEqual(chunks, sorted(chunks))

    def test_the_cap_reaches_terabytes_before_it_binds(self):
        # The cap used to be 16 MiB, which is where chunk count started growing
        # again past about a terabyte. It is the catalog -- rewritten whole on
        # every commit, 128 bytes a chunk -- that this is really about.
        for size in (1024**4, 2 * 1024**4, 4 * 1024**4):
            chunk = chunk_size_for(size)
            chunks = (size + chunk - 1) // chunk
            self.assertLessEqual(chunks, 65536, f"{size} bytes -> {chunks}")

    def test_a_half_terabyte_package_keeps_its_catalog_small(self):
        # 128 bytes of catalog per chunk, rewritten in full on every commit.
        # At the smallest chunk this package would carry a 32 MB catalog; the
        # policy is what keeps it in single-digit megabytes.
        size = 500 * 1024**3
        chunk = chunk_size_for(size)
        catalog = 256 + 384 + 128 * ((size + chunk - 1) // chunk)
        self.assertLess(catalog, 8 * 1024 * 1024)


