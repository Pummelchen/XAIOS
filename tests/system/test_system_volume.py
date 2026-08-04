import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.xaios_system_volume import (
    BACKUP_OFFSET,
    METADATA_BYTES,
    NO_SLOT,
    PRIMARY_OFFSET,
    SECTOR_BYTES,
    SLOT0_LBA,
    create,
    metadata,
    parse_metadata,
    read_best_metadata,
    verify,
)


class Arguments:
    pass


class SystemVolumeTests(unittest.TestCase):
    @staticmethod
    def arguments(image, kernel):
        args = Arguments()
        args.output = image
        args.slot_a = kernel
        args.slot_b = None
        args.generation_a = 7
        args.generation_b = 8
        args.active = 0
        args.pending = 1
        args.pending_attempted = False
        args.sequence = 4
        return args

    def test_round_trip_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "kernel.elf"
            image = root / "system.img"
            kernel.write_bytes(b"\x7fELF" + bytes(range(251)) * 19)
            create(self.arguments(image, kernel))
            verify_args = Arguments()
            verify_args.image = image
            verify(verify_args)
            info = parse_metadata(image.read_bytes()[:METADATA_BYTES])
            self.assertEqual(info["active"], 0)
            self.assertEqual(info["pending"], 1)
            self.assertEqual(info["slots"][1]["generation"], 8)

            corrupted = bytearray(image.read_bytes())
            corrupted[SLOT0_LBA * SECTOR_BYTES + 7] ^= 1
            image.write_bytes(corrupted)
            with self.assertRaisesRegex(ValueError, "payload checksum"):
                verify(verify_args)

    def test_metadata_write_crash_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "kernel.elf"
            image = root / "system.img"
            payload = b"\x7fELF" + bytes(range(251)) * 19
            kernel.write_bytes(payload)
            create(self.arguments(image, kernel))
            old = metadata(payload, payload, 7, 8, 0, 1, 0, 4)
            new = metadata(payload, payload, 7, 8, 1, NO_SLOT, 0, 5)

            cases = {
                "old copies": (old, old, 4, "primary"),
                "backup committed": (old, new, 5, "backup"),
                "both committed": (new, new, 5, "primary"),
                "torn backup": (old, bytes(METADATA_BYTES), 4, "primary"),
                "torn primary": (bytes(METADATA_BYTES), new, 5, "backup"),
            }
            for label, (primary, backup, sequence, source) in cases.items():
                with self.subTest(label=label), image.open("r+b") as output:
                    output.seek(PRIMARY_OFFSET)
                    output.write(primary)
                    output.seek(BACKUP_OFFSET)
                    output.write(backup)
                    output.flush()
                with image.open("rb") as source_file:
                    info, selected = read_best_metadata(source_file)
                self.assertEqual(info["sequence"], sequence)
                self.assertEqual(selected, source)

    def test_rejects_when_both_metadata_copies_are_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "system.img"
            image.write_bytes(bytes(METADATA_BYTES * 2))
            with image.open("rb") as source:
                with self.assertRaisesRegex(ValueError, "no valid"):
                    read_best_metadata(source)

    def test_rejects_bad_metadata_hash(self):
        data = bytearray(METADATA_BYTES)
        data[-32:] = hashlib.sha256(data[:-32]).digest()
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            parse_metadata(bytes(data))

    def test_no_slot_constant_is_abi_stable(self):
        self.assertEqual(NO_SLOT, 0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
