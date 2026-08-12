import hashlib
import os
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from xaios_model_v2 import (
    BytesSource,
    CHUNK_SIZE,
    EXECUTION_EXACT,
    IO_ALIGNMENT,
    PackageWriter,
    SECTION_ARCHITECTURE,
    SECTION_DENSE_WEIGHTS,
    SECTION_INTEGRITY,
    SECTION_LAYER_PLAN,
    SECTION_TOKENIZER,
    SectionSource,
    SectionSpec,
    TENSOR_DESCRIPTOR_SIZE,
    TensorSpec,
    build_miniature_package,
    read_header,
)


ROOT = Path(__file__).resolve().parents[2]
INSPECTOR = ROOT / "build/hosted/test-engine"


class TrackingSource(SectionSource):
    def __init__(self, length: int) -> None:
        self.length = length
        self.maximum_chunk = 0

    def chunks(self, chunk_size: int = CHUNK_SIZE):
        remaining = self.length
        block = bytes(min(chunk_size, self.length))
        while remaining:
            chunk = block[: min(len(block), remaining)]
            self.maximum_chunk = max(self.maximum_chunk, len(chunk))
            remaining -= len(chunk)
            yield chunk


def add_required_sections(writer: PackageWriter) -> None:
    writer.add_section(
        SectionSpec(SECTION_ARCHITECTURE, "architecture", BytesSource(b"{}"))
    )
    writer.add_section(
        SectionSpec(SECTION_LAYER_PLAN, "layers", BytesSource(b'{"layers":[]}'))
    )
    writer.add_section(
        SectionSpec(SECTION_TOKENIZER, "tokenizer", BytesSource(b'{"type":"none"}'))
    )


class ModelV2Tests(unittest.TestCase):
    def run_inspector(self, package: Path, expected: int = 0) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [str(INSPECTOR), str(package)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stdout)
        return result

    def test_python_writer_to_c_reader_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "miniature.xaiosmodel2"
            build_miniature_package(package)
            header = read_header(package)
            self.assertEqual(header["architecture_id"], "xaios_fixture")
            self.assertEqual(header["tensor_count"], 1)
            result = self.run_inspector(package)
            self.assertIn("architecture=xaios_fixture", result.stdout)

    def test_sparse_package_exceeds_four_gib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "sparse.xaiosmodel2"
            writer = PackageWriter("kimi_k3", hashlib.sha256(b"k3").digest())
            add_required_sections(writer)
            writer.add_section(
                SectionSpec(
                    SECTION_INTEGRITY,
                    "large-offset-proof",
                    BytesSource(b"proof"),
                    requested_offset=(1 << 32) + IO_ALIGNMENT,
                )
            )
            writer.write(package)
            self.assertGreater(package.stat().st_size, 1 << 32)
            self.run_inspector(package)

    def test_streaming_writer_bounds_payload_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "streamed.xaiosmodel2"
            source = TrackingSource(32 * 1024 * 1024)
            writer = PackageWriter(
                "xaios_fixture", hashlib.sha256(b"stream").digest()
            )
            add_required_sections(writer)
            writer.add_section(
                SectionSpec(SECTION_DENSE_WEIGHTS, "dense", source)
            )
            writer.write(package)
            self.assertLessEqual(source.maximum_chunk, CHUNK_SIZE)
            self.assertGreater(package.stat().st_size, source.length)
            self.run_inspector(package)

    def test_checksum_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "corrupt.xaiosmodel2"
            build_miniature_package(package)
            header = read_header(package)
            with package.open("r+b") as stream:
                section_directory = int(header["section_directory_offset"])
                dense_descriptor = section_directory + (3 * 128)
                stream.seek(dense_descriptor + 16)
                dense_offset = struct.unpack("<Q", stream.read(8))[0]
                stream.seek(dense_offset)
                byte = stream.read(1)
                stream.seek(dense_offset)
                stream.write(bytes([byte[0] ^ 0x80]))
            self.run_inspector(package, expected=1)

    def test_malformed_section_offset_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "bad-offset.xaiosmodel2"
            build_miniature_package(package)
            header = read_header(package)
            with package.open("r+b") as stream:
                stream.seek(int(header["section_directory_offset"]) + 16)
                stream.write(struct.pack("<Q", 0xFFFFFFFFFFFFF000))
            self.run_inspector(package, expected=1)

    def test_tensor_dimension_overflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "overflow.xaiosmodel2"
            build_miniature_package(package)
            header = read_header(package)
            with package.open("r+b") as stream:
                tensor_offset = int(header["tensor_directory_offset"])
                stream.seek(tensor_offset + 136)
                stream.write(struct.pack("<QQ", (1 << 64) - 1, 2))
            self.run_inspector(package, expected=1)

    def test_metadata_directories_cannot_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "overlap.xaiosmodel2"
            build_miniature_package(package)
            header = bytearray(package.read_bytes()[:256])
            section_directory = struct.unpack_from("<Q", header, 48)[0]
            struct.pack_into("<Q", header, 64, section_directory)
            header[208:240] = bytes(32)
            header[208:240] = hashlib.sha256(header).digest()
            with package.open("r+b") as stream:
                stream.write(header)
            self.run_inspector(package, expected=1)

    def test_scale_offset_is_absolute_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "scales.xaiosmodel2"
            writer = PackageWriter(
                "xaios_fixture", hashlib.sha256(b"scales").digest()
            )
            add_required_sections(writer)
            writer.add_section(
                SectionSpec(
                    SECTION_DENSE_WEIGHTS,
                    "dense",
                    BytesSource(bytes(IO_ALIGNMENT)),
                )
            )
            writer.add_tensor(
                TensorSpec(
                    name="quantized.weight",
                    semantic_role=1,
                    section_name="dense",
                    data_offset=0,
                    data_length=16,
                    dimensions=(2, 2),
                    strides=(8, 4),
                    scale_offset=16,
                    scale_length=4,
                )
            )
            writer.write(package)
            header = read_header(package)
            with package.open("rb") as stream:
                stream.seek(int(header["tensor_directory_offset"]) + 104)
                scale_offset = struct.unpack("<Q", stream.read(8))[0]
                stream.seek(int(header["section_directory_offset"]) + (3 * 128) + 16)
                dense_offset = struct.unpack("<Q", stream.read(8))[0]
            self.assertEqual(scale_offset, dense_offset + 16)
            self.run_inspector(package)

    def test_truncated_and_random_headers_fail_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "valid.xaiosmodel2"
            build_miniature_package(package)
            original = package.read_bytes()[:256]
            for length in (0, 1, 8, 64, 255):
                candidate = Path(temporary) / f"truncated-{length}.bin"
                candidate.write_bytes(original[:length])
                self.run_inspector(candidate, expected=1)
            randomizer = random.Random(0)
            for index in range(16):
                mutated = bytearray(original)
                position = randomizer.randrange(0, 240)
                mutated[position] ^= 1 << randomizer.randrange(0, 8)
                candidate = Path(temporary) / f"mutated-{index}.bin"
                candidate.write_bytes(mutated)
                self.run_inspector(candidate, expected=1)


if __name__ == "__main__":
    unittest.main()
