#!/usr/bin/env python3
"""Streaming writer and inspection helpers for the xaios.model.v2 package.

This module is deliberately independent of GGUF, SafeTensors, NumPy, and the
kernel. Importers provide validated section streams and tensor metadata; this
writer lays them out deterministically without retaining weight payloads.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import os
import struct
import uuid
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Optional


MAGIC = b"XAIOSM2\0"
VERSION_MAJOR = 2
VERSION_MINOR = 0
ENDIAN_LITTLE = 1
HASH_SHA256 = 1
EXECUTION_EXACT = 1
EXECUTION_APPROXIMATE = 2
HEADER_SIZE = 256
SECTION_DESCRIPTOR_SIZE = 128
TENSOR_DESCRIPTOR_SIZE = 320
IO_ALIGNMENT = 4096
EXPERT_ALIGNMENT = 2 * 1024 * 1024
INDEX_NONE = (1 << 64) - 1
MAX_RANK = 8
CHUNK_SIZE = 1024 * 1024

SECTION_ARCHITECTURE = 1
SECTION_LAYER_PLAN = 2
SECTION_TENSOR_DIRECTORY = 3
SECTION_TOKENIZER = 4
SECTION_STRING_TABLE = 5
SECTION_DENSE_WEIGHTS = 6
SECTION_EXPERT_WEIGHTS = 7
SECTION_VISION = 8
SECTION_INTEGRITY = 9

TENSOR_RESIDENT = 1
TENSOR_CACHEABLE = 2
TENSOR_STREAMABLE = 4


def align(value: int, alignment: int) -> int:
    if alignment < IO_ALIGNMENT or alignment & (alignment - 1):
        raise ValueError("alignment must be a power of two of at least 4096")
    return (value + alignment - 1) & ~(alignment - 1)


class SectionSource:
    length: int

    def chunks(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class BytesSource(SectionSource):
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data)

    def chunks(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        for offset in range(0, len(self.data), chunk_size):
            yield self.data[offset : offset + chunk_size]


@dataclasses.dataclass(frozen=True)
class FileSource(SectionSource):
    path: Path

    @property
    def length(self) -> int:
        return self.path.stat().st_size

    def chunks(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        with self.path.open("rb") as source:
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    return
                yield chunk


@dataclasses.dataclass
class SectionSpec:
    section_type: int
    name: str
    source: SectionSource
    flags: int = 0
    alignment: int = IO_ALIGNMENT
    shard_id: int = 0
    requested_offset: Optional[int] = None


@dataclasses.dataclass
class TensorSpec:
    name: str
    semantic_role: int
    section_name: str
    data_offset: int
    data_length: int
    dimensions: tuple[int, ...]
    strides: tuple[int, ...]
    flags: int = TENSOR_RESIDENT
    tensor_id: int = 0
    layer_id: int = INDEX_NONE
    expert_id: int = INDEX_NONE
    logical_dtype: int = 1
    stored_dtype: int = 1
    quantization_scheme: int = 0
    scale_dtype: int = 0
    layout_id: int = 0
    required_backend: int = 1
    shard_id: int = 0
    alignment: int = IO_ALIGNMENT
    scale_section_name: Optional[str] = None
    scale_offset: int = 0
    scale_length: int = 0
    quant_block_size: int = 0
    quant_group_size: int = 0


@dataclasses.dataclass
class _PlannedSection:
    spec: SectionSpec
    section_id: int
    offset: int
    checksum: bytes = bytes(32)
    name_offset: int = 0


class PackageWriter:
    def __init__(
        self,
        architecture_id: str,
        source_revision: bytes,
        converter_version: str = "xaios-tools-0.1",
        model_uuid: Optional[bytes] = None,
        execution_mode: int = EXECUTION_EXACT,
    ) -> None:
        encoded_architecture = architecture_id.encode("ascii")
        encoded_converter = converter_version.encode("ascii")
        if not encoded_architecture or len(encoded_architecture) > 32:
            raise ValueError("architecture_id must be 1..32 ASCII bytes")
        if len(source_revision) != 32:
            raise ValueError("source_revision must be a 32-byte digest")
        if len(encoded_converter) > 16:
            raise ValueError("converter_version must fit in 16 ASCII bytes")
        if execution_mode not in (EXECUTION_EXACT, EXECUTION_APPROXIMATE):
            raise ValueError("invalid execution mode")
        self.architecture_id = architecture_id
        self.source_revision = source_revision
        self.converter_version = converter_version
        self.model_uuid = model_uuid or uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"xaios.model.v2:{architecture_id}:{source_revision.hex()}",
        ).bytes
        if len(self.model_uuid) != 16 or not any(self.model_uuid):
            raise ValueError("model_uuid must be 16 nonzero bytes")
        self.execution_mode = execution_mode
        self.sections: list[SectionSpec] = []
        self.tensors: list[TensorSpec] = []

    def add_section(self, spec: SectionSpec) -> None:
        if not spec.name or any(item.name == spec.name for item in self.sections):
            raise ValueError("section names must be nonempty and unique")
        if spec.source.length <= 0:
            raise ValueError("sections must be nonempty")
        align(0, spec.alignment)
        self.sections.append(spec)

    def add_tensor(self, tensor: TensorSpec) -> None:
        if not tensor.name or tensor.semantic_role <= 0:
            raise ValueError("tensor name and semantic role are required")
        if not 1 <= len(tensor.dimensions) <= MAX_RANK:
            raise ValueError("tensor rank must be 1..8")
        if len(tensor.strides) != len(tensor.dimensions):
            raise ValueError("tensor dimensions and strides must match")
        if any(value <= 0 for value in tensor.dimensions + tensor.strides):
            raise ValueError("tensor dimensions and strides must be positive")
        if tensor.data_offset < 0 or tensor.data_length <= 0:
            raise ValueError("tensor data range is invalid")
        align(0, tensor.alignment)
        self.tensors.append(tensor)

    def _required_section_index(self, section_type: int) -> int:
        matches = [
            index
            for index, spec in enumerate(self.sections)
            if spec.section_type == section_type
        ]
        if len(matches) != 1:
            raise ValueError(f"exactly one section of type {section_type} is required")
        return matches[0]

    def write(self, output_path: Path) -> None:
        required_types = (
            SECTION_ARCHITECTURE,
            SECTION_LAYER_PLAN,
            SECTION_TOKENIZER,
        )
        for section_type in required_types:
            self._required_section_index(section_type)
        if any(spec.section_type == SECTION_STRING_TABLE for spec in self.sections):
            raise ValueError("the writer owns the string-table section")

        names = [spec.name for spec in self.sections] + ["strings"]
        names.extend(tensor.name for tensor in self.tensors)
        string_offsets: dict[str, int] = {}
        string_data = bytearray()
        for name in names:
            encoded = name.encode("utf-8")
            if name not in string_offsets:
                string_offsets[name] = len(string_data)
                string_data.extend(encoded)
                string_data.append(0)
        all_sections = list(self.sections) + [
            SectionSpec(SECTION_STRING_TABLE, "strings", BytesSource(bytes(string_data)))
        ]

        section_directory_offset = IO_ALIGNMENT
        section_directory_end = section_directory_offset + (
            len(all_sections) * SECTION_DESCRIPTOR_SIZE
        )
        tensor_directory_offset = align(section_directory_end, IO_ALIGNMENT)
        tensor_directory_end = tensor_directory_offset + (
            len(self.tensors) * TENSOR_DESCRIPTOR_SIZE
        )
        cursor = align(tensor_directory_end, IO_ALIGNMENT)
        planned: list[_PlannedSection] = []
        for section_id, spec in enumerate(all_sections):
            offset = align(cursor, spec.alignment)
            if spec.requested_offset is not None:
                requested = align(spec.requested_offset, spec.alignment)
                if requested < offset:
                    raise ValueError("requested section offset overlaps metadata or payload")
                offset = requested
            planned.append(_PlannedSection(spec, section_id, offset))
            cursor = offset + spec.source.length
            if cursor >= 1 << 64:
                raise OverflowError("model package exceeds 64-bit offsets")
        file_size = cursor
        by_name = {item.spec.name: item for item in planned}
        string_section = by_name["strings"]

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w+b") as output:
            output.truncate(file_size)
            for item in planned:
                output.seek(item.offset)
                digest = hashlib.sha256()
                written = 0
                for chunk in item.spec.source.chunks(CHUNK_SIZE):
                    if not chunk or len(chunk) > CHUNK_SIZE:
                        raise ValueError("section source violated streaming chunk contract")
                    output.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
                if written != item.spec.source.length:
                    raise ValueError("section source length changed during conversion")
                item.checksum = digest.digest()
                item.name_offset = string_section.offset + string_offsets[item.spec.name]

            tensor_descriptors = []
            for index, tensor in enumerate(self.tensors):
                section = by_name.get(tensor.section_name)
                if section is None:
                    raise ValueError(f"unknown tensor section: {tensor.section_name}")
                if tensor.data_offset + tensor.data_length > section.spec.source.length:
                    raise ValueError("tensor data lies outside its section")
                absolute_data_offset = section.offset + tensor.data_offset
                if absolute_data_offset & (tensor.alignment - 1):
                    raise ValueError("tensor data offset does not meet alignment")
                output.seek(absolute_data_offset)
                digest = hashlib.sha256()
                remaining = tensor.data_length
                while remaining:
                    chunk = output.read(min(remaining, CHUNK_SIZE))
                    if not chunk:
                        raise IOError("short read while hashing tensor")
                    digest.update(chunk)
                    remaining -= len(chunk)
                absolute_scale_offset = 0
                if tensor.scale_length:
                    scale_section = by_name.get(
                        tensor.scale_section_name or tensor.section_name
                    )
                    if scale_section is None:
                        raise ValueError("unknown tensor scale section")
                    if (
                        tensor.scale_offset < 0
                        or tensor.scale_offset + tensor.scale_length
                        > scale_section.spec.source.length
                    ):
                        raise ValueError("tensor scales lie outside their section")
                    absolute_scale_offset = scale_section.offset + tensor.scale_offset
                tensor_descriptors.append(
                    self._tensor_descriptor(
                        tensor,
                        index,
                        absolute_data_offset,
                        absolute_scale_offset,
                        string_section.offset + string_offsets[tensor.name],
                        digest.digest(),
                    )
                )

            output.seek(section_directory_offset)
            for item in planned:
                output.write(self._section_descriptor(item))
            output.seek(tensor_directory_offset)
            for descriptor in tensor_descriptors:
                output.write(descriptor)

            header = bytearray(HEADER_SIZE)
            header[0:8] = MAGIC
            struct.pack_into("<HHBBBB", header, 8, VERSION_MAJOR, VERSION_MINOR,
                             ENDIAN_LITTLE, HASH_SHA256, self.execution_mode, 0)
            struct.pack_into(
                "<QQQQQQQQQQQQ",
                header,
                16,
                HEADER_SIZE,
                SECTION_DESCRIPTOR_SIZE,
                TENSOR_DESCRIPTOR_SIZE,
                file_size,
                section_directory_offset,
                len(planned),
                tensor_directory_offset,
                len(self.tensors),
                self._required_section_index(SECTION_ARCHITECTURE),
                self._required_section_index(SECTION_TOKENIZER),
                self._required_section_index(SECTION_LAYER_PLAN),
                len(planned) - 1,
            )
            header[112:128] = self.model_uuid
            header[128:160] = self.source_revision
            header[160:176] = self.converter_version.encode("ascii").ljust(16, b"\0")
            header[176:208] = self.architecture_id.encode("ascii").ljust(32, b"\0")
            header[208:240] = hashlib.sha256(header).digest()
            output.seek(0)
            output.write(header)

    @staticmethod
    def _section_descriptor(item: _PlannedSection) -> bytes:
        descriptor = bytearray(SECTION_DESCRIPTOR_SIZE)
        struct.pack_into(
            "<IIQQQQQII",
            descriptor,
            0,
            item.spec.section_type,
            item.spec.flags,
            item.section_id,
            item.offset,
            item.spec.source.length,
            item.spec.alignment,
            item.spec.shard_id,
            HASH_SHA256,
            0,
        )
        descriptor[56:88] = item.checksum
        struct.pack_into(
            "<QQ", descriptor, 88, item.name_offset, len(item.spec.name.encode("utf-8"))
        )
        return bytes(descriptor)

    @staticmethod
    def _tensor_descriptor(
        tensor: TensorSpec,
        index: int,
        absolute_data_offset: int,
        absolute_scale_offset: int,
        name_offset: int,
        checksum: bytes,
    ) -> bytes:
        descriptor = bytearray(TENSOR_DESCRIPTOR_SIZE)
        tensor_id = tensor.tensor_id or (index + 1)
        struct.pack_into(
            "<IIQQQQQIHHHHIQQQQQQQQQ",
            descriptor,
            0,
            tensor.flags,
            tensor.semantic_role,
            tensor_id,
            tensor.layer_id,
            tensor.expert_id,
            name_offset,
            len(tensor.name.encode("utf-8")),
            len(tensor.dimensions),
            tensor.logical_dtype,
            tensor.stored_dtype,
            tensor.quantization_scheme,
            tensor.scale_dtype,
            tensor.layout_id,
            tensor.required_backend,
            tensor.shard_id,
            absolute_data_offset,
            tensor.data_length,
            tensor.alignment,
            absolute_scale_offset,
            tensor.scale_length,
            tensor.quant_block_size,
            tensor.quant_group_size,
        )
        for index, value in enumerate(tensor.dimensions):
            struct.pack_into("<Q", descriptor, 136 + (index * 8), value)
        for index, value in enumerate(tensor.strides):
            struct.pack_into("<Q", descriptor, 200 + (index * 8), value)
        struct.pack_into("<I", descriptor, 264, HASH_SHA256)
        descriptor[272:304] = checksum
        return bytes(descriptor)


def read_header(path: Path) -> dict[str, object]:
    with path.open("rb") as package:
        header = package.read(HEADER_SIZE)
    if len(header) != HEADER_SIZE or header[:8] != MAGIC:
        raise ValueError("invalid model-v2 header")
    expected_hash = header[208:240]
    hash_input = bytearray(header)
    hash_input[208:240] = bytes(32)
    if hashlib.sha256(hash_input).digest() != expected_hash:
        raise ValueError("model-v2 header checksum mismatch")
    values = struct.unpack_from("<QQQQQQQQQQQQ", header, 16)
    result = {
        "version": list(struct.unpack_from("<HH", header, 8)),
        "endianness": header[12],
        "hash_algorithm": header[13],
        "execution_mode": header[14],
        "header_size": values[0],
        "section_descriptor_size": values[1],
        "tensor_descriptor_size": values[2],
        "file_size": values[3],
        "section_directory_offset": values[4],
        "section_count": values[5],
        "tensor_directory_offset": values[6],
        "tensor_count": values[7],
        "architecture_section_index": values[8],
        "tokenizer_section_index": values[9],
        "layer_plan_section_index": values[10],
        "string_table_section_index": values[11],
        "model_uuid": header[112:128].hex(),
        "source_revision": header[128:160].hex(),
        "converter_version": header[160:176].rstrip(b"\0").decode("ascii"),
        "architecture_id": header[176:208].rstrip(b"\0").decode("ascii"),
    }
    if result["file_size"] != path.stat().st_size:
        raise ValueError("model-v2 file size mismatch")
    return result


def build_miniature_package(path: Path, architecture_id: str = "qwen3_5") -> None:
    architecture = json.dumps(
        {
            "architectures": ["Qwen3_5ForConditionalGeneration"],
            "model_type": architecture_id,
            "status": "interface-only",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    writer = PackageWriter(
        architecture_id=architecture_id,
        source_revision=hashlib.sha256(architecture).digest(),
    )
    writer.add_section(
        SectionSpec(SECTION_ARCHITECTURE, "architecture", BytesSource(architecture))
    )
    writer.add_section(
        SectionSpec(SECTION_LAYER_PLAN, "layers", BytesSource(b'{"layers":[]}'))
    )
    writer.add_section(
        SectionSpec(SECTION_TOKENIZER, "tokenizer", BytesSource(b'{"type":"none"}'))
    )
    weights = struct.pack("<4f", 1.0, -2.0, 3.5, 0.25)
    weights = weights.ljust(IO_ALIGNMENT, b"\0")
    writer.add_section(
        SectionSpec(SECTION_DENSE_WEIGHTS, "dense", BytesSource(weights))
    )
    writer.add_tensor(
        TensorSpec(
            name="model.embed_tokens.weight",
            semantic_role=1,
            section_name="dense",
            data_offset=0,
            data_length=16,
            dimensions=(2, 2),
            strides=(8, 4),
        )
    )
    writer.write(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or create model-v2 fixtures")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-miniature")
    create.add_argument("output", type=Path)
    create.add_argument("--architecture", default="qwen3_5")
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("package", type=Path)
    args = parser.parse_args()
    if args.command == "create-miniature":
        build_miniature_package(args.output, args.architecture)
        return 0
    print(json.dumps(read_header(args.package), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
