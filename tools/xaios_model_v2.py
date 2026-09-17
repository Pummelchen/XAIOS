#!/usr/bin/env python3
"""Streaming writer and inspection helpers for the xaios.model.v2 package.

This module is deliberately independent of GGUF, SafeTensors, NumPy, and the
kernel. Importers provide validated section streams and tensor metadata; this
writer lays them out deterministically without retaining weight payloads.

The package format itself -- the constant table, the section sources, the
``PackageWriter`` and ``read_header`` -- lives in ``xaios_model_v2_core``
beside this file. Its public names are re-exported here, so
``from xaios_model_v2 import ...`` keeps working for the hosted test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from xaios_model_v2_core import (
    CHUNK_SIZE,
    ENDIAN_LITTLE,
    EXECUTION_APPROXIMATE,
    EXECUTION_EXACT,
    EXPERT_ALIGNMENT,
    FileSource,
    HASH_SHA256,
    HEADER_SIZE,
    INDEX_NONE,
    IO_ALIGNMENT,
    MAGIC,
    MAX_RANK,
    PackageWriter,
    SECTION_ARCHITECTURE,
    SECTION_DENSE_WEIGHTS,
    SECTION_DESCRIPTOR_SIZE,
    SECTION_EXPERT_WEIGHTS,
    SECTION_INTEGRITY,
    SECTION_LAYER_PLAN,
    SECTION_STRING_TABLE,
    SECTION_TENSOR_DIRECTORY,
    SECTION_TOKENIZER,
    SECTION_VISION,
    SectionSource,
    SectionSpec,
    TENSOR_CACHEABLE,
    TENSOR_DESCRIPTOR_SIZE,
    TENSOR_RESIDENT,
    TENSOR_STREAMABLE,
    TensorSpec,
    VERSION_MAJOR,
    VERSION_MINOR,
    align,
    BytesSource,
    read_header,
)

def build_miniature_package(path: Path, architecture_id: str = "xaios_fixture") -> None:
    architecture = json.dumps(
        {
            "architectures": ["XAIOSFixtureForCausalLM"],
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


def build_kimi_k3_miniature_package(path: Path) -> None:
    """Write the executable CI-scale K3 metadata and native-block fixture."""
    architecture_data = {
        "architectures": ["KimiK3ForConditionalGeneration"],
        "model_type": "kimi_k3",
        "text_model_type": "kimi_linear",
        "status": "miniature-reference-only",
        "hidden_size": 4,
        "num_hidden_layers": 4,
        "layer_types": ["dense", "kda", "gated_mla", "sparse_moe"],
        "num_experts": 20,
        "num_experts_per_token": 16,
        "num_shared_experts": 2,
        "activation": "situ",
        "weight_quantization": "mxfp4_e2m1",
    }
    architecture = json.dumps(
        architecture_data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    layer_plan = json.dumps(
        {
            "layers": [
                {"id": 0, "type": "dense"},
                {"id": 1, "type": "kda", "state": ["conv", "recurrent"]},
                {"id": 2, "type": "gated_mla", "state": ["latent_kv"]},
                {"id": 3, "type": "sparse_moe", "top_k": 16, "shared": 2},
            ]
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    writer = PackageWriter(
        architecture_id="kimi_k3",
        source_revision=hashlib.sha256(architecture).digest(),
        converter_version="xaios-k3-mini-1",
    )
    writer.add_section(
        SectionSpec(SECTION_ARCHITECTURE, "architecture", BytesSource(architecture))
    )
    writer.add_section(
        SectionSpec(SECTION_LAYER_PLAN, "layers", BytesSource(layer_plan))
    )
    writer.add_section(
        SectionSpec(
            SECTION_TOKENIZER,
            "tokenizer",
            BytesSource(b'{"type":"none","status":"not-tokenizer-support"}'),
        )
    )
    dense = struct.pack("<16f", *[float(index) / 8.0 for index in range(16)])
    writer.add_section(
        SectionSpec(
            SECTION_DENSE_WEIGHTS,
            "dense",
            BytesSource(dense.ljust(IO_ALIGNMENT, b"\0")),
        )
    )
    writer.add_tensor(
        TensorSpec(
            name="model.layers.1.kda.q_proj.weight",
            semantic_role=101,
            section_name="dense",
            data_offset=0,
            data_length=len(dense),
            dimensions=(4, 4),
            strides=(16, 4),
            layer_id=1,
        )
    )
    expert_extents = bytearray(20 * IO_ALIGNMENT)
    for expert in range(20):
        extent = expert * IO_ALIGNMENT
        expert_extents[extent : extent + 16] = bytes(
            ((expert + index) & 0xFF) for index in range(16)
        )
        expert_extents[extent + 16] = 127
        writer.add_tensor(
            TensorSpec(
                name=f"model.layers.3.experts.{expert}.weight",
                semantic_role=201,
                section_name="experts",
                data_offset=extent,
                data_length=16,
                dimensions=(32,),
                strides=(1,),
                flags=TENSOR_CACHEABLE | TENSOR_STREAMABLE,
                layer_id=3,
                expert_id=expert,
                stored_dtype=4,
                quantization_scheme=4,
                scale_dtype=5,
                layout_id=1,
                alignment=IO_ALIGNMENT,
                scale_section_name="experts",
                scale_offset=extent + 16,
                scale_length=1,
                quant_block_size=32,
                quant_group_size=32,
            )
        )
    writer.add_section(
        SectionSpec(
            SECTION_EXPERT_WEIGHTS,
            "experts",
            BytesSource(bytes(expert_extents)),
            alignment=EXPERT_ALIGNMENT,
        )
    )
    writer.write(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or create model-v2 fixtures")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-miniature")
    create.add_argument("output", type=Path)
    create.add_argument("--architecture", default="xaios_fixture")
    create_k3 = subparsers.add_parser("create-kimi-k3-miniature")
    create_k3.add_argument("output", type=Path)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("package", type=Path)
    args = parser.parse_args()
    if args.command == "create-miniature":
        build_miniature_package(args.output, args.architecture)
        return 0
    if args.command == "create-kimi-k3-miniature":
        build_kimi_k3_miniature_package(args.output)
        return 0
    print(json.dumps(read_header(args.package), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
