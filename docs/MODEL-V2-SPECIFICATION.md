# xaios.model.v2 specification

Status: stable binary layout version 2.0. The current implementation parses,
writes, and validates package structure. It does not imply that any model
architecture can execute.

## Goals and non-goals

`xaios.model.v2` is the canonical, portable package boundary between model
importers, the hosted inference engine, and XAIOS services. It is designed for
streaming conversion and positional reads of multi-shard packages. It does not
extend the deterministic 80-byte model-v1 QEMU fixture.

All integers are unsigned little-endian unless a field says otherwise. Every
offset and length is 64-bit. Additions and multiplications must be checked for
overflow before use. Section payloads start on at least 4 KiB boundaries;
large expert and cache extents should start on 2 MiB boundaries.

## Header

The header is exactly 256 bytes. Its SHA-256 is calculated with bytes 208-239
set to zero.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic `XAIOSM2\0` |
| 8 | 2 | Major version, currently 2 |
| 10 | 2 | Minor version, currently 0 |
| 12 | 1 | Endianness, 1 for little-endian |
| 13 | 1 | Hash algorithm, 1 for SHA-256 |
| 14 | 1 | Execution mode, 1 exact or 2 explicit approximate |
| 15 | 1 | Header flags |
| 16 | 8 | Header size |
| 24 | 8 | Section descriptor size, 128 |
| 32 | 8 | Tensor descriptor size, 320 |
| 40 | 8 | Complete file size |
| 48 | 8 | Section-directory offset |
| 56 | 8 | Section count |
| 64 | 8 | Tensor-directory offset |
| 72 | 8 | Tensor count |
| 80 | 8 | Architecture-section index |
| 88 | 8 | Tokenizer-section index |
| 96 | 8 | Ordered layer-plan-section index |
| 104 | 8 | String-table-section index |
| 112 | 16 | Model UUID/content identity |
| 128 | 32 | SHA-256 source-revision identity |
| 160 | 16 | NUL-padded conversion-tool version |
| 176 | 32 | NUL-padded official architecture identifier |
| 208 | 32 | Header SHA-256 |
| 240 | 16 | Reserved, zero |

Architecture identity comes from official configuration fields. Display names
are not identifiers. The existing `xaios_fixture` entry is synthetic test
metadata, not evidence for any Qwen architecture identifier. Kimi K3 packages
use `model_type=kimi_k3`.

## Section directory

Each 128-byte descriptor contains: type and flags (32-bit), section ID,
offset, length, alignment and shard ID (64-bit), checksum algorithm, SHA-256,
and a string-table name offset/length. Current section types are architecture
configuration, ordered layer plan, tokenizer, string table, dense weights,
expert weights, vision metadata, and integrity metadata.

Every nonempty section has its own SHA-256. Admission can therefore validate
metadata and selected shards incrementally without reading or copying all
weights. Sections are ordered by increasing non-overlapping file offset.

Architecture configuration must preserve the official `architectures`,
`model_type`, nested text/vision configuration, operator-specific fields,
special-token semantics, context limits, exactness metadata, and unsupported
fields. The ordered layer plan records every layer type rather than deriving a
generic transformer from a model name.

## Tensor directory

Each 320-byte descriptor contains:

- flags/storage class, semantic role and tensor ID;
- 64-bit layer and expert IDs, using `UINT64_MAX` when absent;
- string-table name offset and length;
- rank, up to eight 64-bit dimensions and eight 64-bit byte strides;
- logical dtype, stored dtype, quantization scheme and scale dtype;
- packed-layout ID and required backend/ISA capabilities;
- shard ID, data offset/length and required alignment;
- scale offset/length and quantization block/group dimensions;
- checksum algorithm and SHA-256.

Expert lookup uses `(model_uuid, layer_id, expert_id, layout_id)`. Dense spine
and expert sections are separate. Every expert must be independently
addressable and checksumable. Canonical portable layouts may be accompanied by
generated hardware packs, but hardware-specific data cannot be the sole copy.

## Tokenizer section

The tokenizer payload is owned by one package, never global process state. A
production tokenizer encoding must include an algorithm/version, complete
vocabulary with byte-preserving token text, merges or rules, added and special
tokens, BOS/EOS/padding IDs, normalization, pre-tokenization, chat template,
and multimodal placeholders. The current writer treats this payload as opaque;
the miniature packages use metadata only and are not tokenizer support.

`create-kimi-k3-miniature` writes a deterministic CI-scale `kimi_k3` package
with dense, KDA, gated-MLA and sparse-MoE layer metadata. Its 20 independently
addressable expert descriptors activate exactly 16 experts and include native
32-value MXFP4/E2M1 blocks with E8M0 scales. The companion scalar gate checks
KDA recurrence, causal MLA cache and output gating, correction-biased sigmoid
routing, stable routed/shared-expert reduction and SiTU. This is miniature
operator and package-format evidence, not tokenizer, checkpoint or token parity.

## Validation and security

Readers must reject wrong magic/version/endianness, unsupported descriptor
sizes, zero identities, out-of-range or overlapping extents, insufficient
alignment, unknown required hash algorithms, integer overflow, invalid ranks,
zero dimensions, and checksum corruption. Parsing returns an error and never
panics the host or kernel.

The hosted implementation is in `engine/src/model_v2.c`; the streaming writer
and Python reader are in `tools/xaios_model_v2.py`. `make hosted-test` covers
Python-to-C round trips, sparse files beyond 4 GiB, malformed offsets,
overflow, corruption, and bounded streaming chunks.
