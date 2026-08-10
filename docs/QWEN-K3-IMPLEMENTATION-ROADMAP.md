# Qwen, Kimi, DeepSeek and GLM implementation roadmap

This roadmap is dependency ordered. The declared XAIOS QEMU platform gate now
passes, so Qwen 3.6 27B correctness is the active workstream 2. An interface or
fixture is not model support, and Kimi K3 text
support is not multimodal support. Later model-family targets enter only after
the XAIOS and Qwen gates, plus their own immutable official source and
architecture-contract prerequisites.

## Delivery sequence

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | QEMU Complete | ARM and x86 common-service correctness gates pass; physical platform qualification remains separate. |
| 2 | Qwen 3.6 27B Support | Ready | Next workstream; begin scalar tokenizer, tensor and logits correctness. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

## Verified baseline, 2026-08-01

- The kernel model-v1 path tokenizes at most 32 input bytes and emits an
  XOR-derived hexadecimal fixture, not transformer logits.
- The retired GGUF converter and model-v1 reader disagreed on layout,
  quantization, tokenizer and checksum semantics. Conversion now fails closed.
- BPE state is global and capped at 32,768 tokens/8,192 rules, below the
  official Qwen3.5/3.6 and Kimi K3 vocabularies.
- The former INT4/INT6 kernel paths expanded full matrices and leaked INT6
  allocations. Current source uses no-expand packed loops and correct tail/row
  addressing; its compatibility work-unit entrypoint remains sequential.
- Model admission copies the complete image and inference session/batching paths
  remain QEMU-scale prototypes. The x86_64 image executes shared CRC/block/VFS/
  engine probes, while EL0, interrupts/SMP, PCI VirtIO and full parity remain open.
- A native macOS/Linux engine CLI and caller-owned service boundary exist. No
  complete model executes through the Apple CPU path, and no Metal backend
  exists.

## Completed foundation

- [x] Architecture-correct compile CI with independent ABI, hosted, smoke and
  regression jobs.
- [x] Honest support status and benchmark evidence policy.
- [x] Explicit model-v1 deterministic fixture path and unsupported production
  decode behavior.
- [x] Stable `xaios.model.v2` binary layout with 64-bit offsets/counts,
  sections, tensors, SHA-256 and sparse-file coverage above 4 GiB.
- [x] Streaming Python package writer and C reader round trip.
- [x] Architecture-adapter/backend interfaces and scalar dense-projection
  canary.
- [x] Portable group-scaled INT4/INT6 no-expand scalar GEMV/GEMM plus
  experimental AArch64 NEON backend, startup canary, randomized differential
  tests, and every packing tail. Experimental AVX2 known-answer execution also
  passes under x86 QEMU TCG. This is microkernel correctness, not model parity
  or physical performance evidence.

## Workstream 1: XAIOS completion gate

- [x] Add the portable caller-owned engine/service boundary, immutable reader
  admission, direct async range I/O and native macOS/Linux CLI.
- [x] Replace fixed RAM/CPU bitmap and worker-dispatch limits with runtime-sized
  NUMA/CPU/cpuset state and CPU-assigned joinable worker threads.
- [x] Link portable common CRC/block/VFS/engine components into x86_64.
- [x] Prove x86 controlled exception, local-APIC timer and shared-driver MSI-X
  completion delivery plus modern VirtIO PCI discovery under QEMU.
- [x] Start MADT-discovered x86 APs, dispatch IPI work, validate GDT/TSS ring-3
  syscall entry and XSAVE/FXSAVE interrupt state, and operate modern VirtIO
  block/network plus emulated NVMe.
- [x] Port the complete ARM EL0/thread ABI, receive networking/SSH, mounted
  filesystems, security, AI Cell and telemetry services to the x86 QEMU image.
- [x] Replace copied production model admission with no-copy immutable 64-bit
  mappings and add lifecycle-safe 64-bit session metadata.
- [ ] Complete typed reusable model state, prefix COW, ragged batching and exact
  target-authoritative speculation.
- [ ] Pass release/security gates and record physical-hardware entry evidence.

## Workstream 2: Qwen config and tokenizer (ready)

- [ ] Add a SafeTensors/config/tokenizer importer that streams tensor payloads.
- [ ] Pin immutable official Qwen3.5-0.8B files and preserve unknown config
  fields.
- [ ] Implement package-owned tokenizer data and exact tokenizer parity corpus.
- [ ] Implement the `qwen3_5` adapter's ordered hybrid layer plan and reject
  unsupported fields.
- [ ] Add scalar embedding, RMSNorm and one configured projection with Python
  reference parity.
- [ ] Add conversion RSS evidence showing payload-size-independent memory.

## Qwen scalar correctness (workstream 2)

- [ ] Implement full and linear attention, convolution/recurrent state,
  grouped-query attention, causal masking, configured mRoPE, SwiGLU, residuals,
  output norm/head and logits.
- [ ] Separate prefill and decode plans with actual per-layer state.
- [ ] Pass tokenizer, embedding, complete-layer, prefill-logit and 32-step
  deterministic decode golden gates, including save/reload continuity.

## Qwen packed backends and serving state (workstream 2)

- [x] No-expand scalar and AArch64 NEON INT4/INT6 GEMV/GEMM with
  differential/tail tests, plus an experimental AVX2 QEMU canary path.
- [ ] Physical AVX2 differential validation and tiled prefill/verification
  GEMM.
- [ ] Native macOS process and optional Metal backend.
- [ ] AVX-512/VNNI/AMX capability canaries, persistent worker gangs and NUMA
  placement.
- [ ] Typed paged state with prefix COW, branching/rollback, ragged continuous
  batching and exact speculative equivalence.

## Later backlog: Kimi K3 text

- [ ] Implement a separate `kimi_k3` adapter from an immutable official config.
- [ ] Add KDA, Gated MLA, AttnRes, exact top-16 Stable LatentMoE routing, shared
  experts, SiTU, native MXFP4 and long-context state.
- [ ] Build a miniature executable K3 package and golden KDA/MLA/router/expert/
  reduction tests.
- [ ] Add independently addressable expert shards, async expert cache/prefetch
  and exact speculative expert-union tracking.
- [ ] Pass tokenizer, operator, router/expert, target-token and production-width
  checkpoint metadata gates on physical hardware.

## Later backlog: Kimi K3 multimodal and scale-out

- [ ] Validate MoonViT-V2 preprocessing, projection, multimodal positions,
  placeholders/chat template and golden image cases as a separate milestone.
- [ ] Add large-memory mappings, real NUMA discovery, NVMe multiqueue and
  expert ownership across NUMA nodes/machines.
- [ ] Add immutable Apple and Xeon benchmark artifacts under
  `docs/BENCHMARK-CONTRACT.md`.

## Later backlog: additional architecture targets

These targets reuse the model-v2 package, architecture registry, backend API
and scalar parity harness. They do not reuse another model's execution plan
unless official configuration and operator metadata prove that compatibility.

- [ ] **DeepSeek V4 Flash 0731:** verify the exact official release label and
  source revision before defining tensor roles, routing/state semantics or
  quantization support.
- [ ] **GLM 5.2:** pin the official source revision, then implement and validate
  a separate adapter for its configured sparse-attention/MoE operations and
  long-context state.
- [ ] For every target, pass tokenizer, tensor import, operator/layer, prefill
  logits, deterministic decode, session-state and physical-hardware gates
  before changing its status from `Roadmap only`.

## Official compatibility sources

- [Qwen3.5-0.8B official configuration](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/main/config.json)
- [Qwen3.6-27B official configuration](https://huggingface.co/Qwen/Qwen3.6-27B/blob/main/config.json)
- [Qwen3.6 official repository](https://github.com/QwenLM/Qwen3.6)
- [Kimi K3 official configuration](https://huggingface.co/moonshotai/Kimi-K3/blob/main/config.json)
- [Kimi K3 official repository and report](https://github.com/MoonshotAI/Kimi-K3)
- [GLM 5.2 official model repository](https://huggingface.co/zai-org/GLM-5.2)

Before coding against these sources, record an immutable revision and verify
that the official architecture/configuration has not changed. An authoritative
source for the exact label DeepSeek V4 Flash 0731 remains an open prerequisite.
