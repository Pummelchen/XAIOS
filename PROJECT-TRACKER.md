# XAIOS project tracker

Last updated: 2026-08-04. Status labels and delivery order are checked against
[`docs/MODEL-SUPPORT.json`](./docs/MODEL-SUPPORT.json). A checked interface is
not equivalent to executing-model support. Platform recommendation status is
authoritative in [`docs/PLATFORM-SUPPORT.json`](./docs/PLATFORM-SUPPORT.json).

## Support status

| Model or path | Status | Exit criterion |
|---|---|---|
| Deterministic QEMU model-v1 path | Fixture only | Remains limited to OS/runtime correctness and ABI gates. |
| xaios.model.v2 tooling | Interface only | Production importer, tokenizer schema and executing engine integration still required. |
| Qwen 3.6 27B | Interface only | Official tokenizer, layer/logit parity, 32-step decode parity and physical execution. |
| Kimi K3 text | Interface only | KDA/MLA/MoE/MXFP4 parity, target-token parity and physical execution. |
| Kimi K3 multimodal | Roadmap only | Vision preprocessing/tower/projection/position and golden multimodal parity. |
| DeepSeek V4 Flash 0731 | Roadmap only | Verify and pin the exact official release before defining its adapter and correctness gates. |
| GLM 5.2 | Roadmap only | Pin official sources, implement a separate adapter, and pass tokenizer/operator/logit parity. |

## Delivery sequence

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | In Progress | Finish the core OS, portable engine, model-v2 integration, platform services, hardware readiness, and release gates. |
| 2 | Qwen 3.6 27B Support | Blocked | Starts only after the XAIOS completion gate. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

## Completed foundation

- [x] AArch64 UEFI/QEMU OS bring-up and deterministic system fixtures.
- [x] Architecture-correct compile checks for AArch64 and x86_64 source.
- [x] Independent CI jobs so ABI, hosted engine, docs, smoke and regression
  results are visible even when another job fails.
- [x] QEMU contract synchronized through syscall 46 and current initfs
  capacity/paths.
- [x] Production decode fails with an unsupported error; deterministic decode
  is explicitly selected as `XAIOS_ML_MODEL_FIXTURE_DECODE`.
- [x] Stable model-v2 header/section/tensor binary layout and SHA-256 rules.
- [x] Streaming Python writer and on-demand C reader with >4 GiB sparse-file,
  corruption, malformed-range and overflow tests.
- [x] Portable architecture/backend interfaces and scalar projection canary.
- [x] Benchmark evidence contract and removal of unevidenced throughput claims.
- [x] Phase 1 `xaiosctl` read-only administration foundation: versioned bounded
  protocol, capability/role gate, deterministic JSON, measured state, log
  cursors/redaction, exact SSH allowlist and Debian OpenSSH coverage.
- [x] Phase 2 fixture-tested administrative security: observer/operator/admin
  Ed25519 principals, persistent revocation, strict configuration transactions,
  replay-protected mutations, host-key rotation, redacted audit, per-connection
  session state and Debian 13 OpenSSH/QEMU acceptance coverage.
- [x] Replace the fixed 256-page userspace image tracker with dynamically sized,
  overflow-checked mapping ownership and cleanup.

## Workstream 1: active XAIOS completion

- [x] Complete distributed-server Phase 1 (`xaiosctl` foundation).
- [x] Complete Phase 2 administrative roles, configuration transactions, key
  management and audit commands at the QEMU fixture-tested evidence level.
- [x] Add a separate signed immutable large-model volume with hosted lifecycle,
  fsck/scrub/grow/trim tools, immutable QEMU reads, and sparse >100 GiB reader
  gates.
- [x] Add authenticated dynamic ModelFS registration, resumable SFTP staging,
  complete verification, replay-protected activation, cleanup/reuse and
  immutable concurrent macOS/Debian download coverage against one QEMU guest.
- [x] Add bounded typed guest block-device and mounted-filesystem list/show,
  mount-status and usage queries with stable human/JSON rendering.
- [x] Add scalar and experimental AArch64 NEON no-expand INT4/INT6 GEMV/GEMM
  with startup canaries and randomized differential/tail tests.
- [x] Add capability-gated experimental AVX2 no-expand GEMV/GEMM and execute
  INT4/INT6 startup canaries under x86 QEMU TCG.
- [x] Add QEMU-testable online GPT/ModelFS lifecycle, dynamic staging allocation,
  fsck/repair, grow, persisted scrub/quarantine, free-only trim/discard, and
  staged-extent reclamation.
- [x] Replace the single outstanding QEMU VirtIO path with interrupt-dispatched
  block/network completions, event-index suppression, indirect descriptors,
  eight concurrent direct-or-bounce block requests, scatter/gather network
  transmit and batched multi-sector backend transfers.
- [x] Add a focused QEMU NVMe admin/I/O queue path and validate identify,
  write/flush/read plus backing-image bytes.
- [ ] Add production NVMe multiqueue, PRP/SGL, interrupt affinity, direct
  final-buffer reads and physical durability/discard validation.
- [x] Add a caller-owned portable engine/service boundary with native macOS and
  Linux CLI entrypoints, immutable reader-backed model admission, explicit
  backend/adapter selection and fail-closed unsupported execution.
- [x] Replace fixed RAM/CPU bitmap ceilings with runtime-sized NUMA metadata,
  CPU registries, cpusets/core leases and CPU-assigned joinable worker threads;
  hosted cpusets cover 4,097 CPU IDs and the focused QEMU gate boots 130 CPUs.
- [x] Replace copied four-slot model admission with dynamically registered,
  immutable, no-copy 64-bit mappings; retain copied admission only for the
  explicitly named model-v1 fixture.
- [x] Add 64-bit lifecycle-safe session metadata with append, fork, commit,
  rollback, snapshot and reference-safe destruction tests.
- [ ] Replace fixture batching and session metadata with typed model state,
  prefix COW, ragged batching and exact target-authoritative speculation.
- [x] Link and execute portable common CRC/block/VFS/engine components on x86_64.
- [x] Validate x86 controlled exception delivery, a real local-APIC timer
  interrupt, and modern VirtIO/MSI/MSI-X PCI capability discovery under QEMU.
- [x] Start all MADT-discovered x86 APs through an OS-owned trampoline and
  dispatch deterministic IPI work with dynamically sized CPU records.
- [x] Add an OS-owned x86 GDT/TSS, a user-only mapping and a ring-3 `int 0x80`
  syscall/exit round trip.
- [x] Execute modern PCI VirtIO block DMA, MSI-X completion delivery and
  VirtIO-network DMA transmit under x86 QEMU.
- [ ] Port the complete ARM EL0 process/thread ABI, receive-side networking,
  filesystems, SSH/control/security, AI Cell and telemetry services for full
  x86_64 OS parity.
- [x] Add cumulative/partial ACK TCP sliding-window transmit with up to eight
  retained segments, SACK, fast retransmit, zero-window handling, bounded
  reordering and RTO backoff.
- [x] Add bounded out-of-order IPv4/IPv6 fragment reassembly and exercise it
  from macOS and Debian clients during concurrent SSH/SFTP/UDP load.
- [x] Wire asynchronous DNS retry/cache behavior to an EL0 resolver syscall.
- [x] Add EL0 thread create/join/cancel/exit over runtime-sized CPU metadata.
- [x] Add focused QEMU SMMUv3 translated-DMA authorization, fault and stale-map
  revocation evidence.
- [x] Add kill/reboot crash-consistency gates for both redundant system-slot
  metadata write points.
- [x] Add `make qemu-core-os-rc` as a non-skipping aggregate evidence gate.
- [x] Add `make qemu-high-core-gate` for >128-CPU SMP/NUMA capacity evidence
  without treating TCG duration as physical scalability evidence.
- [ ] Complete security, release-readiness and physical-hardware entry gates.
- [x] Keep QEMU evidence limited to correctness and ABI claims.

Qwen and every other model-family implementation remain gated until these
platform criteria and the XAIOS GitHub milestone are complete.

## Workstream 2: Qwen correctness MVP (blocked on XAIOS)

- [ ] Pin immutable Qwen3.5-0.8B config, tokenizer and SafeTensors fixtures.
- [ ] Implement streaming SafeTensors/config/tokenizer importer.
- [ ] Implement package-owned tokenizer and trusted ID corpus.
- [ ] Build `qwen3_5` ordered hybrid layer plan from official fields.
- [ ] Implement scalar embedding, RMSNorm and first projection parity.
- [ ] Implement configured linear/full attention, convolution/recurrent state,
  GQA, masking, mRoPE, feed-forward, residual and output head.
- [ ] Pass embedding, complete-layer, prefill-logit, 32-step decode and session
  reload golden gates.

## Qwen follow-on: packed hardware backends and sessions

- [x] Replace full-matrix INT4/INT6 expansion with direct packed scalar/NEON
  kernels for the implemented GEMV/GEMM correctness boundary.
- [x] Add scalar differential and randomized packing-tail tests before NEON
  selection.
- [ ] Physically validate AVX2 differentials; add tiled prefill/verification
  kernels, persistent worker pools, bandwidth autotuning, and production
  model-layout integration.
- [x] Build a native macOS/Linux engine CLI and caller-owned service boundary.
- [ ] Execute real model plans through the Apple CPU backend and add the
  optional Metal backend.
- [ ] Add AVX-512/VNNI and AMX capability canaries.
- [ ] Add persistent NUMA-aware worker gangs and bandwidth-knee autotuning.
- [ ] Replace prototype state/batching/speculation with typed state, prefix COW,
  branch/commit/rollback, ragged batching and exact target verification.

## Later backlog: Kimi K3 text

- [ ] Implement the separate `kimi_k3` architecture adapter.
- [ ] Preserve exact top-16 routing; predictive routing may affect prefetch only.
- [ ] Implement KDA, Gated MLA, AttnRes, shared experts, SiTU and native MXFP4.
- [ ] Add independently addressable expert extents and asynchronous expert
  residency/cache policy.
- [ ] Pass a miniature K3 metadata/operator/router/expert/reduction fixture.
- [ ] Pass real checkpoint tokenizer and target-token parity on physical hardware.

## Later backlog: Kimi K3 multimodal

- [ ] Implement MoonViT-V2 preprocessing and vision tower.
- [ ] Implement vision-language projection and multimodal positions.
- [ ] Match official special-token and chat-template behavior.
- [ ] Pass separate golden image/text cases before advertising full K3 support.

## Later backlog: additional model architecture targets

- [ ] Pin immutable official source, configuration, tokenizer and tensor-index
  revisions for DeepSeek V4 Flash 0731 and GLM 5.2.
- [ ] Probe official architecture identifiers and reject unknown configuration
  fields before building execution plans.
- [ ] Implement each family as a separate architecture adapter rather than
  adding model-name conditionals to Qwen or Kimi code.
- [ ] Define per-model tokenizer, layer/operator, state, logits, deterministic
  decode and physical-hardware acceptance gates.

## OS and scale-out dependencies

- [x] Link and execute the portable common-runtime subset in the x86_64 image.
- [ ] Replace fixed-size physical/virtual/model allocators with sparse,
  multi-terabyte-capable structures and large pages.
- [x] Parse and checksum x86 MADT/SRAT/SLIT/HMAT with dynamic xAPIC/x2APIC and
  64-bit memory-affinity records; QEMU exposes only the available subset.
- [ ] Apply SRAT/SLIT/HMAT policy to production allocators and track local and
  remote inference bytes.
- [ ] Add asynchronous NVMe multiqueue and direct final-buffer reads.
- [ ] Dispatch real inference work to secondary CPUs and AI Cell leases.
- [ ] Add NUMA/machine expert ownership, stable reduction and failure handling.

## Evidence gates

- `make compile-check`
- `make hosted-test`
- `make docs-check`
- `make qemu-abi-contract`
- `make qemu-smoke`
- `make qemu-regression-suite`

QEMU gates are correctness evidence only. Physical performance claims require
immutable artifacts satisfying
[`docs/BENCHMARK-CONTRACT.md`](./docs/BENCHMARK-CONTRACT.md).

Detailed dependency order and official source links are in
[`docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md`](./docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md).
The OS/control/storage/cluster sequence is tracked in
[`docs/DISTRIBUTED-AI-SERVER-PLAN.md`](./docs/DISTRIBUTED-AI-SERVER-PLAN.md).
