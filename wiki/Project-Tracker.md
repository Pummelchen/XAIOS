# Project Tracker

Last reviewed: 2026-08-14.

The current QEMU closure revision passes hosted, AArch64/x86_64 smoke, libc,
dual-architecture all-queue NVMe interrupt, SVE2 per-task context, x86 HMAT/
1-GiB/TLB, MutableFS-v5 migration/scale, TLS xapt, and external network gates.
The final consolidated report deliberately retains
`physical_qualification=false`.

This is the only human-maintained XAIOS project tracker. Roadmaps, milestones,
phase plans, open decisions, and risks are consolidated here. The Wiki does not
retain previous tracker, roadmap, milestone, or phase-plan pages.

This page tracks open work only. Completed rows are removed after their named
evidence gates pass; implementation history remains available in Git and the
linked test evidence.

## Status codes

| Code | Meaning |
|---|---|
| `TESTING` | Implemented, but the current acceptance run or physical qualification is still underway. |
| `IN PROGRESS` | Active implementation is incomplete. |
| `NOT STARTED` | No qualifying implementation has begun. An interface or fixture alone does not count. |
| `BLOCKED` | Work cannot proceed until the stated external decision or dependency is resolved. |
| `FAILED` | The latest required acceptance gate failed; the failure evidence must be linked in the item. |

QEMU status proves correctness and ABI behavior only. Physical support and
performance require immutable evidence under the
[benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).

## Delivery order

| Order | Workstream | Status | Current boundary / exit gate |
|---:|---|---|---|
| 1b | Physical Apple/ARM, Intel desktop, and Xeon qualification | `NOT STARTED` | Named hardware must pass firmware, device, durability, security, ISA-state, NUMA, soak, and benchmark contracts. |
| 2 | Qwen 3.8 support | `NOT STARTED` | Begins after physical platform qualification is accepted or explicitly deferred; official tokenizer, layer, logits, 32-step decode, session, and physical gates must pass. |
| 3 | Kimi K3 text support | `NOT STARTED` | Begins after Qwen unless reprioritized; KDA, Gated MLA, exact top-16 MoE, MXFP4, and token parity are mandatory. |
| 4 | Kimi K3 multimodal support | `NOT STARTED` | Separate vision preprocessing/tower/projection/position and golden image gates. |
| 5 | DeepSeek V4 Flash 0731 support | `BLOCKED` | The exact official release label and immutable source must be verified first. |

## Model support boundary

| Model or format | Progress | Support boundary | Completion gate |
|---|---|---|---|
| Qwen 3.8 | `NOT STARTED` | Roadmap target; no architecture adapter is claimed | Pin an immutable official configuration before tokenizer, tensor, layer, prefill-logit, decode, session, backend, and physical parity work. |
| Kimi K3 text | `NOT STARTED` | Interface only | KDA/MLA/MoE/MXFP4/operator and target-token parity on a real checkpoint. |
| Kimi K3 multimodal | `NOT STARTED` | Roadmap only | Separate official vision and multimodal golden acceptance. |
| DeepSeek V4 Flash 0731 | `BLOCKED` | Roadmap only | Verify exact official source before architecture work. |

## Platform recommendations

Only open ARM/Intel/platform recommendations remain here. The complete numbered
catalog stays in `docs/PLATFORM-SUPPORT.json`; no secondary page owns progress
status.

| # | Recommendation | Status | Evidence / remaining gate |
|---:|---|---|---|
| P-05 | Physical Apple NEON evidence | `NOT STARTED` | QEMU cannot satisfy this physical gate. |
| P-07 | SVE/SVE2 backend | `IN PROGRESS` | ARM64 QEMU executes the SVE2 canary and preserves per-task Z/P/FFR state across scheduling and interrupts. Packed inference kernels, scalar-model differential tests, and physical qualification remain; backend selection stays fail closed. |
| P-14 | Physical Intel/Xeon evidence | `NOT STARTED` | Physical firmware, ISA, NUMA, storage, network, thermals, and sustained-load gates remain. |

## Core OS, network, and SSH phases

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| N-F3P | Physical SSH/network security qualification | `IN PROGRESS` | Consolidated QEMU network/SSH readiness evidence is available through `make qemu-qualification-readiness`; physical lossy-link, sustained-load, side-channel analysis, and independent SSH/cryptography review remain open. QEMU evidence cannot close this item. |

## Storage phases

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| S-11P Physical production NVMe qualification | `IN PROGRESS` | Consolidated QEMU NVMe and crash-recovery evidence is available through `make qemu-qualification-readiness`; named physical devices must still pass queue scaling, interrupt affinity, FUA/flush/discard semantics, reset recovery, power-loss durability, sustained-load, and performance gates. QEMU evidence cannot close this item. |
| S-12 Trusted-replica repair and production key custody | `BLOCKED` | Depends on production trust and repair-source decisions. |

## Distributed AI server phases

| Phase | Status | Exit gate |
|---|---|---|
| D-05 Real local inference | `NOT STARTED` | Real Qwen correctness, typed state, scheduling, cancellation, backpressure, and metrics. |
| D-06 Authenticated cluster control | `IN PROGRESS` | Hosted tests cover directional HMAC framing, receiver/epoch/nonce validation, replay rejection, and membership transitions. The next QEMU-testable tranche is asynchronous transport between independent XAIOS guests plus join, partition, recovery, and ownership-version tests. |
| D-07 Distributed placement/execution | `IN PROGRESS` | Hosted tests cover deterministic expert ownership, grouped routing, simulated node-loss rerouting, and stable node/expert reduction. End-to-end distributed activation execution depends on D-05 real local inference and D-06 guest transport; it cannot be closed by hosted placement tests alone. |
| D-08 Benchmarks/diagnostics | `IN PROGRESS` | QEMU benchmark telemetry and a hashed qualification-readiness report are implemented; physical metadata-rich NUMA, bandwidth, PMU, thermal, storage, network, and redacted support-bundle evidence remain. |
| D-09 Production inference service | `NOT STARTED` | Authenticated API, streaming, cancellation, saturation, loss, and long-lived tests. |
| D-10 Support qualification/cleanup | `IN PROGRESS` | Documentation contracts and the consolidated QEMU qualification-readiness gate exist; physical, model, cluster, thermal, PMU, and durability qualifications remain. |

## Qwen 3.8 implementation

| Item | Status | Acceptance |
|---|---|---|
| Pin immutable official config/tokenizer/SafeTensors and parity corpus | `NOT STARTED` | Hashes and source revisions recorded. |
| Streaming SafeTensors/config/tokenizer importer | `NOT STARTED` | Bounded RSS and deterministic package output. |
| Package-owned tokenizer | `NOT STARTED` | Trusted tokenizer IDs match. |
| Official architecture probe and ordered configuration-derived layer plan | `NOT STARTED` | Unknown fields fail closed. |
| Scalar embedding, RMSNorm, and first projection | `NOT STARTED` | Python reference parity. |
| Every configured attention/recurrent/convolution operator, position encoding, FFN, residual, norm/head | `NOT STARTED` | Complete-layer and prefill-logit parity. |
| Separate prefill/decode plans and real per-layer state | `NOT STARTED` | State and reload continuity. |
| 32-step deterministic decode | `NOT STARTED` | Exact trusted continuation within documented tolerance. |
| Physical AVX2 and tiled prefill/verification kernels | `NOT STARTED` | Physical differential and performance artifacts. |
| Native model-executing macOS process and optional Metal | `NOT STARTED` | Real model plan runs end to end; CPU fallback remains authoritative. |
| AVX-512/VNNI/AMX, SVE/SVE2, persistent worker gangs, NUMA autotuning | `NOT STARTED` | Capability canaries, scalar differential, and physical evidence. |
| Typed paged state, prefix COW, ragged batching, exact speculation | `NOT STARTED` | Target-only and speculative deterministic outputs match. |

## Later model work

| Item | Status | Acceptance |
|---|---|---|
| Separate `kimi_k3` adapter from immutable official config | `NOT STARTED` | Config/tensor roles reject unsupported fields. |
| K3 KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts, SiTU, MXFP4 | `NOT STARTED` | Scalar operator/router/expert parity. |
| K3 independently addressable expert shards and async residency/prefetch | `NOT STARTED` | Authoritative routing is unchanged by prediction. |
| Real K3 text checkpoint | `NOT STARTED` | Tokenizer/operator/router/target-token and production-width physical gates. |
| K3 MoonViT-V2 and multimodal pipeline | `NOT STARTED` | Separate golden image/text cases. |
| DeepSeek V4 Flash 0731 source verification | `BLOCKED` | Maintainer-approved immutable official source. |
| DeepSeek adapter and parity suite | `BLOCKED` | Depends on verified source. |
| Multi-terabyte sparse allocators and large pages | `IN PROGRESS` | Hosted model packages represent sparse offsets above 100 GiB; both QEMU targets cover 2 MiB mappings and x86_64 covers a 1 GiB leaf plus targeted SMP TLB invalidation. Physical capacity and performance qualification remain. |
| SRAT/SLIT/HMAT placement policy and local/remote byte telemetry | `IN PROGRESS` | The two-node x86_64 QEMU gate validates SRAT/SLIT/HMAT parsing, usable-memory intersection, deterministic preferred-node policy, node-local allocation, and local/remote byte accounting. Physical locality/performance qualification remains. |
| AI Cell/secondary-CPU real inference dispatch | `NOT STARTED` | Real model work executes on leased workers. |
| NUMA/machine expert ownership and stable failure-aware reduction | `IN PROGRESS` | Hosted tests validate deterministic owner selection, grouping, simulated owner failure, and stable reduction. Real NUMA/machine transport, remote activation execution, and multi-QEMU exactness remain. |

## Open decisions

| ID | Decision | Status | Required before |
|---|---|---|---|
| OD-001 | Select first physical Apple/ARM target and firmware/storage/NIC boundary | `NOT STARTED` | Physical ARM support. |
| OD-002 | Select representative AVX2 Intel desktop and hybrid-core/device baseline | `NOT STARTED` | Intel desktop support. |
| OD-003 | Select Xeon generation, sockets/NUMA, memory, NIC, and NVMe | `NOT STARTED` | Xeon support. |
| OD-004 | Provision production update/ModelFS trust roots and define custody/authorization procedures | `BLOCKED` | Rotation, revocation, offline recovery, and interrupted-activation rollback are implemented; private operator keys and process are required before untrusted deployment. |
| OD-005 | Define SSH fleet limits, identity, audit retention, lockout, recovery | `NOT STARTED` | Production SSH exposure. |
| OD-006 | Define supported NVMe/FUA/flush/discard/repair/power-loss contract | `NOT STARTED` | Physical persistent deployment. |
| OD-007 | Pin official immutable Qwen 3.8 fixtures | `NOT STARTED` | Qwen implementation. |
| OD-008 | Pin official Kimi/DeepSeek sources | `BLOCKED` | Corresponding adapters; DeepSeek exact label is unresolved. |
| OD-009 | Select expert-parallel interconnect and failure/ownership model | `NOT STARTED` | Cluster inference. |
| OD-010 | Define names, quality reporting, telemetry, and acceptance for opt-in approximate modes | `NOT STARTED` | Any approximate mode. |

## Risk register

Risk status `TESTING` means mitigations exist but the risk remains open and is
checked continuously.

| ID | Risk | Status | Mitigation / closure gate |
|---|---|---|---|
| R-001 | QEMU timing presented as hardware performance | `TESTING` | Evidence vocabulary and benchmark contract; close only with continued claim audits. |
| R-002 | Documentation drift | `TESTING` | One tracker plus `make docs-check` and live-Wiki parity. |
| R-004 | Unreviewed SSH exposure | `TESTING` | Passwords off by default, bounded limits, OpenSSH/FreeBSD gates; independent review remains. |
| R-005 | Fixture keys used as production trust | `TESTING` | Fixtures are labeled; OD-004 blocks production trust. |
| R-006 | Storage durability inferred from sparse/QEMU tests | `TESTING` | Passing emulated async-NVMe and crash-recovery gates remain separate from physical S-11P and trust/repair S-12; only physical evidence can establish durability. |
| R-007 | Parser arithmetic or ownership error | `TESTING` | Checked arithmetic, malformed tests, sanitizers, immutable readers, fuzzing. |
| R-008 | Interfaces advertised as model support | `TESTING` | Separate progress and support-boundary columns plus golden gates. |
| R-009 | SIMD selected from CPUID alone | `TESTING` | OS-state checks, known-answer canaries, and scalar differential tests. |
| R-010 | Bounded fixture limits treated as server-scale targets | `TESTING` | Runtime-sized CPU/NUMA structures and explicit remaining bounded stores. |
| R-012 | Repository Wiki diverges from live Wiki | `TESTING` | Versioned Wiki source, post-push byte comparison, and docs checks. |

## Evidence gates

The default status-changing evidence set is documented in
[[Testing XAIOS|Testing-XAIOS]]. At minimum, source changes require the smallest
relevant compile/hosted/QEMU gates; documentation changes require layout,
status, JSON, link, and live-Wiki checks. A failed required gate changes the
affected item to `FAILED` until a passing rerun is recorded.

GitHub issues and milestones may provide discussion and execution history, but
their descriptive status must link back here rather than becoming another
independent tracker.
