# Project Tracker

Last reviewed: 2026-08-12.

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
| 2 | Qwen 3.6 27B support | `NOT STARTED` | Begins after the libc workstream unless reprioritized; official tokenizer, layer, logits, 32-step decode, session, and physical gates must pass. |
| 3 | Kimi K3 text support | `NOT STARTED` | Begins after Qwen unless reprioritized; KDA, Gated MLA, exact top-16 MoE, MXFP4, and token parity are mandatory. |
| 4 | Kimi K3 multimodal support | `NOT STARTED` | Separate vision preprocessing/tower/projection/position and golden image gates. |
| 5 | DeepSeek V4 Flash 0731 support | `BLOCKED` | The exact official release label and immutable source must be verified first. |
| 6 | GLM 5.2 support | `NOT STARTED` | Pin official sources, then implement a separate adapter and parity gates. |

## Model support boundary

| Model or format | Progress | Support boundary | Completion gate |
|---|---|---|---|
| Qwen 3.6 27B | `NOT STARTED` | Interface only | Trusted tokenizer, tensor, layer, prefill-logit, decode, session, backend, and physical parity. |
| Kimi K3 text | `NOT STARTED` | Interface only | KDA/MLA/MoE/MXFP4/operator and target-token parity on a real checkpoint. |
| Kimi K3 multimodal | `NOT STARTED` | Roadmap only | Separate official vision and multimodal golden acceptance. |
| DeepSeek V4 Flash 0731 | `BLOCKED` | Roadmap only | Verify exact official source before architecture work. |
| GLM 5.2 | `NOT STARTED` | Roadmap only | Immutable official source plus independent adapter/parity suite. |

### Compatibility sources

The current architecture audit uses these official upstream sources:

- [Qwen3.5-0.8B configuration](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/main/config.json)
- [Qwen3.6-27B configuration](https://huggingface.co/Qwen/Qwen3.6-27B/blob/main/config.json)
- [Qwen3.6 repository](https://github.com/QwenLM/Qwen3.6)
- [Kimi K3 configuration](https://huggingface.co/moonshotai/Kimi-K3/blob/main/config.json)
- [Kimi K3 repository and report](https://github.com/MoonshotAI/Kimi-K3)
- [GLM 5.2 model repository](https://huggingface.co/zai-org/GLM-5.2)

An immutable official source has not yet been pinned for the exact
DeepSeek V4 Flash 0731 roadmap label. That name records planning scope, not
compatibility evidence.

## Platform recommendations

Only open ARM/Intel/platform recommendations remain here. The complete numbered
catalog stays in `docs/PLATFORM-SUPPORT.json`; no secondary page owns progress
status.

| # | Recommendation | Status | Evidence / remaining gate |
|---:|---|---|---|
| P-05 | Physical Apple NEON evidence | `NOT STARTED` | QEMU cannot satisfy this physical gate. |
| P-07 | SVE/SVE2 backend | `NOT STARTED` | Capability IDs fail closed; no executing backend exists. |
| P-14 | Physical Intel/Xeon evidence | `NOT STARTED` | Physical firmware, ISA, NUMA, storage, network, thermals, and sustained-load gates remain. |

## Hosted ISO C99 libc

The architecture, non-POSIX boundary, syscall budget and evidence contract are
defined in [[ISO C99 Library|C99-Libc]]. A selected upstream implementation or
an available symbol is not proof of conformance.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| L-14 | Thread-safe libc contexts for XAIOS native threads | `NOT STARTED` | Optional non-ISO extension: per-thread `errno`, allocator/stream locks and concurrency gates without a new syscall ID. |

## Core OS, network, and SSH phases

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| O-U1 | Split outbound `ssh`/`scp` from the persistent SSH service | `NOT STARTED` | File, text, archive, and observability utilities are isolated ELFs without increasing the 50-syscall ABI. Correct client separation requires asynchronous child-channel IPC so password prompts and PTY traffic remain serviceable; no such ABI exists yet. |
| N-E4 | DNSSEC, TCP fallback, complete AAAA results | `NOT STARTED` | These remain explicit network limitations. |
| N-F1 | Hybrid post-quantum SSH KEX | `NOT STARTED` | Current interoperable suite is classical curve25519 only. |
| N-F2 | Outbound public-key auth, IPv6 active open, forwarding/agents/jump hosts | `NOT STARTED` | Outbound SSH/SCP currently uses password auth over IPv4/DNS A. |
| N-F3 | Hostile-network fuzz/physical soak/independent SSH review | `IN PROGRESS` | Deterministic sanitizer coverage now includes 50,000 malformed IPv4/IPv6 fragment cases in addition to SSH/SFTP/DNS malformed corpora and concurrent QEMU load. Coverage-guided fuzzing, physical soak, side-channel work and independent review remain. |

## Storage phases

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| S-11 Production NVMe multiqueue/PRP/SGL/affinity/direct reads | `IN PROGRESS` | AArch64 and x86_64 QEMU negotiate four I/O queues and verify four-page PRP 16 KiB write/read/flush commands plus backing bytes. Async block integration, SGL, cancellation, MSI-X affinity, direct final-buffer APIs and physical durability remain. |
| S-12 Trusted-replica repair and production key custody | `BLOCKED` | Depends on production trust and repair-source decisions. |

## Distributed AI server phases

| Phase | Status | Exit gate |
|---|---|---|
| D-04 Model management | `IN PROGRESS` | Register/verify/activate/cleanup exist; execution load/unload/pin/evict/cache remain. |
| D-05 Real local inference | `NOT STARTED` | Real Qwen correctness, typed state, scheduling, cancellation, backpressure, and metrics. |
| D-06 Authenticated cluster control | `NOT STARTED` | Mutually authenticated protocol and three-node join/partition/replay tests. |
| D-07 Distributed placement/execution | `NOT STARTED` | Transactional dense/MoE ownership, deterministic routing, and node-loss behavior. |
| D-08 Benchmarks/diagnostics | `NOT STARTED` | Physical metadata-rich measurements and redacted support bundles. |
| D-09 Production inference service | `NOT STARTED` | Authenticated API, streaming, cancellation, saturation, loss, and long-lived tests. |
| D-10 Support qualification/cleanup | `IN PROGRESS` | Documentation contracts exist; physical/model/cluster qualifications remain. |

## Qwen 3.6 27B implementation

| Item | Status | Acceptance |
|---|---|---|
| Pin immutable official config/tokenizer/SafeTensors and parity corpus | `NOT STARTED` | Hashes and source revisions recorded. |
| Streaming SafeTensors/config/tokenizer importer | `NOT STARTED` | Bounded RSS and deterministic package output. |
| Package-owned tokenizer | `NOT STARTED` | Trusted tokenizer IDs match. |
| Official architecture probe and ordered hybrid layer plan | `NOT STARTED` | Unknown fields fail closed. |
| Scalar embedding, RMSNorm, and first projection | `NOT STARTED` | Python reference parity. |
| Full/linear attention, convolution/recurrent state, GQA, masking, mRoPE, FFN, residual, norm/head | `NOT STARTED` | Complete-layer and prefill-logit parity. |
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
| Miniature executable K3 package | `NOT STARTED` | KDA/MLA/router/expert/reduction golden tests. |
| K3 independently addressable expert shards and async residency/prefetch | `NOT STARTED` | Authoritative routing is unchanged by prediction. |
| Real K3 text checkpoint | `NOT STARTED` | Tokenizer/operator/router/target-token and production-width physical gates. |
| K3 MoonViT-V2 and multimodal pipeline | `NOT STARTED` | Separate golden image/text cases. |
| DeepSeek V4 Flash 0731 source verification | `BLOCKED` | Maintainer-approved immutable official source. |
| DeepSeek adapter and parity suite | `BLOCKED` | Depends on verified source. |
| GLM 5.2 source pin and independent adapter | `NOT STARTED` | Tokenizer/operator/logit/decode/session/physical gates. |
| Multi-terabyte sparse allocators and large pages | `NOT STARTED` | Physical capacity and correctness evidence. |
| SRAT/SLIT/HMAT placement policy and local/remote byte telemetry | `NOT STARTED` | Physical NUMA validation. |
| AI Cell/secondary-CPU real inference dispatch | `NOT STARTED` | Real model work executes on leased workers. |
| NUMA/machine expert ownership and stable failure-aware reduction | `NOT STARTED` | Multi-node exactness and failure tests. |

## Open decisions

| ID | Decision | Status | Required before |
|---|---|---|---|
| OD-001 | Select first physical Apple/ARM target and firmware/storage/NIC boundary | `NOT STARTED` | Physical ARM support. |
| OD-002 | Select representative AVX2 Intel desktop and hybrid-core/device baseline | `NOT STARTED` | Intel desktop support. |
| OD-003 | Select Xeon generation, sockets/NUMA, memory, NIC, and NVMe | `NOT STARTED` | Xeon support. |
| OD-004 | Define production update/ModelFS trust roots, custody, rotation, revocation, recovery | `BLOCKED` | Untrusted deployment. |
| OD-005 | Define SSH fleet limits, identity, audit retention, lockout, recovery | `NOT STARTED` | Production SSH exposure. |
| OD-006 | Define supported NVMe/FUA/flush/discard/repair/power-loss contract | `NOT STARTED` | Physical persistent deployment. |
| OD-007 | Pin official immutable Qwen fixtures | `NOT STARTED` | Qwen implementation. |
| OD-008 | Pin official Kimi/DeepSeek/GLM sources | `BLOCKED` | Corresponding adapters; DeepSeek exact label is unresolved. |
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
| R-006 | Storage durability inferred from sparse/QEMU tests | `TESTING` | Physical S-11/S-12 gates remain explicit. |
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
