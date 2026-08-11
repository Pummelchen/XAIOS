# Project Tracker

Last reviewed: 2026-08-12.

This is the only human-maintained XAIOS project tracker. Roadmaps, milestones,
phase plans, open decisions, and risks are consolidated here. The Wiki does not
retain previous tracker, roadmap, milestone, or phase-plan pages.

## Status codes

| Code | Meaning |
|---|---|
| `DONE` | Implementation and the named evidence gate are complete. |
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
| 1 | XAIOS QEMU core OS | `DONE` | AArch64 and x86_64 run the common service image and pass the declared aggregate QEMU correctness gates. |
| 1b | Physical Apple/ARM, Intel desktop, and Xeon qualification | `NOT STARTED` | Named hardware must pass firmware, device, durability, security, ISA-state, NUMA, soak, and benchmark contracts. |
| 1c | Hosted ISO C99 libc without POSIX | `DONE` | The strict 24-header/464-function inventory, native adapters, both target QEMU runs, and 50-syscall invariant pass. This is project evidence, not third-party certification. |
| 2 | Qwen 3.6 27B support | `NOT STARTED` | Begins after the libc workstream unless reprioritized; official tokenizer, layer, logits, 32-step decode, session, and physical gates must pass. |
| 3 | Kimi K3 text support | `NOT STARTED` | Begins after Qwen unless reprioritized; KDA, Gated MLA, exact top-16 MoE, MXFP4, and token parity are mandatory. |
| 4 | Kimi K3 multimodal support | `NOT STARTED` | Separate vision preprocessing/tower/projection/position and golden image gates. |
| 5 | DeepSeek V4 Flash 0731 support | `BLOCKED` | The exact official release label and immutable source must be verified first. |
| 6 | GLM 5.2 support | `NOT STARTED` | Pin official sources, then implement a separate adapter and parity gates. |

## Current change acceptance

| Item | Status | Evidence required |
|---|---|---|
| Centralize all test runners and Docker fixtures under `tests/` | `DONE` | Layout, syntax, hosted, docs, ABI, QEMU, Docker rebuild, and [CI](https://github.com/Pummelchen/XAIOS/actions/runs/31454809543) gates pass. |
| Publish the operator Wiki and this canonical tracker | `DONE` | The repository mirrors the complete curated live-Wiki page set. |

## Model support boundary

| Model or format | Progress | Support boundary | Completion gate |
|---|---|---|---|
| Deterministic model-v1 path | `DONE` | Fixture only | Remain explicitly fixture-only and fail closed for production decode. |
| `xaios.model.v2` format/tooling | `DONE` | Interface only | Stable 64-bit package/parser/writer round trips exist; execution admission remains a later task. |
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

These are the former 20 ARM/Intel/platform recommendations. Evidence details
remain concise here; no secondary page owns their status.

| # | Recommendation | Status | Evidence / remaining gate |
|---:|---|---|---|
| P-01 | Restore independent green CI gates | `DONE` | Compile, hosted, docs, ABI, AArch64, x86, storage, network, and aggregate jobs are independent. |
| P-02 | ARM SMP worker dispatch | `DONE` | Runtime-discovered CPUs and joinable worker groups pass QEMU. |
| P-03 | ARM FP/NEON context preservation | `DONE` | q0-q31, FPCR, and FPSR survive live timer interrupts under QEMU. |
| P-04 | Native macOS/Linux engine executable | `DONE` | Hosted probe/inspect/fail-closed serve boundary passes. |
| P-05 | Physical Apple NEON evidence | `NOT STARTED` | QEMU cannot satisfy this physical gate. |
| P-06 | Generic ARM server scope | `DONE` | UEFI/SBSA-style AArch64 scope is documented; QEMU `virt` is the service target. |
| P-07 | SVE/SVE2 backend | `NOT STARTED` | Capability IDs fail closed; no executing backend exists. |
| P-08 | x86 AP startup and worker participation | `DONE` | MADT AP trampoline/IPI work, a bounded per-CPU dispatch-loop readiness handshake, and 1/4/8/128/256-vCPU matrices pass QEMU. |
| P-09 | x86 ring 3, syscalls, and user threads | `DONE` | Common loader, per-CPU page tables, syscall ABI, and EL0 threads pass QEMU. |
| P-10 | x86 PCI storage/network/NVMe/interrupts | `DONE` | PCI VirtIO, block MSI-X-or-bounded-poll completion, and focused emulated NVMe gates pass. Repeated post-reset MSI-X requires physical validation. |
| P-11 | x86 full platform services | `DONE` | Filesystems, IPv4/IPv6, SSH/SFTP, control, security, AI Cell, and telemetry match ARM QEMU scope. |
| P-12 | MADT/SRAT/SLIT/HMAT parsing | `DONE` | MADT passes QEMU; all four tables have hosted checksum/range tests. |
| P-13 | XSAVE/XRSTOR state management | `DONE` | Runtime-sized XSAVE with FXSAVE fallback passes live-interrupt tests; AMX remains separate. |
| P-14 | Physical Intel/Xeon evidence | `NOT STARTED` | Physical firmware, ISA, NUMA, storage, network, thermals, and sustained-load gates remain. |
| P-15 | Inference service ownership boundary | `DONE` | Caller-owned package/backend/model/session registries fail closed. |
| P-16 | Immutable 64-bit model mappings | `DONE` | Production mappings are no-copy and read-only; copied admission is fixture-only. |
| P-17 | Async direct model range I/O | `DONE` | Hosted aligned direct-buffer completion/cancellation tests pass. |
| P-18 | Lifecycle-safe sessions | `DONE` | 64-bit append/fork/commit/rollback/destruction metadata passes; typed model state is tracked below. |
| P-19 | Documentation reconciliation | `DONE` | Docs checks and repository/live-Wiki byte parity pass. |
| P-20 | GitHub milestone reconciliation | `DONE` | All human progress status is consolidated here; legacy planning pages and redirects are removed. |

## Core OS foundation items

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| C-01 | Runtime-sized CPU, NUMA, cpuset, lease, and worker metadata | `DONE` | Hosted cpusets cover 4,097 IDs and QEMU boots 130 CPUs for capacity evidence. |
| C-02 | Dynamic userspace image ownership and cleanup | `DONE` | ELF-page-sized tracking, rollback, descriptor/socket/VFS reclamation, and 64-bit narrowing checks pass. |
| C-03 | QEMU SMMUv3 translated-DMA isolation | `DONE` | Authorization, fault, and stale-map revocation pass with the pinned test device. |
| C-04 | EL0 thread create/join/cancel/exit | `DONE` | Runtime-sized CPU metadata and focused QEMU tests pass on ARM and x86. |
| C-05 | Redundant system-slot crash consistency | `DONE` | Kill/reboot fault points pass both metadata write windows. |
| C-06 | Non-skipping aggregate core release gate | `DONE` | `make qemu-core-os-rc` reports each required component independently. |
| C-07 | Security-sensitive syscall/user-buffer audit | `DONE` | Capability, ownership, snapshot, range, and bounded-I/O gates pass. |
| C-08 | Professional bounded filesystem/PTY command surface | `DONE` | Local and concurrent SSH sessions pass create/copy/move/delete/archive/editor/process/error tests. |
| C-09 | Orderly power lifecycle | `DONE` | AArch64 PSCI and x86 reset/ACPI paths persist intent, flush logs/devices, reboot, and power off in the focused QEMU gate. |
| C-10 | Process and service controls | `DONE` | Authenticated list/status/start/stop/restart and protected bounded PID termination are implemented; PID 1/2/current cannot be killed. |
| C-11 | Network diagnostics | `DONE` | Interface, route, ARP/NDP, packet/flow/drop counters, asynchronous ICMP, and DNS pass real-SSH QEMU checks. |
| C-12 | Clock management and SNTP | `DONE` | RTC/manual source reporting plus validated SNTP request/reply/retry/timeout behavior pass parser and live QEMU gates. |
| C-13 | Resource pressure behavior | `DONE` | Normal/warning/critical thresholds and underlying memory/process/filesystem/CPU counters pass self-tests and QEMU inspection. |
| C-14 | Crash and recovery lifecycle | `DONE` | Abrupt QEMU termination is detected from persistent running state; forced/consecutive rescue policy and clean-state reset pass. |
| C-15 | System update lifecycle operations | `DONE` | Signed streamed inactive-slot delivery, hash/signature verification, commit/fail/fallback/rollback, reboot selection, and current-version rejection pass on ARM and x86 QEMU. Production trust remains OD-004. |
| C-16 | Configuration recovery and support bundles | `DONE` | Canonical text export/import uses the transactional admin path; support output is bounded and secret-redacted. |
| C-17 | Long-duration and fault closure | `DONE` | Operations closure is combined with existing soak, fault injection, storage crash, boot-loop, and non-skipping aggregate gates. Physical soak remains P-05/P-14. |
| C-18 | Independent signed application updates | `DONE` | `xapt` verifies monotonic signed catalogs and per-app manifests, atomically installs/upgrades/removes, preserves one rollback version, accepts argv, and persists across reboot on ARM and x86 QEMU. The external `calculator` package is the executable gate. |

## Hosted ISO C99 libc

The architecture, non-POSIX boundary, syscall budget and evidence contract are
defined in [[ISO C99 Library|C99-Libc]]. A selected upstream implementation or
an available symbol is not proof of conformance.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| L-01 | Hosted C99 conformance and non-POSIX architecture contract | `DONE` | The Wiki defines ISO/IEC 9899:1999 plus TC1-3, zero libc-specific syscall growth, native extension separation and final evidence gates. |
| L-02 | Pin and license-audit complete library baseline | `DONE` | Picolibc 1.8.12 commit `2ae376c6cdf4fef90ca2388ecf7a07457fa63cff` is a pinned submodule; generated sysroots retain `COPYING.picolibc` and verify source identity. |
| L-03 | Machine-readable mandatory C99 inventory | `DONE` | `c99-requirements.json` and `c99-library-functions.json` enumerate 24 headers, 464 functions, forbidden extensions, syscall budget, architectures and runtime markers. |
| L-04 | XAIOS hosted sysroot, compiler runtime and static link path | `DONE` | Strict AArch64/x86_64 sysroots, page-separated ELF layout, generic application builder and all-symbol links pass. |
| L-05 | Startup, standard streams, heap and termination | `DONE` | Both standard `main` forms, initialized streams, allocation, `atexit`, return, `_Exit(23)` and `abort` pass as XAIOS processes. |
| L-06 | Native console, file, time and temporary-file adapters | `DONE` | Private adapters use existing capability-checked syscalls; stdio file/temp/position tests pass without a public POSIX API. |
| L-07 | Complete strings, conversion, locale, multibyte and wide-character surface | `DONE` | Strict runtime tests cover the required `C` locale, conversions, narrow/wide strings and allocation edge cases. |
| L-08 | Complete printf/scanf and stream semantics | `DONE` | C99 formats, long long, architecture long double, `%n`, buffering, scan, positioning and wide streams pass. |
| L-09 | Complete libm, complex and floating-point environment | `DONE` | Mandatory symbols link and special-value, complex, rounding and exception operations execute on both targets. |
| L-10 | setjmp, ISO signals and ISO libc state | `DONE` | Architecture `setjmp`/`longjmp`, process-local standard `signal`/`raise`, and termination behavior pass. C99 has no thread API. |
| L-11 | ARM64 and x86_64 full C99 QEMU conformance | `DONE` | Every required runtime marker and termination exit code passes under both QEMU targets. |
| L-12 | Syscall, POSIX-surface and AI-architecture invariants | `DONE` | AST and negative-compile audits expose only 464 ISO function names, omit forbidden headers, add zero syscall IDs, and preserve native AI boundaries. |
| L-13 | Final audit and immutable conformance report | `DONE` | The second inventory audit corrected 13 omissions; the generated 13/13 report hashes manifests, ELFs, archives and both QEMU logs. |
| L-14 | Thread-safe libc contexts for XAIOS native threads | `NOT STARTED` | Optional non-ISO extension: per-thread `errno`, allocator/stream locks and concurrency gates without a new syscall ID. |

## Core OS, network, and SSH phases

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| N-A1 | TCP checksum validation | `DONE` | Inbound validation and outbound generation are covered. |
| N-A2 | Full TCP state/FIN lifecycle | `DONE` | Connection and close bookkeeping pass focused/QEMU tests. |
| N-A3 | TCP data retransmission and RTO backoff | `DONE` | Retained segments, partial/cumulative ACK, and backoff are implemented. |
| N-A4 | TCP MSS negotiation | `DONE` | Bounded option parsing and peer MSS handling are implemented. |
| N-A5 | TCP window scaling/zero-window behavior | `DONE` | Window handling and zero-window recovery pass. |
| N-A6 | Basic congestion/fast retransmit/SACK | `DONE` | SACK-aware fast retransmit and bounded send window pass. |
| N-A7 | TCP keepalive | `DONE` | Keepalive and timeout bookkeeping are implemented. |
| N-A8 | Mandatory IPv6 UDP checksum | `DONE` | IPv6 UDP validation is covered. |
| N-A9 | Out-of-order TCP data | `DONE` | Bounded reordering passes focused tests. |
| N-A10 | Listener backlog | `DONE` | Multiple transports and bounded pending/active channels pass concurrent tests. |
| N-B1 | IPv4 receive fragment reassembly | `DONE` | Bounded out-of-order reassembly passes macOS/Debian load. |
| N-B2 | General outbound IPv4 fragmentation | `DONE` | The common egress boundary enforces the 1500-byte MTU and source-fragments maximum-size UDP output; macOS/Debian raw clients and AArch64/x86_64 QEMU gates reassemble two fragments with valid offsets and checksums. |
| N-B3 | ICMPv4 error generation | `DONE` | Bounded protocol errors are implemented and tested. |
| N-B4 | ARP aging and bounded expansion | `DONE` | Cache aging/replacement behavior is implemented. |
| N-B5 | Route deletion and expanded table | `DONE` | Bounded mutable route management is present. |
| N-C1 | IPv6 extension-header parsing | `DONE` | Supported chain validation is bounded. |
| N-C2 | IPv6 receive fragment reassembly | `DONE` | Focused out-of-order cases pass. |
| N-C3 | General outbound IPv6 fragmentation | `DONE` | The common egress boundary source-fragments above the IPv6 minimum MTU; dual-client load and AArch64/x86_64 QEMU gates verify two-fragment UDP echo, offsets and checksums. |
| N-C4 | NDP reachability, aging, and hop-limit checks | `DONE` | Neighbor cache lifecycle and validation are covered. |
| N-C5 | Duplicate address detection and router discovery | `DONE` | Bounded DAD/RS/RA behavior is implemented. |
| N-C6 | ICMPv6 error generation | `DONE` | Bounded protocol errors are implemented. |
| N-D1 | Per-connection SSH state | `DONE` | Concurrent session cwd/parser/channel state is isolated. |
| N-D2 | Multi-session SSH scheduling | `DONE` | Four transports and two active channels each pass load gates. |
| N-D3 | Persistent Ed25519 host key | `DONE` | Stable identity and rotation/reconnect behavior pass. |
| N-D4 | Public-key server authentication | `DONE` | Provisioned Ed25519 principals, roles, and revocation pass OpenSSH gates. |
| N-D5 | Ed25519 verification | `DONE` | Authentication and malformed-signature cases pass. |
| N-D6 | SSH rekey | `DONE` | Forced rekey is covered. |
| N-D7 | Production-bounded SFTP handles | `DONE` | Concurrent read/write/stat/fsync/rename/remove and 64-bit offsets pass. |
| N-D8 | Random transport/SFTP padding | `DONE` | Entropy-backed padding is implemented. |
| N-D9 | Minimum-padding validation | `DONE` | Malformed packet/padding rejection is tested. |
| N-D10 | Channel windows | `DONE` | Flow-control limits pass OpenSSH transfer tests. |
| N-D11 | stderr/exit-status reporting | `DONE` | Remote failures return bounded stderr and nonzero status. |
| N-E1 | DNS message parser | `DONE` | Bounded A-record parsing and malformed responses pass. |
| N-E2 | UDP DNS query/retry/cache | `DONE` | Asynchronous resolver syscall and cache-hit path pass QEMU. |
| N-E3 | Resolver configuration | `DONE` | Boot/network configuration supplies bounded resolver settings. |
| N-E4 | DNSSEC, TCP fallback, complete AAAA results | `NOT STARTED` | These remain explicit network limitations. |
| N-F1 | Hybrid post-quantum SSH KEX | `NOT STARTED` | Current interoperable suite is classical curve25519 only. |
| N-F2 | Outbound public-key auth, IPv6 active open, forwarding/agents/jump hosts | `NOT STARTED` | Outbound SSH/SCP currently uses password auth over IPv4/DNS A. |
| N-F3 | Hostile-network fuzz/physical soak/independent SSH review | `IN PROGRESS` | Deterministic sanitizer coverage now includes 50,000 malformed IPv4/IPv6 fragment cases in addition to SSH/SFTP/DNS malformed corpora and concurrent QEMU load. Coverage-guided fuzzing, physical soak, side-channel work and independent review remain. |

## Storage phases

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| S-01 Generic 64-bit block API | `DONE` | Hosted and QEMU overflow, split, flush/discard/write-zeroes behavior passes. |
| S-02 GPT partitions | `DONE` | Redundant GPT, CRC/range/GUID checks, dry-run, replay protection, and 512/4096 sectors pass. |
| S-03 VFS and 64-bit file API | `DONE` | Mount routing, generation-owned handles, >4 GiB positions, immutable reads, and staging writes pass. |
| S-04 ModelFS v1 | `DONE` | Signed C/Python parsing, COW lifecycle, sparse 128 GiB volume, recovery, staging, activation, and reuse pass. |
| S-05 Format/mount/usage/grow tools | `DONE` | Hosted/QEMU administration and macOS/Debian OpenSSH inventory pass. |
| S-06 Fsck/repair | `DONE` | Read-only fsck and explicit redundant-superblock repair pass. |
| S-07 Scrub/quarantine | `DONE` | Resumable checksummed scrub, corruption offsets, and atomic quarantine pass. |
| S-08 TRIM/discard | `DONE` | Free-only planning, persistence, cancellation, and QEMU VirtIO negotiation pass. |
| S-09 Large SFTP | `DONE` | >4 GiB offsets and concurrent resumable macOS/Debian transfers pass at QEMU-testable scope. |
| S-10 Model loader boundary | `DONE` | Signed open, ranged reads, extent maps, callbacks, aligned arena, metrics, and >100 GiB offsets pass hosted tests. |
| S-11 Production NVMe multiqueue/PRP/SGL/affinity/direct reads | `IN PROGRESS` | AArch64 and x86_64 QEMU negotiate four I/O queues and verify four-page PRP 16 KiB write/read/flush commands plus backing bytes. Async block integration, SGL, cancellation, MSI-X affinity, direct final-buffer APIs and physical durability remain. |
| S-12 Trusted-replica repair and production key custody | `BLOCKED` | Depends on production trust and repair-source decisions. |

## Distributed AI server phases

| Phase | Status | Exit gate |
|---|---|---|
| D-01 `xaiosctl` foundation | `DONE` | Bounded protocol, human/JSON output, authorization, QEMU, and Debian OpenSSH gates pass. |
| D-02 Administrative security | `DONE` | Roles, revocation, config transactions, audit, host-key rotation, and redaction pass fixture gates. |
| D-03 Large-model volume/packer | `DONE` | QEMU/hosted transactional storage scope passes; physical storage remains S-11. |
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
| No-expand scalar/NEON/AVX2 INT4/INT6 microkernels | `DONE` | Differential, tail, and startup canary tests pass at fixture scope. |
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
| R-003 | x86 service status overstated | `DONE` | Full common QEMU service image passes; physical claims remain explicitly separate. |
| R-004 | Unreviewed SSH exposure | `TESTING` | Passwords off by default, bounded limits, OpenSSH/FreeBSD gates; independent review remains. |
| R-005 | Fixture keys used as production trust | `TESTING` | Fixtures are labeled; OD-004 blocks production trust. |
| R-006 | Storage durability inferred from sparse/QEMU tests | `TESTING` | Physical S-11/S-12 gates remain explicit. |
| R-007 | Parser arithmetic or ownership error | `TESTING` | Checked arithmetic, malformed tests, sanitizers, immutable readers, fuzzing. |
| R-008 | Interfaces advertised as model support | `TESTING` | Separate progress and support-boundary columns plus golden gates. |
| R-009 | SIMD selected from CPUID alone | `TESTING` | OS-state checks, known-answer canaries, and scalar differential tests. |
| R-010 | Bounded fixture limits treated as server-scale targets | `TESTING` | Runtime-sized CPU/NUMA structures and explicit remaining bounded stores. |
| R-011 | Model scope blocks stable core OS | `DONE` | QEMU core OS gate completed before Qwen work. |
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
