# Project Tracker

Last reviewed: 2026-08-25.

The current QEMU closure revision passes hosted, AArch64/x86_64 smoke, libc,
dual-architecture all-queue NVMe interrupt, SVE2 per-task context, x86 HMAT/
1-GiB/TLB, MutableFS-v5 migration/scale, TLS xapt, and external network gates.
The final consolidated report deliberately retains
`physical_qualification=false`.

The three-profile virtual-platform evidence set passes at
`adc0b69a1b4e6eb8f1c123fcc25aa3a73d6a881e`: macOS QEMU ARM64, macOS VMware
Fusion ARM64, and Intel VPS QEMU x86_64. **That evidence is behind the current
tree.** 113 commits have landed since, touching kernel and boot sources 153
times, including secondary-CPU bring-up, subsystem serialisation and the virtio
transports. The profiles must be re-run before their result is quoted as
current; a profile report names the commit it was taken at for exactly this
reason. The completed Fusion 26H1 (26.0.0)
one-vCPU profile is removed from the open-work tables; it covers UEFI/GRUB
boot, E1000E DHCP IPv4, AHCI MutableFS, public-key SSH/SFTP, abrupt-stop
recovery, reboot, shutdown, and repeat boot.

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

## Supported environments

XAIOS runs on three hypervisors. QEMU covers two architectures, so four
targets exist, but the platform contract is per hypervisor.

Firmware differences below are the hypervisor's, not XAIOS's: the system
behaves identically wherever a capability exists, and where one is absent it
degrades the same way everywhere. See
[Platform neutrality](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-NEUTRALITY.md),
which the build enforces.

| Function | QEMU ARM64 | QEMU x86_64 | VMware Fusion ARM64 | Virtualization.framework |
|---|---|---|---|---|
| Boots to a login | yes | yes | yes | yes |
| Durable MutableFS volume | yes | yes | yes | yes |
| IPv4 by DHCP | yes | yes | yes | yes |
| IPv6 by SLAAC | yes | yes | `F-03` not qualified | yes, unique-local only (`V-03`) |
| SSH server | yes | yes | yes | yes |
| SSH client, SFTP | yes | yes | yes | yes |
| Reachable from the host | yes | yes | yes | vmnet helper only, one direction at a time |
| Multiple vCPUs | yes, 130 gated | yes, 128/256 scenarios | `F-01` one vCPU only | yes, 8/8 |
| Message-signalled interrupts | distributor | yes | PCI | none; every queue polls (`V-02`) |
| Framebuffer console | no, serial | no, serial | yes | none published; renders to virtio console |
| USB keyboard input | yes | yes | provisioned, not gated | console input over virtio |
| Entropy protocol | virtio-rng | virtio-rng | `F-05` none exposed | yes |
| Storage transport | virtio-MMIO | virtio-PCI, NVMe | AHCI | virtio-PCI |
| Network transport | virtio-MMIO | virtio-PCI | E1000E (`F-02` no VMXNET3) | virtio-PCI |
| Automated gate | full CI | full CI | `make vmware-fusion-smoke` | `make vz-gate`, `make vz-stress-gate` |
| Evidence class | correctness only | correctness only | Fusion 26H1 lifecycle | development target, not evidence |

Device inventory differs because the hypervisors differ; the kernel discovers
what is present rather than assuming a platform, so those rows are not defects.
The rows carrying an item identifier are.

## Open bugs

Defects with no fix in place. Fixed defects leave this table when their gate
passes; the reasoning stays in the commit that closed them.

| ID | Defect | Affects | Status | Notes |
|---|---|---|---|---|
| B-01 | Outbound ProxyJump fails host key verification | x86_64 builds | `OPEN` | `ssh -J` reports "host key verification failed" on an emulated x86_64 host and succeeds natively, with the same command and known_hosts state. It fails immediately, so it is not a timeout. Reproduction needs an x86_64 host; it cannot be exercised on Apple Silicon. One hypothesis is eliminated: the tunneled session restores the target's own host, user and port before its handshake, so it does not verify against the jump endpoint. Do not "fix" it by skipping malformed known_hosts lines -- that falls through to the append path and stores a fresh key for a host that already had one, which is a host key verification downgrade. |
| B-02 | Thread join failed once under sustained load | Virtualization.framework | `OPEN` | One stress run at fifteen seconds had a worker thread never complete, and the join timed out. It has not recurred in roughly twenty-five subsequent runs of the same harness, and no cause is attributed. `make vz-stress-gate` would catch a recurrence. Recorded rather than closed, because an intermittent hang under contention is exactly what that gate exists to find. |

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

## VMware Fusion ARM64 remaining work

The qualified Fusion boundary is Apple Silicon VMware Fusion 26H1 (26.0.0),
one vCPU, E1000E, AHCI, DHCP IPv4, and public-key SSH/SFTP. The items below
are intentionally not implied by that passing profile.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| F-01 | Fusion multi-vCPU startup | `NOT STARTED` | Fusion UEFI does not expose PSCI `CPU_ON` after `ExitBootServices`. Define a validated UEFI MP Services handoff, add secondary-CPU bring-up and scheduler gates, then qualify 2+ vCPU lifecycle behavior. |
| F-02 | VMXNET3 networking | `NOT STARTED` | The current profile uses PCI E1000E only. Implement capability-gated VMXNET3 discovery, queue/DMA/interrupt paths, recovery behavior, and IPv4/IPv6 SSH/SFTP interoperability gates. |
| F-03 | Fusion network feature qualification | `NOT STARTED` | Prove IPv6 TCP/UDP, outbound SSH/SCP, local DNSSEC interoperability, forwarding, and constrained loss/reorder behavior on a Fusion guest; existing QEMU evidence does not transfer automatically. |
| F-04 | Fusion snapshot and sustained-load qualification | `NOT STARTED` | Define snapshot/resume semantics and run bounded long-duration storage/network, crash-recovery, and repeat-boot tests against generated VMDKs. QEMU durability evidence is not Fusion evidence. |
| F-05 | Fusion entropy and production-credential boundary | `BLOCKED` | Fusion 26H1 exposes neither `EFI_RNG_PROTOCOL` nor AArch64 RNDR in this profile, so current images use a unique local development seed. Production requires an operator-approved entropy/key-provisioning design and credentials. |
| F-06 | Fusion release-version coverage | `NOT STARTED` | Qualify each additional Fusion release independently. Fusion 26H1 evidence is not a compatibility claim for earlier/later releases, x86_64 guests, or physical Apple hardware. |

## Apple Virtualization.framework ARM64 remaining work

XAIOS boots to a login on this platform with MutableFS on a durable volume,
DHCP IPv4, SLAAC IPv6, SSH and all four vCPUs online, and the Mac can ssh into
the guest over vmnet
through `tools/vz/vmnet-helper`, which is the only route in: the built-in NAT
attachment delivers no host-initiated frame, and bridging needs an entitlement
V-03 also waits on. `make vz-gate` checks that boot and writes
`build/vz-gate.json`. It is a development target: the gate needs macOS on Apple
Silicon and a signed harness, so it cannot run in CI and its result is not
qualification evidence.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| V-02 | MSI-X delivery for virtio on PCI | `TESTING` | Exercised by attaching QEMU's virtio devices on PCI, with modern identifiers and the 32-bit window, against a real translation service: every device on the bus receives a distinct vector. Three defects were fixed to get there -- one translation table shared by all devices, identifiers reissued to a second device because the first polls and never registers a handler, and an assertion on any BAR above 512 GiB. Physical ARM PCIe hardware remains the qualifying case; Virtualization.framework still has no ITS, so its queues stay polled. |
| V-03 | Globally routable IPv6 | `BLOCKED` | The NAT attachment advertises the unique-local prefix `fd4a:25c::/64`, so no globally routable address is on offer. A bridged attachment would carry real IPv6 but needs the `com.apple.vm.networking` entitlement, which Apple issues only with a provisioning profile; ad-hoc signing cannot provide it. |
| V-04 | Multi-vCPU qualification | `IN PROGRESS` | Secondaries genuinely run here now, which they never did before: PSCI starts them with translation off, where exclusives are unsupported, so the atomic each one used to announce itself aborted, and everything they published went to memory the boot CPU was not reading. Every boot reported `online cpus=1/4` and most panicked. With that window made coherent, boots come up `1/1`, `4/4` and `8/8`, the secondary worker barrier passes at each, and ten consecutive eight-vCPU boots produce byte-identical `smptest` signatures -- worker sets, kernel-dispatched worker groups and EL0 create/join -- with no panic in any of them. `make vz-gate` boots four vCPUs and requires 4/4. What remains cannot be answered here: this host has eight cores against a 128-256 core target, the platform offers no control over interrupt affinity, and none of this is sustained-load evidence. |
| V-10 | Intermittent virtio-net transmit non-completion | `OPEN` | On one boot in roughly twenty-five at eight vCPUs, the transmit in `virtio_net_self_test` never completes: the used ring does not advance within the transport's five-second window. The failing boot is identical to the passing ones up to that point -- same feature negotiation, same offload, same bounded polling because this platform has no MSI-X -- and nothing anomalous is logged before it. Five seconds is far too generous for this to be a slow host, so "late completion" is not the explanation; the queue appears to wedge. Found by `make vz-stress-gate`, which is how repetition earns its keep. It no longer halts the machine (that assertion is gone) and now logs `tx_completed=0`, so recurrences accumulate evidence instead of stopping the boot. Unproven hypothesis worth testing first: the completion is detected by polling a ring the host writes, so it is the same coherence question as V-04 seen from the other side -- whether the guest's view of that memory can go stale. |
| C-01 | Shared kernel state under genuine parallelism | `TESTING` | Addressed subsystem by subsystem, because the right fix differed per file. The network stack, service records and CPU-AI runtime took a reentrant guard on their syscall-reachable entry points -- reentrant because ten of the network stack's exported functions call other exported ones, which a plain lock at each entry would deadlock on. The resolver shares the network guard rather than holding its own, since it calls tcp_open/send/recv/close while `network_poll_tick` calls back into its timers; a separate guard there was a lock-order inversion, caught and removed before it could bite. `security.c` and `agent_protocol.c` hold no tables at all, so their 48 audit totals became atomics instead: guarding capability checks on the syscall path would have cost far more than it bought. `vfs_model.c` already locked; `update`, `ai_cell`, `persistence` and `sandbox` have no syscall entry points and are covered by guarded callers. Guard order is service before network, one direction, recorded on the primitive along with the rule that it must never be taken from interrupt context. What remains is not correctness but cost: these are coarse locks, network syscalls now serialise against each other and the poll path, and no controlled measurement of that exists yet. |
| V-06 | Graphical console | `BLOCKED` | The GOP is `PixelBltOnly`, so no linear framebuffer exists and `GOP->Blt()` does not outlive `ExitBootServices`. A graphical console here would need a kernel virtio-GPU driver rather than the framebuffer path the other targets use. |

## Core OS, network, and SSH phases

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| N-F3P | Physical SSH/network security qualification | `IN PROGRESS` | Consolidated QEMU network/SSH readiness evidence is available through `make qemu-qualification-readiness`; physical lossy-link, sustained-load, side-channel analysis, and independent SSH/cryptography review remain open. QEMU evidence cannot close this item. |

## Storage phases

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| S-11P Physical production NVMe qualification | `IN PROGRESS` | Consolidated QEMU NVMe and crash-recovery evidence is available through `make qemu-qualification-readiness`; named physical devices must still pass queue scaling, interrupt affinity, FUA/flush/discard semantics, reset recovery, power-loss durability, sustained-load, and performance gates. QEMU evidence cannot close this item. |
| S-12 Production ModelFS trust-root and signing-key custody | `BLOCKED` | Offline trusted-replica payload repair is implemented and QEMU/hosted-tested. Production trust-root enrollment, private-key custody, replica authorization, and rotation decisions require named operators and deployment credentials. |

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
