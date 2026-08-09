<!--
AI onboarding file.
Mode: refresh
Indexed base commit: 8ddefb26f3dbc366dc4402677a156cf235daed82
Last refreshed: 2026-08-04
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Known unknowns and conflicts

## Resolved in primary status docs: performance claims vs QEMU evidence

README, project tracker, hardware-readiness, benchmark methodology, and the
selected local/live Wiki status pages now label QEMU as correctness/ABI
evidence only. The support table and delivery sequence are checked from
`docs/MODEL-SUPPORT.json`; generated `.qoder/repowiki/` material remains
non-authoritative and may still contain historical wording.

Recommendation: treat performance numbers as targets or unverified design claims unless a human provides measured hardware baselines.

Evidence:
- `README.md`
- `PROJECT-TRACKER.md`
- `wiki/Home.md`
- `wiki/Model-Support-Roadmap.md`
- `wiki/Qwen3.6-INT6-Support.md`
- `wiki/Production-SSH-Server.md`
- `HARDWARE-READINESS.md`
- `contracts/qemu-rc-v1.json`

## Resolved in current working tree: syscall/API documentation lag

Source, userspace wrappers, `docs/API.md`, and the release-candidate contract now
cover syscalls 1-41 and all 21 capabilities. `scripts/qemu_gate_lib.py` rejects missing or extra source
syscalls/capabilities.

Evidence:
- `kernel/include/xaios/syscall.h`
- `userspace/include/xaios_user.h`
- `kernel/user/syscall.c`
- `docs/API.md`
- `contracts/qemu-rc-v1.json`
- `scripts/qemu_gate_lib.py`

## Resolved: license status

`LICENSE` contains the standard PolyForm Noncommercial License 1.0.0 with the
XAIOS required notice. Private, educational and noncommercial research use is
permitted. Commercial use requires a separate written commercial license as
described in `COMMERCIAL-LICENSE.md`.

Do not alter license language without explicit human authorization.

Evidence:
- `LICENSE`
- `COMMERCIAL-LICENSE.md`
- `README.md`

## Resolved: safe default for macOS QEMU correctness gates

The AArch64 launcher now defaults to TCG on all hosts. It no longer auto-selects
HVF on Apple Silicon, where current QEMU versions can abort in
`hvf_handle_exception`. HVF remains an explicit experimental override rather
than a correctness-gate default.

Evidence:
- `scripts/run-qemu-aarch64.sh`
- `scripts/qemu-abi-contract.py`
- `.ai/TESTING.md`

## Verified implementation gaps

- `xaios.control.v1` operations 1-49, persistent config/key/revocation/audit
  state, observer/operator/administrator roles, and ModelFS/storage lifecycle are
  QEMU/OpenSSH-tested. Model-v2 execution loading, cluster control and the
  inference data plane remain absent.
- The former fixed 256-page ELF tracking ceiling is replaced by a dynamically
  sized, checked tracker with partial-load rollback and a 513-page self-test.
- A 64-bit block/GPT/VFS foundation and signed ModelFS v1 now exist. Dynamic
  staging registration/allocation, resumable SFTP, cleanup/reuse, verification,
  audited activation, immutable retrieval, format/mount/grow/fsck, persistent
  scrub/quarantine and free-only trim pass hosted and QEMU gates. The portable
  model-file API passes sparse >100 GiB logical tests.
- QEMU VirtIO-MMIO block/network completions are interrupt-driven with
  event-index suppression and indirect descriptors; block has eight concurrent
  direct-or-bounce slots and batched multi-sector transfers. An emulated NVMe
  admin/I/O queue gate verifies identify, write, flush, read and host backing
  bytes. Production NVMe multiqueue/affinity, physical durability/performance,
  trusted-replica repair and model-v2 execution admission remain absent.
- ModelFS activation and MutableFS audit persistence are separate durability
  domains. A post-publication audit failure is logged but cannot roll back the
  active ModelFS generation.
- Phase 2 remains intentionally bounded to 16 active keys, 16 revoked
  fingerprints, 64 audit/replay records, 16 shell contexts, four live SSH
  transports and two channels each. Fleet-scale identity/audit/replay policy is
  unresolved.

- No official tokenizer importer, real Qwen tensor import, transformer plan, logits
  parity or 32-token decode parity exists.
- Kimi K3 is interface/roadmap only; KDA, Gated MLA, exact top-16 MoE, MXFP4,
  text parity and multimodal execution are absent.
- INT4/INT6 fixture-era full-matrix expansion and the INT6 temporary leak are
  removed. Portable scalar and experimental NEON packed kernels pass
  differential/tail tests, and the experimental AVX2 path passes INT4/INT6
  known-answer execution under QEMU TCG. Physical AVX2 differential validation,
  tiled GEMM and inference-specific persistent worker gangs do not exist.
- Runtime-sized NUMA metadata, CPU registry/cpusets/core leases and CPU-assigned
  joinable kernel workers replace their former fixed/sequential forms. Legacy
  copied model-v1 admission is fixture-only. Production model mappings are
  no-copy, immutable-checked and 64-bit; typed model state, inference batching
  and AI Cell compute dispatch remain incomplete.
- The x86_64 image boots a real shared-runtime `/bin/hello` ELF and executes
  shared CRC, block, VFS, architecture, scalar, security and packed-engine
  probes, a controlled INT3 round trip, a local-APIC timer
  interrupt, MADT-discovered AP startup and IPI work, ring-3 syscall round trip,
  runtime-sized XSAVE, modern VirtIO block DMA/MSI-X and network TX. The full
  ARM EL0/thread ABI, receive network stack, mounted filesystems, SSH/control,
  x86 NVMe operation, process-owned security services, AI Cell and telemetry
  integration remain absent.
- A native macOS/Linux engine CLI and caller-owned service boundary exist, but
  there is no complete model-executing macOS inference process, Metal backend,
  AVX-512/VNNI/AMX backend, physical model-parity run, or immutable performance
  artifact. The native-hosted experimental NEON and QEMU-tested AVX2 backends
  exist only at the microkernel correctness level.

Repository, tracker, readiness, backend and selected Wiki platform claims are
checked against `docs/PLATFORM-SUPPORT.json`.

## Delivery order

XAIOS platform completion is the only active workstream. Qwen 3.6 27B is next
but blocked until the platform gate passes. Kimi K3 and GLM 5.2 are backlog;
DeepSeek V4 Flash 0731 is blocked by sequencing and authoritative source
verification. Keep README, tracker, roadmap, Wiki mirrors, GitHub milestones,
and Project status aligned with `docs/MODEL-SUPPORT.json`.

## Unknowns

- The freestanding SSH/SFTP server interoperates with Debian 13 OpenSSH in local
  QEMU tests, and a native macOS plus Debian 13 load gate exercises the same
  successful guest. Evidence includes provisioned Ed25519 and PBKDF2
  authentication, fail-closed entropy/configuration variants, persistent host
  identity, shared channels, forced rekey, strict and overlapping SFTP, four
  simultaneous connections with eight active channels, clean over-capacity
  rejection, 40 combined reconnects, and post-load recovery. Four is the
  deliberate fixed service limit. Independent security review, physical-NIC
  validation, hostile-network soak, fleet key/audit policy, and side-channel
  analysis remain non-QEMU gates. Phase 2 host-key rotation and user-key
  revocation pass only within the bounded QEMU acceptance scope.
- DNS has an asynchronous resolver syscall, bounded cache, timeout/retry path,
  and persistent-loop integration. QEMU verifies external A-record resolution
  and a cache hit. DNSSEC, TCP fallback, AAAA application results, and
  deployment resolver policy remain absent.
- TCP retains up to eight unacknowledged MSS-sized payload segments with
  cumulative/partial ACK release, RTT/RTO backoff, SACK, fast retransmit,
  zero-window handling, bounded reordering, keepalive, and FIN bookkeeping.
  Direct malformed-checksum, out-of-order IPv4/IPv6 fragment reassembly,
  reordered-input, and withheld-ACK cases pass. Repeated-loss soak,
  congestion-control tuning, and physical-network recovery remain unknown.
- Bounded IPv4/IPv6 fragment reassembly is integrated and dual-client QEMU load
  verifies fragmented TCP SYN handling. Broad hostile-fragment fuzzing remains
  incomplete.
- A focused QEMU SMMUv3 gate proves translated authorized DMA, forbidden-DMA
  faults, and stale-map rejection; physical Stage 1 policy remains unknown.
  General EL0 create/join/cancel/exit syscalls now use runtime-sized thread and
  CPU metadata, but physical many-core scheduling remains unverified.
- The old bump-only heap limitation is obsolete: `kheap_free()` and free-list
  reuse are implemented and covered by `kheap_self_test()`.

- Exact production Qwen/K3 source revisions for golden compatibility fixtures
  are not pinned yet; verify official configuration at importer implementation time.
- Exact source revisions for GLM 5.2 and the roadmap label DeepSeek V4 Flash
  0731 are not pinned. The latter exact label still requires authoritative
  upstream release verification.
- Hardware validation status beyond repository artifacts is unknown; currently
  no qualifying physical artifact is present.
- Production signing/key-management design is not complete in source comments inspected.
- Whether `.qoder/repowiki/` should be removed, ignored, or refreshed is unknown; it was not modified.

## Ask a human before editing

- Licensing text.
- Hardware performance claims that lack benchmark-contract artifacts.
- Production security model/signing claims.
- Removal of non-onboarding docs with vendor-specific wording.
- Any change that relaxes capability checks, credential-material rejection, update authorization, or sandbox path validation.
