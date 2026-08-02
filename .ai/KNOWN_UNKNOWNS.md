<!--
AI onboarding file.
Mode: refresh
Indexed base commit: 8404c1ec1b76c02157bb08d8a3a9466a93e5c2cb
Last refreshed: 2026-08-01
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
cover syscalls 1-35. `scripts/qemu_gate_lib.py` rejects missing or extra source
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

- No official tokenizer importer, real Qwen tensor import, transformer plan, logits
  parity or 32-token decode parity exists.
- Kimi K3 is interface/roadmap only; KDA, Gated MLA, exact top-16 MoE, MXFP4,
  text parity and multimodal execution are absent.
- INT4/INT6 fixture-era kernels still expand matrices; the INT6 path still leaks
  temporary storage and worker units remain sequential.
- Model admission, model arena, NUMA bitmaps, synchronous block I/O, scheduler
  work dispatch and AI Cell leases remain QEMU-scale prototypes.
- The x86_64 image still links only early architecture bring-up, not the common
  kernel or portable inference engine.
- There is no native macOS process/backend, Metal backend, AVX2/AVX-512/VNNI/AMX
  backend, physical hardware parity run, or immutable performance artifact.

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
  validation, hostile-network soak, key rotation policy, and side-channel
  analysis remain non-QEMU gates.
- DNS contains an A-record encoder/parser/cache prototype, but `dns_tick()` is
  not wired into the persistent network poll loop and there is no userspace
  resolver API. DNS is not an operational service.
- TCP retains and retransmits one unacknowledged MSS-sized payload segment with
  RTT/RTO, ACK/window, bounded reordering, keepalive, and FIN bookkeeping.
  Direct malformed-checksum, fragment-rejection, reordered-input, and withheld-
  ACK cases pass. Repeated-loss soak, SACK, multi-segment congestion tuning, and
  physical-network recovery remain unknown.
- Active IPv4/IPv6 transport paths reject fragments. End-to-end fragment
  reassembly is not integrated.
- AArch64 SMMUv3 is still bypass-only. General userspace thread creation is not
  exposed, although bounded SMP and thread-group work APIs exist.
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
