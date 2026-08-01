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

README, project tracker, hardware-readiness and benchmark methodology now label
QEMU as correctness/ABI evidence only. Older local wiki/generated material may
still contain historical targets and is not an authoritative support source.

Recommendation: treat performance numbers as targets or unverified design claims unless a human provides measured hardware baselines.

Evidence:
- `README.md`
- `PROJECT-TRACKER.md`
- `wiki/Qwen3.6-INT6-Support.md`
- `HARDWARE-READINESS.md`
- `contracts/qemu-rc-v1.json`

## Resolved in current working tree: syscall/API documentation lag

Source, userspace wrappers, `docs/API.md`, and the release-candidate contract now
cover syscalls 1-34. `scripts/qemu_gate_lib.py` rejects missing or extra source
syscalls/capabilities.

Evidence:
- `kernel/include/xaios/syscall.h`
- `userspace/include/xaios_user.h`
- `kernel/user/syscall.c`
- `docs/API.md`
- `contracts/qemu-rc-v1.json`
- `scripts/qemu_gate_lib.py`

## Conflicting: license status

`LICENSE` starts with MIT license text but ends with “License to be decided.” `README.md` also says license is to be decided.

Recommendation: do not alter license language without human approval.

Evidence:
- `LICENSE`
- `README.md`

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

## Unknowns

- Exact production Qwen/K3 source revisions for golden compatibility fixtures
  are not pinned yet; verify official configuration at importer implementation time.
- Exact source revisions for GLM 5.2 and the roadmap labels DeepSeek V4 Flash
  0731 and Qwen 3.7 27B are not pinned. The latter two exact labels still
  require authoritative upstream release verification.
- Hardware validation status beyond repository artifacts is unknown; currently
  no qualifying physical artifact is present.
- Production signing/key-management design is not complete in source comments inspected.
- Default macOS HVF QEMU aborts in `hvf_handle_exception`; TCG correctness passes.
- Whether `.qoder/repowiki/` should be removed, ignored, or refreshed is unknown; it was not modified.

## Ask a human before editing

- Licensing text.
- Hardware performance claims that lack benchmark-contract artifacts.
- Production security model/signing claims.
- Removal of non-onboarding docs with vendor-specific wording.
- Any change that relaxes capability checks, credential-material rejection, update authorization, or sandbox path validation.
