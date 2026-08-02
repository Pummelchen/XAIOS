<!--
AI onboarding file.
Mode: bootstrap
Indexed commit: 8458ff956831e1b3b44a0cbcb396352ce28e3a01
Last generated: 2026-06-25T09:20:22Z
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# AI onboarding changelog

## 2026-08-02 — delivery sequencing and Wiki synchronization

- Made XAIOS platform completion the only active workstream and Qwen 3.6 27B
  the next gated workstream.
- Added a machine-checked delivery sequence to the authoritative model-support
  source, README, project tracker, implementation roadmap, and local Wiki
  mirrors.
- Replaced stale Qwen and SSH production/performance claims with current
  fixture, interface, and physical-evidence boundaries.
- Synchronized the live GitHub Project, milestones, tracker issues, and Wiki
  status pages with the same order.

## 2026-08-02 — QEMU launcher and early spinlock regression fixes

- Made TCG the default AArch64 QEMU accelerator on every host; HVF remains an
  explicit experimental override with a warning.
- Added an early single-core `xaios_spin_trylock()` reuse self-test and QEMU
  smoke marker.
- Added ABI-gate coverage for the safe launcher default.

## 2026-08-02 — sampled htop accounting

- Replaced tick-count-only `htop` output with monotonic sampled `%CPU`, resident
  `%MEM`, cumulative runtime, and per-CPU busy/idle data.
- Added scheduler switch accounting and process dispatch/exit runtime tracking.
- Allocated the monitoring registry from the runtime-discovered CPU count and
  added continuation paging instead of 32/64-core display masks.
- Removed 32-CPU truncation from scheduler and SMP aggregate scans.
- Separated managed-memory pressure from detected physical capacity so NUMA
  bitmap overflow is not counted as used memory.

## 2026-08-02 — command utilities

- Added bounded, line-oriented `nano` editing commands backed by the mutable
  filesystem, with immediate saves and explicit capacity errors.
- Added `htop` process snapshots backed by live kernel scheduler/process data.
- Added QEMU and SSH-bridge coverage for editing and process-table behavior.
- Documented that XAIOS does not yet provide the TTY ABI needed for full-screen
  curses interfaces.

## 2026-08-01 — license resolution

- Replaced the contradictory MIT/to-be-decided text with the standard PolyForm
  Noncommercial License 1.0.0.
- Recorded permitted private, educational and noncommercial university research
  use and the requirement for a separate written commercial license.
- Added `COMMERCIAL-LICENSE.md` and synchronized README and onboarding status.

## 2026-06-25 — bootstrap

Indexed commit: `8458ff956831e1b3b44a0cbcb396352ce28e3a01`

### Added

- Root `AI_INDEX.md` with repository snapshot, task map, commands, risks, and read order.
- Root `AGENTS.md` with vendor-neutral AI-agent working rules.
- `.ai/START_HERE.md` first-session prompt.
- `.ai/PROJECT_MAP.md`, `.ai/ARCHITECTURE.md`, `.ai/COMPONENTS.md`.
- `.ai/COMMANDS.md`, `.ai/TESTING.md`, `.ai/SECURITY.md`, `.ai/PLAYBOOKS.md`.
- `.ai/KNOWN_UNKNOWNS.md` for conflicts and unresolved questions.
- `.ai/MANIFEST.json` machine-readable manifest.

### README

- Added a top-of-file AI onboarding block after the title.
- Preserved the existing project README content.

### Model-specific file migration

- No generated model-specific AI onboarding files were found during targeted inspection.
- No model-specific AI files were created.

### Risks recorded

- QEMU correctness vs hardware performance claim conflict.
- Syscall/API/contract documentation drift.
- License ambiguity.
- Some stale or duplicate existing human docs.
