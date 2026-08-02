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

## 2026-08-03 - dual-origin single-guest SSH/network load

- Added a macOS plus Debian 13 load gate that drives native OpenSSH/SFTP, UDP,
  and two framed raw TCP clients concurrently against one successful XAIOS
  guest instance.
- Fixed regular-file SFTP CLOSE status, shared-transport channel-close
  acknowledgement, bounded atomic audit logging, stale address-family state on
  recycled TCP flows, TIME_WAIT reclamation, and TCP drain fairness.
- Matched socket-buffer capacity to the configured TCP and UDP flow limits and
  made the raw clients close their successful flows explicitly.
- Verified four-connection/eight-channel saturation, clean over-capacity
  rejection, 40 SFTP cycles, 330 UDP round trips, 40 reconnects, and post-load
  recovery without claiming physical-network production readiness.
- Made VirtIO completion waits use a monotonic deadline rather than a
  CPU-speed-dependent spin count, acquire-ordered device-written status/data
  consumption, and added block-flush failure diagnostics.

## 2026-08-02 - SSH and network QEMU completion gate

- Added VirtIO RNG-backed SSH entropy, persistent flushed Ed25519 host keys,
  authorized-key authentication, strict PBKDF2 user records, and fail-closed
  entropy/default/malformed configuration tests.
- Added SSH rekey, per-connection channels and SFTP handles, flow-controlled
  channel output, absolute SFTP offsets, and cooperative four-session service.
- Added TCP checksum/sequence/window validation, retained-segment and FIN
  retransmission, RTT/RTO tracking, bounded reordered receive, keepalive, and
  IPv4 fragment rejection on the active path.
- Expanded the Debian 13 gate with host-key reboot, forced rekey, shared-channel,
  malformed packet, reorder, retransmission, and negative image variants; made
  it an independent CI job.
- Replaced stale-address PMM double-free tracking with lock-protected NUMA
  allocation ownership, eliminating false rejections of reused pages and the
  post-release page write; added boot-time double-free and reuse assertions.
- Hardened SSH packet/version/authentication length validation, closed SFTP
  handles on every channel completion, and made READDIR bounded and stateful.
- Added UDP checksum generation/validation, atomic datagram boundaries and flow
  buffer reclamation; hardened TCP reset, allocation, and accept-backlog paths.

## 2026-08-02 — Debian 13 SSH and network interoperability

- Raised the bounded freestanding SSH service from one to four simultaneous
  connections and made packet assembly, channels, and SFTP handles
  connection-owned.
- Added conservative retained-payload TCP retransmission with persistent-loop
  timeout maintenance, receive-window ACKs, closing-flow reclamation, and
  unconditional VirtIO RX descriptor recycling.
- Added an official Debian 13 Docker client gate covering password acceptance
  and rejection, SFTP transfer/stat, overlapping SFTP sessions, four concurrent
  SSH sessions, reconnect recycling, UDP echo, and direct IPv6/TCP with a
  deliberately withheld-ACK retransmission check.
- Kept physical NIC, adverse-network, rekey, production-key, security-review,
  and long-soak claims explicitly unresolved.

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
