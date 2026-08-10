# Development History

This page summarizes significant implementation and validation changes. Git
commits, source code, and machine-readable test artifacts remain authoritative.

## 2026-08-10 - on-demand diagnostic applications

- Removed workers and diagnostic applications from the normal boot lifecycle;
  persistent SSH now starts as PID 3 after `/init` and the service manager.
- Added an exact SSH diagnostic registry that runs each utility in a separate
  transient address space and reaps its process slot and pages after exit.
- Kept historical boot markers under the explicit `XAIOS_BOOT_TEST_APPS=1`
  QEMU fixture profile.
- Made process-local user mappings authoritative and preserved complete
  AArch64 callee-saved state across nested EL0 execution.
- Provisioned `/tmp`, `/home`, and `/home/admin` during filesystem mount so SFTP
  no longer depends on `systest` having run during boot.
- Passed the QEMU smoke contract and the Debian 13 OpenSSH/SFTP/network suite,
  including the on-demand execution and reaping assertion.

## 2026-08-10 - interactive XAIOS htop

- Made bare `htop` select all process slots, all detected CPUs, and a 250 ms
  live refresh while retaining explicit view, interval, and CPU-range options.
- Matched Debian htop's adaptive, column-major CPU header: eight CPUs in the
  left column beside Tasks/Load/Uptime, followed by 2/4/8/16-column grids with
  width-aware density and unbounded ordinal paging.
- Added scheduler-maintained fixed-point 1/5/15-minute load averages and kept
  Memory/Swap aligned beneath the left CPU group.
- Converted PTY `htop` from a one-shot ANSI screen into a persistent live SSH
  application with periodic sampled refresh and output-window backpressure.
- Added selection, process paging, CPU paging, terminal resize, active/all
  views, sorting, reverse order, filtering, help and process-tree display.
- Added a monotonic 60-frame-per-second hard cap across periodic, keyboard,
  filter, help and resize-triggered rendering; rapid changes are coalesced.
- Kept non-PTY output machine-readable and one-shot, retained runtime-sized CPU
  accounting, and documented that kill/nice await a safe process-control ABI.
- Extended the Debian 13 and FreeBSD interoperability gates to send keys, verify
  interactive frames and help/filter state, quit cleanly and restore the cursor.

## 2026-08-10 - FreeBSD Unix-reference interoperability

- Added a checksum-pinned official FreeBSD 15.1 AArch64 QEMU client gate for
  SSH key acceptance/rejection, `xaiosctl`, SFTP, PTY ANSI `htop`, and UDP.
- Defined FreeBSD as the external Unix behavioral reference while explicitly
  rejecting implied FreeBSD or Linux binary ABI compatibility.
- Retained Debian 13 as an independent Linux/OpenSSH cross-client and made both
  gates separate CI jobs.

## 2026-08-10 - native SSH PTY htop dashboard

- Added validated per-channel SSH PTY dimensions and resize handling.
- Added the initial guest-generated ANSI `htop` snapshot with colored CPU/memory meters,
  process framing, terminal-bounded rows, and runtime-sized CPU pagination.
- Preserved plain non-PTY output for automation and added QEMU plus Debian 13
  OpenSSH coverage for both output modes.

## 2026-08-10 - VMware Fusion ARM64 bring-up

- Added a reproducible Debian 13 GRUB UEFI compatibility stage, El Torito VM
  bundle generator, GUI runner and serial-marker Fusion smoke gate.
- Added boot-info v6 optional initfs extents and an explicitly volatile
  `boot-memory` compatibility device while retaining QEMU VirtIO behavior.
- Added ACPI SPCR serial discovery, ARM PAN-safe syscall user access, and
  fail-closed handling for absent fixed-address GIC/PL031/VirtIO-net devices.
- Verified Fusion 25.0.1 on an M3 Mac through a successful `/init` return and
  retained VMware networking, persistent storage, SMP/GIC/clock discovery and
  physical-performance boundaries as open.

## 2026-08-09 — portable compile, x86 ELF, and syscall hardening

- Added architecture-neutral CPU primitives and made all common kernel and
  userspace C compile as real AArch64 and x86_64 objects.
- Replaced the synthetic x86 ring-3 byte canary with a real `/bin/hello` ELF
  built from the shared userspace startup/runtime and LOG/EXIT syscall ABI.
- Executed shared security and scalar packed-kernel self-tests in the x86 image.
- Audited syscall capability and user-buffer paths; added process-owned dynamic
  sockets, process-reclaim cleanup for sockets and VFS handles, bounded I/O,
  descriptor narrowing checks, and kernel-owned snapshots for mutable
  log/write/send payloads.
- Enforced valid connected/TCP and datagram/UDP send-state pairs without
  blocking UDP replies; one guest passed the simultaneous macOS and Debian 13
  SSH, SFTP, IPv4/IPv6 TCP, UDP and reconnect load gate.
- Kept full x86 service integration and all physical-hardware evidence marked
  incomplete.

## 2026-08-04 - remaining QEMU core-OS tranche

- Pinned the aggregate CI SMMUv3 gate to upstream QEMU commit
  `6ce361b02c825b4a12a9684c47342859ee967cb2`, added a fail-closed provisioner
  for its test-only `iommu-testdev`, and made the AArch64 launcher honor an
  explicit validated `XAIOS_QEMU` binary override.
- Moved official checkout, cache and artifact-upload Actions to their Node 24
  release lines so CI no longer relies on GitHub's forced Node 20 fallback.
- Reconciled the authoritative 20-item platform status, repository tracker and
  Wiki table with the green ten-job CI run and live GitHub milestones; retained
  separate blockers for full x86 service parity and physical hardware evidence.

- Expanded VirtIO block to eight queued requests and negotiated event-index and
  indirect descriptors for block/network; the modern net header is 12 bytes.
- Added emulated-NVMe admin/I/O queue, SMMUv3 translated-DMA/revocation,
  redundant-metadata crash, and >128-CPU focused gates.
- Added general EL0 threads, asynchronous userspace DNS, IPv4/IPv6 fragment
  reassembly, and SACK/zero-window/reordering/RTO TCP correctness paths.
- Added x86 controlled exception and local-APIC timer interrupt delivery plus
  modern VirtIO/MSI/MSI-X capability discovery while retaining parity blockers.
- Expanded `make qemu-core-os-rc` into an independent, non-skipping aggregate
  gate and added a production-source unfinished-marker audit.

## 2026-08-03 - core OS capability tranche

- Added signed redundant A/B system-slot loading, streamed delivery, activation,
  fallback and rollback correctness coverage.
- Replaced fixed RAM/CPU bitmap ceilings with runtime-sized NUMA, CPU registry,
  cpuset and core-lease state.
- Added GIC-dispatched VirtIO block/network interrupts, two concurrent block
  requests, direct-or-bounce DMA and batched multi-sector backend transfers.
- Added CPU-assigned joinable kernel workers and routed the userspace thread-group
  contract through real secondary-CPU execution.
- Added an eight-segment TCP transmit window with cumulative/partial ACK release,
  fast retransmit and RTO recovery.
- Linked common CRC/block/VFS/architecture/scalar/packed modules into x86_64 and
  retained explicit full-platform-parity blockers.
- Added `make qemu-core-os-rc` and an independent CI evidence job.
- Added hosted 4,097-CPU cpuset coverage and a focused 130-vCPU QEMU capacity
  gate with a machine-readable correctness-only report.
- Corrected the worker-group smoke marker so it no longer claims an arbitrary
  EL0/POSIX thread ABI.
- Made the known-unstable macOS HVF CPU-matrix tier opt-in and replaced a stale
  fixed capability-count readiness assertion with structural ABI validation.

## 2026-08-03 - final storage/network acceptance fixes

- Corrected the VirtIO network receive header to the 10-byte base layout used
  when `VIRTIO_NET_F_MRG_RXBUF` is not negotiated; the former 12-byte strip
  discarded the first two Ethernet bytes and prevented forwarded SSH traffic.
- Made MutableFS fsck validate current and snapshot files independently,
  including files deleted after a snapshot, so read-only filesystem usage
  queries no longer report valid retained blocks as leaked.
- Added live storage device/filesystem JSON assertions to the native macOS and
  Debian 13 OpenSSH gates and checked ModelFS staging/active accounting across
  audited activation.
- Moved the SSH readiness marker after channel initialization and removed
  per-send UART logging from the network hot path.

## 2026-08-03 - guest storage discovery

- Added observer-safe `xaiosctl storage` device/filesystem discovery and usage
  operations with bounded typed records and explicit truncation reporting.

## 2026-08-03 - resumable guest ModelFS lifecycle

- Added signed pre-registered ModelFS staging writes with chunk verification,
  copy-on-write catalog publication and crash-consistent fsync ordering.
- Added administrator-only `xaiosctl model verify` and replay-protected,
  audited atomic activation while preserving immutable active packages.
- Added a native OpenSSH gate that uploads 2 MiB, resumes the final 64 KiB,
  verifies, activates, checks audit and compares the immutable download against
  one QEMU guest.
- Kept dynamic package registration, async I/O, physical 100+ GiB transfer and
  physical storage evidence explicitly pending.

## 2026-08-03 - storage and ModelFS foundation

- Added a generic 64-bit block API, redundant GPT parser/writer, bounded
  partition devices, VFS mount routing, and MutableFS compatibility adapter.
- Added signed crash-consistent ModelFS v1 host lifecycle/fsck/scrub/grow/trim
  tooling and a read-only kernel mount at `/models`.
- Added 64-bit SFTP positional I/O/fsync hardening and a portable model-file API
  with verified range reads, extent/prefetch metadata, aligned arena streaming,
  and sparse package tests above 100 GiB.
- Documented that guest ModelFS writes, online administration, asynchronous
  storage, real model execution, and physical performance evidence remain
  pending.

## 2026-08-03 - packed scalar, NEON and AVX2 kernel correctness

- Added a portable signed INT4/INT6 group-scale matrix contract with no-expand
  scalar GEMV/GEMM and an experimental AArch64 NEON backend.
- Added startup known-answer validation plus randomized scalar/NEON
  differential tests across every packing and vector tail.
- Added an experimental AVX2 backend with XCR0 capability gating and INT4/INT6
  known-answer execution in the freestanding x86 QEMU gate.
- Removed full-matrix INT4/INT6 expansion and the leaked temporary buffers from
  the legacy kernel, fixed packed work-unit offsets, and labeled sequential
  compatibility dispatch accurately.

## 2026-08-03 - Phase 2 administrative security

- Extended `xaios.control.v1` to 16 typed operations with strict config
  transactions, persistent observer/operator/administrator Ed25519 keys,
  revocation, host-key rotation and payload-redacted audit.
- Added the control-admin capability, syscall 38 per-connection shell contexts,
  sensitive remote-path denial and default-disabled/development-only password
  build policy.
- Replaced fixed userspace ELF page tracking with validated dynamic ownership
  and rollback.
- Added hosted, QEMU and Debian 13 OpenSSH acceptance cases for roles, valid and
  invalid/revoked keys, config rollback/replay, cwd isolation, rate limits,
  rekey, persistence/rotation and secret redaction.

## 2026-08-03 - Phase 1 administrative control

- Added the bounded `xaios.control.v1` protocol, syscall 37 and the
  `XAIOS_CAP_CONTROL_QUERY` capability.
- Added `/bin/xaiosctl` and shared local/SSH parsing/rendering for seven
  read-only measured commands with deterministic JSON and stable errors.
- Replaced hardcoded legacy status/platform claims, added log cursors and
  sensitive-line redaction, and froze protocol constants in the QEMU ABI.
- Added hosted, QEMU and Debian OpenSSH tests plus the ten-phase distributed
  server dependency plan.

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
- Added `COMMERCIAL-LICENSE.md` and synchronized the README and project status
  documentation.
