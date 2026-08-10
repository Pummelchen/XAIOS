# Current Limitations

This page records verified implementation gaps and explicit non-claims. It is
kept consistent with `docs/PLATFORM-SUPPORT.json`, project trackers, readiness
documents, and the QEMU release-candidate contract.

## Platform and hardware

- AArch64 QEMU provides the broadest complete OS-service path. QEMU validates
  behavior, not physical ARM performance, firmware behavior, or scaling.
- VMware Fusion 25.0.1 on Apple Silicon reaches `/init` through a generated
  ARM64 compatibility stage. VMware networking, persistent storage,
  multi-vCPU discovery, and later service gates are not integrated.
- The x86_64 image starts MADT-discovered processors, performs a controlled INT3 round trip
  and local-APIC timer interrupt, executes a ring-3 syscall,
  validates runtime-sized XSAVE and ACPI data, and exercises modern VirtIO
  block DMA/MSI-X plus network TX.
- Full AArch64 service parity on x86_64 remains open: complete userspace and
  thread services, receive networking and SSH, mounted filesystems, x86 NVMe
  operation, process-owned security services, AI Cell integration, and
  telemetry are absent.
- Physical Apple, Intel desktop, Xeon, SMMU/IOMMU, NVMe, NIC, NUMA, many-core,
  thermal, power, and performance evidence is not present.

## Networking and SSH

- FreeBSD 15.1, native macOS, and Debian 13 OpenSSH clients pass bounded QEMU
  interoperability suites. This is not a production Internet deployment or an
  independent security audit.
- The normal QEMU boot requires an external IPv4 A-record response before SSH
  binds. This checks the configured gateway/DNS path only; it is not a general
  Internet-health check. Failure leaves the capability-restricted local serial
  prompt available and reports a numeric startup error.
- The SSH service deliberately supports four transports and two active
  channels per transport. Fleet-scale identity, audit, replay, and connection
  policy remains unresolved.
- SSH key exchange is classical `curve25519-sha256` only. Hybrid post-quantum
  key exchange, OpenSSH interoperability and downgrade-policy review remain
  production security gates; the quiet local QEMU launcher only suppresses the
  OpenSSH 10 client notice for that development connection.
- DNS performs asynchronous external A-record resolution with timeout, retry,
  cache, and a QEMU-verified cache hit. DNSSEC, TCP fallback, complete AAAA
  application results, and deployment resolver policy remain absent.
- TCP implements retained segments, cumulative and partial ACK handling,
  RTT/RTO backoff, SACK, fast retransmit, zero-window handling, bounded
  reordering, keepalive, and FIN bookkeeping. Repeated-loss physical-network
  soak and congestion-control tuning remain unverified.
- Bounded IPv4/IPv6 fragment reassembly passes focused cases. Broad hostile
  fragment fuzzing remains incomplete.

## Storage and persistence

- VirtIO block/network use interrupt-driven completions, event-index
  suppression, indirect descriptors, and bounded queued work. Emulated NVMe
  covers focused identify/write/flush/read and backing-byte checks.
- Production NVMe multiqueue, queue affinity, cancellation, direct final-buffer
  expert reads, physical durability, discard behavior, and throughput remain
  open.
- ModelFS supports signed registration, resumable staging, verification,
  immutable activation, scrub/quarantine, cleanup/reuse, and free-only trim
  under hosted and QEMU tests.
- Trusted-replica repair, production signing and key custody, physical
  multi-terabyte transfer, and model-v2 execution admission are not complete.
- ModelFS activation and MutableFS audit persistence are separate durability
  domains. A post-publication audit failure cannot roll back an already
  published active generation.

## Administration and security

- `xaios.control.v1` operations are bounded to 16 active keys, 16 revoked
  fingerprints, 64 audit/replay records, and 16 shell contexts. These are
  implementation limits, not fleet-scale targets.
- Role, capability, replay, rollback, host-key rotation, sensitive-path denial,
  and secret-redaction behavior pass QEMU/OpenSSH gates but have not received an
  independent production security review.
- Update signing uses a development trust root to validate transaction,
  fallback, and rollback behavior. Production key management is unresolved.

## Inference engine and model support

- The kernel model-v1 path is a deterministic fixture. It does not execute a
  transformer and must not be described as real inference.
- Model-v2 parsing, streaming writing, architecture/backend registries,
  immutable readers, sessions, and scalar packed kernels are foundations only.
  Model-v2 packages are not yet executed end to end.
- No official tokenizer importer, real Qwen tensor importer, transformer plan,
  logits parity, or deterministic 32-token decode parity exists.
- Qwen 3.6 27B is blocked until the XAIOS platform completion gate. Kimi K3,
  DeepSeek V4 Flash 0731, and GLM 5.2 remain later roadmap targets.
- Kimi K3 KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts, native
  MXFP4, text parity, and multimodal execution are not implemented.
- Scalar INT4/INT6 and experimental NEON/AVX2 packed kernels pass bounded
  correctness tests. Physical AVX2 validation, AVX-512/VNNI, AMX, SVE,
  tiled prefill/verification, persistent worker gangs, and bandwidth autotuning
  remain incomplete.
- No complete model-executing native macOS process, Metal backend, physical
  model-parity run, cluster data plane, or immutable performance artifact
  exists.

## Evidence policy

Sparse files above 4 GiB or 100 GiB prove address width and bounded-memory
behavior, not physical transfer throughput. High-vCPU QEMU gates prove dynamic
metadata capacity, not server scalability. Performance claims require physical
artifacts satisfying `docs/BENCHMARK-CONTRACT.md`.

See [[Open Decisions|Open-Decisions]], [[Platform Support|Platform-Support]],
and [[Model Support Roadmap|Model-Support-Roadmap]].
