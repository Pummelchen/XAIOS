# XAIOS Wiki

This directory mirrors selected pages from the live GitHub Wiki. Current source,
build/test configuration, `docs/MODEL-SUPPORT.json`, and
`docs/PLATFORM-SUPPORT.json` take precedence over older Wiki revisions.

XAIOS is an experimental operating system and portable inference-engine
foundation. Its current QEMU paths validate deterministic OS/runtime contracts;
they do not prove real-model inference or physical-hardware performance.

## Delivery Sequence

Only the XAIOS platform workstream is active. Qwen is next, but remains blocked
until XAIOS reaches its completion gate. Later model workstreams are not active
unless the maintainer explicitly reprioritizes them.

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | In Progress | Finish the core OS, portable engine, model-v2 integration, platform services, hardware readiness, and release gates. |
| 2 | Qwen 3.6 27B Support | Blocked | Starts only after the XAIOS completion gate. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

## Current Boundaries

- The model-v1 QEMU path is a deterministic fixture, not a transformer.
- `xaios.model.v2` and portable adapter/backend APIs are interface foundations.
- No listed real model has passed tokenizer, logits, deterministic decode, and
  physical-hardware acceptance gates.
- QEMU is correctness and ABI evidence only.
- VMware Fusion 25.0.1 on Apple Silicon reaches `/init` through the limited
  ARM64 compatibility path. It has no VMware NIC/persistent-disk driver or
  multi-vCPU discovery and is not physical-hardware evidence.
- Performance claims require immutable artifacts under the benchmark contract.
- `xaiosctl` Phase 2 is QEMU/OpenSSH fixture-tested with role-mapped keys,
  revocation, config transactions, host-key rotation, redacted audit and typed
  storage lifecycle administration.
- Normal AArch64 images do not pre-run diagnostic applications. Exact
  allowlisted diagnostics run as transient SSH commands and are reaped after
  exit; deterministic QEMU gates retain a separate boot-fixture profile.
- Normal QEMU boots use an in-place colored 0-100% progress display. SSH binds
  only after an external IPv4 DNS response; the final screen reports the guest
  IPv4 and verified listener state or a numeric error, then leaves the local
  serial command prompt active.
- XAIOS uses a native freestanding ABI. FreeBSD is the primary external Unix
  behavioral reference, with a real FreeBSD 15.1 OpenSSH/SFTP/UDP QEMU gate;
  neither FreeBSD nor Linux binary ABI compatibility is claimed.
- Signed ModelFS supports dynamic registration, resumable SFTP, cleanup/reuse,
  verification, atomic activation, scrub/quarantine and free-only trim under
  QEMU. Concurrent macOS/Debian clients pass against one guest. QEMU VirtIO uses
  interrupt-driven block/network completions, event-index suppression, indirect
  descriptors and eight-request block batching. A focused emulated-NVMe gate
  verifies identify/write/flush/read and host backing bytes; production
  multiqueue and physical storage validation remain open.
- Runtime-sized NUMA/CPU/cpuset state and CPU-assigned worker threads pass QEMU;
  a focused TCG gate validates SMP and NUMA metadata with 130 emulated CPUs,
  while hosted cpuset tests cover 4,097 CPU IDs. EL0 create/join/cancel/exit,
  asynchronous DNS, IPv4/IPv6 reassembly, and SACK-aware TCP pass QEMU gates.
- x86_64 starts MADT-discovered application processors, dispatches IPI work,
  validates controlled exception and local-APIC timer interrupts, performs a
  real shared-runtime `/bin/hello` ELF LOG/EXIT ring-3 syscall round trip,
  executes common security/scalar-kernel self-tests, validates runtime-sized
  XSAVE and ACPI parsing, and operates modern VirtIO block DMA/MSI-X plus
  network TX.
  Full ARM-service parity on x86 remains open: complete userspace/thread services,
  receive networking/SSH, mounted filesystems, x86 NVMe, security, AI Cell and
  telemetry are not yet integrated.
- Model loading, cluster and inference-service administration remains gated.

## Start Here

- [[Developer Guide|Developer-Guide]]
- [[Architecture|Architecture]]
- [[Build System|Build-System]]
- [[Testing and Benchmarking|Testing-and-Benchmarking]]
- [[Security Model|Security-Model]]
- [[Current Limitations|Current-Limitations]]
- [[Open Decisions|Open-Decisions]]
- [[Risk Register|Risk-Register]]
- [[Development History|Development-History]]
- [[Model Support Roadmap|Model-Support-Roadmap]]
- [[Platform Support|Platform-Support]]
- [[VMware Fusion|VMware-Fusion]]
- [[Qwen CPU Inference Status|Qwen3.6-INT6-Support]]
- [[SSH Status|Production-SSH-Server]]
- [[Unix Compatibility|Unix-Compatibility]]
- [Repository README](https://github.com/Pummelchen/XAIOS/blob/main/README.md)
- [Implementation roadmap](https://github.com/Pummelchen/XAIOS/blob/main/docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md)
- [Distributed server plan](https://github.com/Pummelchen/XAIOS/blob/main/docs/DISTRIBUTED-AI-SERVER-PLAN.md)
- [xaiosctl reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
- [Large-model upload status](https://github.com/Pummelchen/XAIOS/blob/main/docs/LARGE-MODEL-UPLOAD.md)
- [Benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
- [GitHub Project](https://github.com/users/Pummelchen/projects/5)
