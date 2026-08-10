# XAIOS Wiki

This directory mirrors selected pages from the live GitHub Wiki. Current source,
build/test configuration, `docs/MODEL-SUPPORT.json`, and
`docs/PLATFORM-SUPPORT.json` take precedence over older Wiki revisions.

XAIOS is an experimental operating system and portable inference-engine
foundation. Its current QEMU paths validate deterministic OS/runtime contracts;
they do not prove real-model inference or physical-hardware performance.

## Delivery Sequence

The declared ARM and x86 QEMU core-OS gate is complete, so Qwen is ready as the
next workstream. Physical platform qualification continues separately. Later
model workstreams are not active unless the maintainer reprioritizes them.

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | QEMU Complete | ARM and x86 common-service correctness gates pass; physical platform qualification remains separate. |
| 2 | Qwen 3.6 27B Support | Ready | Next workstream; begin scalar tokenizer, tensor and logits correctness. |
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
  IPv4 and verified listener state or a numeric error. Password-enabled
  development images then provide authenticated serial login, while key-only,
  default and release images keep the local console locked.
- Local and SSH PTY sessions provide cwd-aware prompts, basic file/directory
  operations, command-not-found errors and interactive `nano`. MutableFS v4
  supports recursive directory rename/removal and bounded 128 KiB state files;
  it is not a replacement for ModelFS or general bulk storage.
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
- x86_64 executes the complete common kernel and userspace/service image. It
  starts MADT-discovered application processors, runs EL0 threads on APs with
  per-CPU page-table roots, preserves FP/SIMD interrupt state, and operates the
  shared filesystems, IPv4/IPv6, SSH/SFTP, control, security, AI Cell and
  telemetry paths over modern PCI VirtIO. Emulated NVMe also passes its focused
  data test, and a post-`sti` canary proves shared-driver MSI-X completion.
  QEMU service parity with AArch64 is complete; physical Intel qualification
  remains open.
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
