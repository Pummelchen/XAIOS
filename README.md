<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/e305c7bb-40f2-4454-87f8-f58c9082d808" />


# XAIOS

XAIOS is an experimental freestanding Unix-like operating system and portable inference-engine
foundation being developed as an SSH-administered distributed CPU AI model
server. The current OS boots under QEMU and exercises deterministic
kernel/runtime contracts. Real-model inference and the dedicated inference
network service are under development and are not production supported.

Human-facing project documentation is maintained in the
[XAIOS Wiki](https://github.com/Pummelchen/XAIOS/wiki). The repository keeps
selected Wiki pages under [`wiki/`](./wiki/) so architecture, development,
testing, security, and status claims can be checked with the source.

## Unix compatibility boundary

FreeBSD is the primary external behavioral reference for portable command,
SSH/SFTP and network interoperability work. XAIOS is not FreeBSD-derived and
does not provide a FreeBSD or Linux binary ABI: guest programs use native XAIOS
syscalls, and passing host-client tests proves wire behavior only. The official
FreeBSD 15.1 AArch64 QEMU gate covers public-key acceptance/rejection,
`xaiosctl`, SFTP, PTY ANSI `htop`, and UDP echo. The Debian 13 client remains an
independent Linux/OpenSSH cross-family gate with broader administration and
load coverage. See [Unix compatibility](./docs/UNIX-COMPATIBILITY.md).

## Model support status

[`docs/MODEL-SUPPORT.json`](./docs/MODEL-SUPPORT.json) is the authoritative
status and delivery-sequence source. CI checks the README, project tracker,
implementation roadmap, hardware-readiness document, and selected Wiki mirrors
against it.

| Model or path | Status | Current evidence and boundary |
|---|---|---|
| Deterministic QEMU model-v1 path | Fixture only | Validates model admission, private state, ABI and deterministic dispatch. It is not transformer inference or a hardware benchmark. |
| xaios.model.v2 tooling | Interface only | Streaming Python writer, Python reader and C parser pass round-trip, checksum, overflow and sparse-file tests. No production importer or executing model uses it yet. |
| Qwen 3.6 27B | Interface only | Next real-model bring-up target after XAIOS platform completion. Transformer execution, official tokenizer parity, logits parity and physical-hardware validation remain incomplete. |
| Kimi K3 text | Interface only | Queued behind XAIOS and Qwen for KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts and native MXFP4. Text inference is not available. |
| Kimi K3 multimodal | Roadmap only | Vision preprocessing, MoonViT-V2, projection, multimodal positions and golden image cases are a separate milestone. |
| DeepSeek V4 Flash 0731 | Roadmap only | Planned architecture-adapter target. The exact official release, configuration and tokenizer sources must be verified and pinned before implementation. |
| GLM 5.2 | Roadmap only | Planned architecture-adapter target. Import, tokenizer, operator, state, logits and physical-hardware parity work has not started. |

## Delivery sequence

This order is authoritative for current execution planning. Only XAIOS is
active. Qwen is the next workstream, but remains blocked until the XAIOS
platform milestone is complete. No relative order is assigned to the later
model workstreams unless the maintainer explicitly reprioritizes them.

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | In Progress | Finish the core OS, portable engine, model-v2 integration, platform services, hardware readiness, and release gates. |
| 2 | Qwen 3.6 27B Support | Blocked | Starts only after the XAIOS completion gate. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

XAIOS is designed for multiple official architecture identifiers rather than a
hard-coded Qwen graph. Qwen 3.6 27B remains the first real-model target after
the platform completion gate. Kimi K3 text and multimodal support are separate
later milestones. DeepSeek V4 Flash 0731 and GLM 5.2 are additional roadmap
targets, each requiring its own verified architecture adapter and parity gates.
Approximate routing or execution modes, if added, will be named, reported and
opt-in; exact target-model semantics are the default.

## Current implementation

- AArch64 UEFI/QEMU boot, freestanding kernel, EL0 userspace, VirtIO devices,
  filesystem, network, capability, AI Cell and telemetry fixtures. Runtime CPU
  discovery has no project-level core-count ceiling. Live timer interrupts
  preserve q0-q31 plus FPCR/FPSR through the FP/SIMD interrupt context, and
  joinable worker groups run on secondary CPUs. This is emulator correctness
  evidence, not ARM server scalability.
- Signed redundant A/B system-volume metadata, streamed update delivery,
  activation, failed-boot fallback and rollback correctness gates. Production
  key custody and physical power-loss testing remain separate requirements.
- Runtime-sized NUMA metadata, CPU registry, cpusets and core leases, plus a
  worker-thread runtime that dispatches and joins work on actual online CPUs.
  QEMU validates the data structures and behavior, not scaling or bandwidth.
- Interrupt-dispatched VirtIO-MMIO block and network completion paths with
  negotiated event-index suppression and indirect descriptors. Block I/O uses
  an eight-request direct-or-bounce queue and batches multi-sector transfers;
  network transmit accepts bounded scatter/gather input without requiring a
  whole-frame copy when the buffers are DMA-addressable. A QEMU NVMe path
  initializes admin and I/O queues, identifies its namespace, and passes a
  write/flush/read test whose backing bytes are checked by the host. Production
  NVMe multiqueue, interrupt affinity, physical durability, and performance
  remain unimplemented.
- An experimental freestanding SSH/SFTP service reachable through QEMU host
  forwarding, plus guest userspace UDP receive/echo and IPv6/TCP receive/send
  paths. OpenSSH clients on FreeBSD 15.1, macOS and in an official Debian 13
  Docker container verify authentication and rejection paths, with the broader
  Linux/macOS gates covering persistent host identity, strict
  SFTP operations, shared channels, forced rekey, four simultaneous sessions,
  reconnect recycling, userspace DNS, UDP echo, IPv4/IPv6 fragment reassembly,
  TCP reordering/retransmission and malformed transport rejection. TCP transmit
  uses an eight-segment SACK-aware cumulative/partial-ACK sliding window with
  fast retransmit, zero-window handling, and RTO backoff. A dual-origin load gate
  runs these paths in parallel against one successful guest instance and
  verifies fragmented TCP traffic and recovery after saturation.
  The native guest also turns an SSH PTY `htop` command into a terminal-sized
  ANSI dashboard with sampled CPU/memory percentages and dynamic many-core
  paging; non-PTY output stays plain for automation.
  SSH has no built-in password and fails closed without secure entropy. These
  QEMU checks complete the declared core-OS correctness gate; they do not approve
  Internet exposure or physical production deployment.
- A deterministic 80-byte model-v1 fixture path used only by QEMU correctness
  gates. The production decode syscall returns an explicit unsupported error.
- A hosted C99 engine boundary under `engine/` with on-demand model-v2 parsing,
  exact architecture registry IDs, backend capability selection, scalar FP32
  projection, and group-scaled signed INT4/INT6 no-expand GEMV/GEMM. The
  experimental AArch64 NEON backend is selected only after a known-answer
  canary and passes native scalar differential/tail tests. An experimental
  x86 AVX2 path passes INT4/INT6 known-answer execution under QEMU TCG; physical
  x86 validation is still required. `make engine-cli` builds the same boundary
  as native macOS/Linux `build/hosted/xaios-engine` with `probe`, `inspect`, and
  fail-closed `serve` commands. Caller-owned service registries provide
  immutable reader-backed admission, direct async range I/O and 64-bit session
  append/fork/commit/rollback; transformer execution remains unsupported.
- A streaming model-v2 writer under `tools/xaios_model_v2.py` that does not keep
  weight payloads proportional to package size in memory.
- A versioned `xaios.control.v1` boundary and shared `xaiosctl` client for
  measured queries plus persistent configuration, role-mapped Ed25519 keys,
  revocation, host-key rotation, redacted audit records, ModelFS lifecycle, GPT,
  format/mount/grow/fsck, online scrub and trim, and storage discovery. Native
  macOS and Debian 13 OpenSSH clients validate these operations against one live
  guest. The `/bin/xaiosctl` image application exercises the same parser/renderer
  used by the exact SSH allowlist; no arbitrary SSH executable launch is
  provided.
- Dynamically sized userspace image-page tracking with checked cleanup. The SSH
  image is no longer constrained by the former fixed 256-page tracking array.
- A backend-neutral 64-bit block API, redundant GPT parser/writer, mount-routing
  VFS, and signed ModelFS v1. Active QEMU guest packages are immutable; signed
  package registration allocates bounded staging extents online, followed by
  chunk-verified resumable SFTP writes, administrator verification,
  replay-protected audited activation, and immutable retrieval. Incomplete
  staging can be removed and its extents reused. Persistent cooperative scrub
  supports pause/resume/cancel and quarantine; trim is free-extent-only, supports
  dry-run/status/cancel, and reaches negotiated VirtIO discard under QEMU.
- A portable model-file boundary streams verified package ranges into
  caller-owned aligned arenas and exposes extent/prefetch metadata. Sparse tests
  exercise a 128 GiB volume and logical package above 100 GiB without
  materializing the payload. QEMU VirtIO now has interrupt-driven eight-request
  batching, and the focused emulated-NVMe gate validates admin/I/O queue and
  backing-image persistence behavior. Production NVMe multiqueue, a physical
  100+ GiB transfer, trusted-replica repair, and physical-device
  durability/performance validation remain incomplete.
- The x86_64 QEMU image links and executes shared CRC, block-device, VFS,
  architecture-registry, scalar-backend and packed-engine code. It owns its
  GDT/TSS and AP trampoline, passes a controlled exception round trip and a
  real local-APIC timer interrupt, starts all enabled MADT CPUs with dynamic
  records and stacks, dispatches IPI worker jobs, executes a real x86_64
  `/bin/hello` ELF from the shared userspace runtime through LOG/EXIT `int 0x80`
  calls, executes common security/scalar-kernel self-tests, and validates
  XSAVE/XRSTOR. ACPI parsing covers
  MADT/SRAT/SLIT/HMAT.
  The PCI path maps QEMU's high MMIO aperture, reads the boot disk through a
  modern VirtIO block DMA queue, receives MSI-X completion, and completes
  network TX. Full x86 service parity remains open: userspace/thread ABI parity,
  RX networking and SSH, mounted filesystems, x86 NVMe operation, security, AI
  Cell and telemetry remain pending; the x86 gate continues to report full
  parity as false.

The retired GGUF converter emitted packages incompatible with the model-v1
reader and has been made fail-closed. `tools/create_xaios_v1_fixture.py` exists
only for deterministic fixture generation. SafeTensors/config/tokenizer and
GGUF importers for model-v2 remain to be implemented.

## Administrative control

The implemented administrative surface is:

```text
xaiosctl version
xaiosctl status
xaiosctl health
xaiosctl capabilities
xaiosctl hardware
xaiosctl metrics
xaiosctl logs
xaiosctl config show|validate|diff|apply
xaiosctl auth key list|add|remove
xaiosctl auth host-key rotate
xaiosctl audit show
xaiosctl model verify PACKAGE_ID
xaiosctl model register PACKAGE_ID --model-uuid UUID --signer-key KEY \
  --signature SIGNATURE --source-revision REVISION --architecture ID \
  --target ID --size BYTES --operation-id ID
xaiosctl model activate PACKAGE_ID --operation-id ID
xaiosctl model cleanup PACKAGE_ID --operation-id ID
xaiosctl storage device list
xaiosctl storage partition list|verify|plan-create|create|plan-delete|delete|plan-resize|resize|repair ...
xaiosctl storage filesystem list
xaiosctl storage usage /models
xaiosctl storage format-plan|format|mount|unmount|fsck|resize-plan|resize ...
xaiosctl storage scrub /models --start|--status|--pause|--resume|--cancel
xaiosctl storage trim /models --dry-run
xaiosctl storage trim /models --all-free --operation-id ID
xaiosctl storage trim-status|trim-cancel /models ...
```

Every command supports `--json`, `--timeout` and `--node`. Mutations require a
nonzero replay-protected `--operation-id`. Ed25519 principals have observer,
operator or administrator roles; config apply requires operator and key or host
identity mutation requires administrator. Config, key/revocation and audit
state persists across reboot. Password authentication is disabled by default,
available only in an explicit development build, and rejected in release
builds. Private host-key and administrative state paths are denied through both
the compatibility shell and SFTP.

Values are measured from current kernel state where a source exists;
unimplemented discovery or services report `unknown`/JSON `null`. The Phase 2
surface is fixture-tested through QEMU with Debian 13 OpenSSH and a macOS-hosted
client/orchestrator. This is correctness evidence, not production security
qualification or approval for Internet exposure.

`xaiosctl health` currently reports degraded and exits nonzero because
production model inference and clustering are not available. This is expected
and prevents fixture health from appearing production-ready. See
[`docs/XAIOSCTL.md`](./docs/XAIOSCTL.md) and
[`docs/CONTROL-PROTOCOL.md`](./docs/CONTROL-PROTOCOL.md).

## Architecture direction

The XAIOS kernel owns topology, cpusets, isolation, NUMA/large-page allocation,
immutable mappings, asynchronous device queues, shared rings, timekeeping,
telemetry and AI Cell admission. The portable engine owns package parsing,
tokenizers/templates, architecture adapters, execution plans, sampling,
session state, batching, expert residency, speculation and backend selection.

The same engine boundary builds as an XAIOS component and as a native macOS or
Linux process. Scalar packed kernels and an experimental Apple CPU/NEON
kernel backend plus an experimental x86 AVX2 path now exist; they do not execute
a complete model and have no performance artifact. Metal and Xeon
AVX-512/VNNI/AMX with NUMA-aware expert placement remain unimplemented. Generic
ARM server scope is UEFI plus an SBSA-style PSCI/GICv3 platform with discovered
topology. QEMU `virt` remains the full device/service correctness target;
VMware Fusion on Apple Silicon now reaches `/init` through a limited ARM64
compatibility path. SVE/SVE2 are fail-closed capability IDs and roadmap targets,
not implemented backends.

## Build and validation

Host prerequisites are Clang, LLD, Python 3, mtools, QEMU and AAVMF/UEFI
firmware. See [`docs/GETTING-STARTED.md`](./docs/GETTING-STARTED.md).

```sh
make bootstrap
make engine-cli
make compile-check
make hosted-test
make hosted-sanitizer-test
make production-source-audit
make qemu-abi-contract
make image
make qemu-smoke
make qemu-storage-crash-test
make qemu-smmu-gate
make qemu-nvme-gate
make qemu-model-sftp-gate
make qemu-freebsd-network-suite
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-core-os-rc
make qemu-high-core-gate
make vmware-fusion-smoke
```

`make hosted-test` is the foundational model-v2/engine gate. QEMU gates validate
OS correctness and ABI behavior only. They do not establish model parity,
physical-hardware readiness, tokens per second, bandwidth, power, or production
support. The ModelFS gate requires macOS and Docker and runs concurrent native
macOS and Debian 13 SFTP clients against one guest; the parallel network gate
has the same host requirements. The focused high-core gate boots 130 emulated
CPUs only far enough to verify runtime-sized SMP and NUMA metadata; it is not a
scalability or performance benchmark.

The translated SMMUv3 isolation gate requires QEMU's test-only
`iommu-testdev`. Aggregate CI builds and caches the exact upstream QEMU commit
`6ce361b02c825b4a12a9684c47342859ee967cb2` through
`scripts/provision-qemu-smmu-testdev.sh`; it does not silently skip this gate
when the distro emulator lacks the device.

The authoritative 20-item platform parity status, including physical-only
Apple and Intel gates, is
[`docs/PLATFORM-SUPPORT.json`](./docs/PLATFORM-SUPPORT.json).

### VMware Fusion on Apple Silicon

VMware Fusion 25.0.1 on an M3 Mac has passed the repository smoke gate. The
generated ARM64 VM uses a Debian 13-built GRUB UEFI compatibility stage,
chainloads the XAIOS loader, obtains serial configuration from ACPI SPCR, loads
the deterministic initfs into firmware-owned memory, and reaches a successful
`/init` return. ARM PAN is enforced during this run, so the gate also exercises
PAN-safe syscall user-buffer access.

```sh
make vmware-fusion-image
make vmware-fusion-smoke
make vmware-fusion
```

This is virtual ARM64 correctness evidence, not native Apple hardware or
performance evidence. Fusion on Apple Silicon does not run the x86_64 XAIOS
image. The current VM deliberately has no virtual NIC; VMware storage/network
drivers, persistent disks, ACPI GIC/SMP/RTC discovery, multi-vCPU execution and
the later scheduler/application/SSH gates remain open. QEMU is still required
for the complete VirtIO, networking, SSH/SFTP, persistence and SMP suites. See
[`docs/VMWARE-FUSION.md`](./docs/VMWARE-FUSION.md).

## Documentation

- [Wiki home and documentation index](https://github.com/Pummelchen/XAIOS/wiki)
- [Developer guide](https://github.com/Pummelchen/XAIOS/wiki/Developer-Guide)
- [Current limitations](https://github.com/Pummelchen/XAIOS/wiki/Current-Limitations)
- [Model implementation roadmap](./docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md)
- [Distributed AI server plan](./docs/DISTRIBUTED-AI-SERVER-PLAN.md)
- [`xaiosctl` command reference](./docs/XAIOSCTL.md)
- [Control protocol](./docs/CONTROL-PROTOCOL.md)
- [xaios.model.v2 specification](./docs/MODEL-V2-SPECIFICATION.md)
- [Architecture adapters](./docs/ARCHITECTURE-ADAPTERS.md)
- [Hardware backends](./docs/HARDWARE-BACKENDS.md)
- [Portable engine service](./docs/ENGINE-SERVICE.md)
- [Benchmark evidence contract](./docs/BENCHMARK-CONTRACT.md)
- [OS architecture](./docs/ARCHITECTURE.md)
- [API](./docs/API.md)
- [Network and SSH status](./docs/NETWORK-SSH-STATUS.md)
- [Unix compatibility boundary](./docs/UNIX-COMPATIBILITY.md)
- [Storage architecture and status](./docs/STORAGE-ARCHITECTURE.md)
- [ModelFS v1 format](./docs/MODELFS-FORMAT.md)
- [ModelFS recovery](./docs/MODELFS-RECOVERY.md)
- [Storage tools](./docs/STORAGE-TOOLS.md)
- [Large-model upload](./docs/LARGE-MODEL-UPLOAD.md)
- [Storage security](./docs/STORAGE-SECURITY.md)
- [Storage benchmarking](./docs/STORAGE-BENCHMARKING.md)
- [Hardware readiness](./HARDWARE-READINESS.md)
- [VMware Fusion](./docs/VMWARE-FUSION.md)
- [Project tracker](./PROJECT-TRACKER.md)
- [Live GitHub Wiki](https://github.com/Pummelchen/XAIOS/wiki)
- [Live model support roadmap](https://github.com/Pummelchen/XAIOS/wiki/Model-Support-Roadmap)

Official compatibility sources used for the current design audit:

- [Qwen3.5-0.8B configuration](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/main/config.json)
- [Qwen3.6-27B configuration](https://huggingface.co/Qwen/Qwen3.6-27B/blob/main/config.json)
- [Qwen3.6 repository](https://github.com/QwenLM/Qwen3.6)
- [Kimi K3 configuration](https://huggingface.co/moonshotai/Kimi-K3/blob/main/config.json)
- [Kimi K3 repository and report](https://github.com/MoonshotAI/Kimi-K3)
- [GLM 5.2 model repository](https://huggingface.co/zai-org/GLM-5.2)

An immutable official source has not yet been pinned for the exact roadmap
label DeepSeek V4 Flash 0731. Its name in this document is a planning target,
not evidence of compatibility or implementation.

## Performance evidence

No physical Apple or Xeon benchmark artifact currently exists in this
repository. Performance numbers without immutable artifacts meeting
[`docs/BENCHMARK-CONTRACT.md`](./docs/BENCHMARK-CONTRACT.md) are targets, not
results. Microbenchmark improvements may not be multiplied into end-to-end
claims.

## License

XAIOS is source-available under the
[PolyForm Noncommercial License 1.0.0](./LICENSE). The license permits private,
personal, educational and noncommercial research use, including use by
universities and public research organizations. It does not grant commercial
use.

Commercial use requires a separate written commercial license obtained before
use. See [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md) for the licensing
route. XAIOS is not MIT-licensed because the MIT License permits unrestricted
commercial use.
