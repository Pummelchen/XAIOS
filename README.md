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
| Qwen 3.6 27B | Interface only | Next real-model bring-up target; its QEMU platform entry gate now passes. Transformer execution, official tokenizer parity, logits parity and physical-hardware validation remain incomplete. |
| Kimi K3 text | Interface only | Queued behind XAIOS and Qwen for KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts and native MXFP4. Text inference is not available. |
| Kimi K3 multimodal | Roadmap only | Vision preprocessing, MoonViT-V2, projection, multimodal positions and golden image cases are a separate milestone. |
| DeepSeek V4 Flash 0731 | Roadmap only | Planned architecture-adapter target. The exact official release, configuration and tokenizer sources must be verified and pinned before implementation. |
| GLM 5.2 | Roadmap only | Planned architecture-adapter target. Import, tokenizer, operator, state, logits and physical-hardware parity work has not started. |

## Delivery sequence

This order is authoritative for current execution planning. The declared ARM
and x86 QEMU core-OS gate is complete, so Qwen is ready as the next workstream.
Physical platform qualification continues separately. No relative order is
assigned to later model workstreams unless the maintainer reprioritizes them.

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | QEMU Complete | ARM and x86 common-service correctness gates pass; physical platform qualification remains separate. |
| 2 | Qwen 3.6 27B Support | Ready | Next workstream; begin scalar tokenizer, tensor and logits correctness. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

XAIOS is designed for multiple official architecture identifiers rather than a
hard-coded Qwen graph. Qwen 3.6 27B is now the active real-model target after
the QEMU platform gate. Kimi K3 text and multimodal support are separate
later milestones. DeepSeek V4 Flash 0731 and GLM 5.2 are additional roadmap
targets, each requiring its own verified architecture adapter and parity gates.
Approximate routing or execution modes, if added, will be named, reported and
opt-in; exact target-model semantics are the default.

## Boot and local console

A normal QEMU boot presents one in-place progress display from the UEFI loader
through service startup. `XAI` is shown in purple and `OS` in cyan; each update
reports the last completed component, the component in progress, and the number
still required. Verbose kernel diagnostics remain available to the log system
without scrolling the normal console. The explicit QEMU test profile retains
text markers for automated correctness gates.

After the VirtIO IPv4 stack is ready, the persistent service resolves an
external A record through the configured DNS path before opening TCP port 22.
Only a successful check permits SSH initialization. The completed screen prints
the configured guest IPv4 address and either `SSH server: up and running` or a
numeric startup error. A password-enabled development image then presents
`xaios login:` and authenticates the local console against the same PBKDF2 user
database used by SSH. Key-only, default, and release images keep the serial
console locked and direct administrators to SSH public-key authentication; no
built-in local password exists. After login, the cwd-aware
`admin@xaios:<path>$` prompt uses the same session-aware command parser as SSH.
This DNS round trip is a QEMU reachability gate, not proof that arbitrary
Internet destinations or physical networks are production-ready.

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
  live ANSI monitor with sampled CPU/memory percentages, process selection,
  scheduler-backed 1/5/15-minute load averages, sorting, filtering, help,
  resize handling and dynamic many-core paging. Its Debian-style header keeps
  up to eight CPU meters in the left column beside Tasks/Load/Uptime, then uses
  progressively denser 2/4/8/16-column CPU grids as core counts grow;
  bare `htop` shows all process slots and detected CPUs at a 250 ms refresh,
  while command-line options can still narrow the view or change the interval;
  a monotonic limiter caps all screen rendering at 60 frames per second, and
  non-PTY output stays a plain one-shot snapshot for automation. The htop sample
  interval uses an interrupt-backed idle wait that is not charged as artificial
  100% housekeeping-core load.
  Running `pong` from an authenticated local console or SSH PTY starts a native
  terminal game against a predictive, rate-limited computer paddle. The human
  uses `W`/`S`; scores continue without a match limit. A human point multiplies
  ball speed by 1.01 and a computer point multiplies it by 0.99, with bounded
  40%-300% safety limits so very long sessions remain playable. Each session
  owns independent scores and game state, responds to SSH terminal resize, and
  restores the original screen and prompt on exit.
  A bare SSH PTY opens a stateful, line-edited shell with a per-connection cwd,
  Unix-style prompt, useful command-not-found diagnostics, and nonzero command
  status. MutableFS v4 provides files and directory trees with atomic recursive
  rename and explicit recursive removal; it remains a bounded state filesystem
  with 128 nodes, 128 KiB files, 64 open handles and 2 MiB of data space.
  Existing valid v2/v3 volumes are migrated rather than silently reformatted.
  `nano PATH` is an interactive alternate-screen editor over both the local
  console and SSH PTYs, with cursor movement, scrolling, insert/delete,
  save and dirty-exit confirmation. Its editable buffer is intentionally
  limited to 32 KiB even though the filesystem accepts larger state files.
  The shell also provides bounded FreeBSD-style core utilities: `ls`, `cd`,
  `pwd`, `mkdir`, `rm`, `cp`, `mv`, `cat`, interactive `less`, `grep`, `find`,
  `ps`, `df`, `du`, POSIX ustar `tar`, and standard `zip`/`unzip`. Tar reads
  ustar, POSIX PAX, GNU long-name and gzip-wrapped archives; ZIP reads stored
  and Deflate entries. Archive paths, checksums and size arithmetic are
  validated before extraction. These tools follow documented portable subsets,
  not a claim of complete FreeBSD or POSIX userland compatibility.
  The SSH PTY includes an outbound SSHv2/SFTP client: `ssh [-p PORT]
  user@host [command]` and `scp [-r] [-P PORT] SOURCE DESTINATION` interoperate
  with OpenSSH using password authentication, verified Ed25519 host keys and a
  persistent fail-closed known-hosts file. IPv4 and A-record destinations are
  supported; public-key client authentication and IPv6 active opens remain
  explicit follow-up work.
  Normal images start only `/init`, `/bin/service-manager`, and the persistent
  `/bin/sshd`; diagnostic applications are not run during boot. An administrator
  can invoke `hello`, `sysinfo`, `systest`, `smptest`, `nettest`, `lstm-xor`,
  `mltest`, `posix-shell`, or `agenttest` through the exact SSH command allowlist.
  Each command runs in a separate transient address space and is reaped after
  exit, so completed diagnostics do not remain in `htop`. The QEMU smoke gates
  build a separate fixture profile that runs these applications once to retain
  deterministic correctness markers.
  `scripts/ssh-xaios-qemu.sh` provides a quiet local QEMU client with persistent
  host-key checking for interactive commands such as `htop`. Both architecture
  launchers forward host TCP port `7788` to guest SSH port `22` by default;
  connect with `ssh -p 7788 admin@127.0.0.1`. The server still
  negotiates classical `curve25519-sha256`; hybrid post-quantum SSH key exchange
  remains a production security gate.
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
  used by the exact SSH allowlist. The allowlist also exposes a fixed set of
  diagnostic applications as isolated transient processes; arbitrary paths,
  arguments, and executable launch remain unavailable.
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
- The x86_64 QEMU image executes the same common kernel and complete userspace
  service image as AArch64. It owns its GDT/TSS and AP trampoline, starts every
  MADT CPU with dynamic records and per-CPU page-table roots, runs EL0
  create/join/exit threads on APs, and preserves FP/SIMD state across live
  interrupts with runtime-sized XSAVE/XRSTOR or FXSAVE/FXRSTOR fallback. The
  shared filesystems, security, AI Cell, telemetry, control, utilities and
  SSH/SFTP services run over modern PCI VirtIO block/network; emulated NVMe
  identify/write/flush/read also passes. The platform matrix covers 1, 4, 8,
  128 and 256 vCPUs including x2APIC, and the Debian 13 OpenSSH/SFTP/IPv4/IPv6
  suite passes against the x86 guest. QEMU service parity with AArch64 is
  complete at the declared correctness boundary. This is not physical Intel
  compatibility, security certification, scalability, or performance evidence.

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
make qemu-x86_64-smoke
make qemu-x86_64-cpu-matrix
make qemu-x86_64-platform-matrix
XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-docker-network-suite
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
