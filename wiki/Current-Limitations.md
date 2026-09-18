# Current Limitations

This page records verified implementation gaps and explicit non-claims. It is
kept consistent with current source and the QEMU release-candidate contract.
Progress status and ownership live only in [[Project Tracker|Project-Tracker]].

## Architectures

AArch64, x86_64 and RISC-V (rv64gc) all run the same shared kernel. On the
QEMU `virt` board RISC-V boots to the first-run setup prompt: Sv48 paging where
the hart offers it and Sv39 where it does not, chosen at run time, with
section-accurate kernel permissions and validated 2 MiB and 1 GiB leaves in
both modes; PLIC interrupts, or an APLIC and IMSIC when the board is started
as `virt,aia=aplic-imsic`; remote TLB shootdown through SBI RFENCE; PCI
enumerated through ECAM with base addresses assigned by the kernel, virtio
disks, the initial filesystem, IPv6, userspace over a full trap frame, and
four harts scheduling.

It also has the hosted ISO C99 library, `xapt`, a real-time clock, a login
prompt, a working SSH server, and a UEFI boot medium built by
`scripts/build-riscv64-boot-media.sh`.

What it does not have is hardware qualification. AArch64 and x86_64 are
qualified on real machines and hypervisors; RISC-V has been run on one
emulated board and nothing else, so no claim about firmware behaviour, timing
or scaling on RISC-V hardware is supported by anything here. Both boot paths are complete: the kernel can be handed to QEMU directly, or
booted from its own disk through UEFI firmware. Build 8 ships a RISC-V image of its own, along with a QEMU kit, a USB
kit and a network-boot binary, as build 6 did first, and
`make release-image-gate` boots that image
*as the file that ships* -- it is one of the gate's five environments. Getting there corrected two things that had made the claim
weaker than it read: the image build did not build the RISC-V half at all but
picked up whatever `build/` held, which is how build 5's ISO came to carry a
build 4 RISC-V kernel; and the gate attached the tree's own A/B system volume,
which the loader prefers over the kernel on the medium, so every log it had
ever produced said "loaded verified A/B system slot" and it had been proving
that the image's *loader* boots and then running a kernel from `build/`. All
three QEMU legs boot with no system volume now, which is what a first boot on
a real machine looks like.

**EL0 preemption is real on RISC-V now, and the other two ports still lack
the per-task kernel context it needs.** This page used to say RISC-V had no tick
to attach to, because `kernel/arch/riscv64/` named no `scheduler_*` symbol. That
part was fixed first: the RISC-V timer interrupt maps its trap frame to the
scheduler's context frame, ticks it and maps the answer back, with its own
round-trip self-test that the smoke requires by name
(`sched-tick: riscv64 trap-frame mapping self-test passed`).

**Then a user process was made a scheduled task, and the proof of preemption is
a boot.** A loaded process is registered on the CPU running it and adopted as
that CPU's current task; it owns a kernel stack of its own and is entered from a
task entry on that stack; and when it exits the task hands the CPU back through
the scheduler rather than unwinding into the context that dispatched it. A
measurement of preemption needs a second runnable task, so the dispatching
context stays `RUNNABLE` at the process's own priority and is re-queued behind
it, and the two alternate. The boot gate dispatches `/bin/spin` -- a process
that never yields, looping in EL0 for 1.2 seconds -- twice: with the dispatcher
runnable it reports `kernel: /bin/spin preempted pid=7 switches=86` and asserts
at least four, and with it blocked it reports `kernel: /bin/spin blocked
dispatcher pid=8 switches=2` and asserts strictly fewer, which is the control
that keeps the first number honest.

**The remaining work is the same work in different places, and it is what stops
the other two ports.** On x86-64 the kernel continuation a process returns
through is one slot per CPU and nesting depth (`user_resume_rsp[]` and the TSS
`rsp0` derived from it), and floating-point state is one area per CPU and depth,
so a switch would hand the incoming task the outgoing task's return path and
registers; a trap taken in kernel mode has no `RSP`/`SS` words in its frame to
apply a switch into at all. Its tick was therefore removed rather than left
half-working: it passed the scheduler a context frame that nothing filled and
never applied the one it got back, which corrupted the scheduler's bookkeeping
without switching the CPU. On AArch64 the exception return keeps the CPU's
`SP_EL1` instead of loading a kernel stack from the frame, so a task cannot own
its kernel context there yet. Both ports say so by name in their own self-tests
rather than passing. RISC-V's idle loop still masks its local timer around
`xaios_thread_run_pending`, because a user thread there runs nested inside the
joiner's syscall with its continuation on that CPU's stack.

This is recorded here because `OD-011`'s timer option and the `B-129` objective
rest on it, and because a reader comparing the three architectures would
otherwise conclude that the shared scheduler running on all of them means the
same execution model on all of them. `B-132` carries the rest: the same proof on
the other two ports, each with its own kernel context.

**A RISC-V machine now boots an XAIOS-installed disk, and getting there took
four faults to find one cause.** The installed-disk gate for this architecture
had never run -- it could not build its own disk (`B-103`) -- and once it could,
every boot died somewhere different. Two of those were fixed on their own terms
and neither was the fault: a five-second join that was really measuring how many
harts the machine had, and a window around user entry where a trap is misread
because the kernel's stack address is parked in `sscratch` while the kernel is
still running.

**The fault was the stacks.** A thread that runs on any hart other than the boot
hart takes its whole syscall chain on that hart's kernel stack, and those were
**16 KiB with no guard page under them** -- while the boot hart's stack is
256 KiB with a page unmapped beneath it, a size the kernel had already raised
once because its deepest chain, an installer walking a FAT directory from inside
a syscall, overflowed 64 KiB and quietly overwrote a per-CPU table. The nested
user-thread run that this port's scheduler borrows the CPU for multiplies the
depth, so the deepest chain in the kernel was running on a quarter of a size
already known to be too small, with nothing underneath it to hit. What that
looks like from outside is a frame holding a garbage stack pointer and execution
arriving in non-executable memory -- and it looks like a different fault every
time anything nearby changes, because which hart runs the chain and how deep the
nesting goes are both races.

The secondary stacks now get what the boot stack gets: the same size, and a
guard page each that the MMU leaves unmapped, so the next overflow is a page
fault at an address that names itself. The installed-disk gate passes, twice in
a row, both boots green on both runs.

**Installation is no longer missing either, and it was missing for a reason
worth stating.** The storage-administration window -- the disk an operator
installs onto -- used to be addressed by a device's *position in the test
bench's device order*: logical slot 5 became PCI ordinal 4, the fifth disk of
the five the bench attaches. A machine with two disks could not open its spare,
so the install phase of the x86-64 and RISC-V gates could only be skipped, and
on a real two-disk machine installing was not merely unproven but impossible.

The window is now the configured one if the machine has it, and otherwise **the
first block device nothing else has taken** -- which on a machine with a spare
is the spare, whatever order the firmware enumerated the bus in, and on a
machine with one disk is nothing, so the caller is told there is no spare rather
than being handed the wrong disk. A device's name is a name and not a position:
the spare is called `/dev/vblk5` wherever it was found, which is what makes the
install path the same on every machine. The fallback needed the driver to start
recording which devices it had taken, because opening one twice is not refused
and would have had two queues fighting over one device.

All three architectures now install: the x86-64 gate passes all four phases
including *the disk XAIOS wrote booting on its own with an SSH server*, AArch64
still passes all four, and RISC-V runs the install phase where it used to skip
it.

## Platform and hardware

- AArch64 QEMU provides the broadest complete OS-service path. QEMU validates
  behavior, not physical ARM performance, firmware behavior, or scaling.
- VMware Fusion on Apple Silicon has a qualified four-vCPU ARM64 profile with a
  generated compatibility stage, PCI-discovered E1000E DHCP, AHCI xaibootFS,
  public-key SSH/SFTP, recovery, reboot, clean shutdown and repeat-boot
  evidence. Four vCPUs come online (`F-01`), VMXNET3 carries traffic end to
  end (`F-02`), a bridged guest configures and answers on a globally routable
  IPv6 address (`F-03`), and snapshot/resume semantics are gated -- though the
  qualified profile stays on E1000E by choice. Outbound SSH and SCP from the
  guest, and `direct-tcpip` forwarding through it, are gated by
  `make vmware-fusion-outbound-gate`. Live DNSSEC interoperability and physical
  qualification remain open.
- Apple Virtualization.framework runs XAIOS to a login with storage and
  dual-stack networking. `make vz-gate` checks that boot at four vCPUs and
  `make vz-stress-gate` soaks it at eight, and `make vz-framebuffer-gate` reads
  the guest's display back off the host, but all three need macOS on Apple
  Silicon and a signed harness, so none of them runs in CI and none is
  qualification evidence. Its firmware describes no GIC ITS, so
  message-signalled interrupts cannot be delivered and every virtio queue runs
  polled; its GOP is `PixelBltOnly`, so firmware leaves no linear
  framebuffer, and the kernel drives the virtio-GPU directly to get one; and it presents no PL011. Its router advertises
  a unique-local IPv6 prefix, so the address configured there is unique-local
  rather than globally routable. What the framebuffer gate is not is a physical
  monitor: it captures a virtual display on one Mac through ScreenCaptureKit,
  which also requires Screen Recording to have been granted to the launching
  application, since the permission is cached per process at launch.
- A guest on Apple Virtualization.framework is reachable from the host only over
  vmnet, and then in one direction at a time. The NAT attachment carries
  guest-initiated traffic but delivers no host-initiated frame, so sshd listens
  there without being reachable. `platform/virtualization-framework/vmnet-helper.c`,
  built as `build/vz/vmnet-helper` by `make vmnet-helper`, fixes that at the cost
  of a privileged helper and a choice: its host mode carries host/guest traffic
  but reaches no further, its shared mode reaches the internet but carries only
  what the guest starts. Bridging, which would do both, needs the
  `com.apple.vm.networking` entitlement Apple issues only with a provisioning
  profile.
- MSI-X for virtio on PCI is implemented against the GIC ITS and is exercised by
  no ARM target available here: Virtualization.framework has no ITS, and QEMU's
  ARM `virt` machine puts virtio on MMIO, where interrupts arrive through the
  distributor. That path is unverified until it meets ARM PCIe hardware. The
  claim is narrower than it used to be rather than gone: on RISC-V's
  `virt,aia=aplic-imsic` board the same shared MSI-X code is driven by an
  IMSIC and is exercised, and `make qemu-riscv64-aia-gate` requires a virtio
  device's first message to actually arrive rather than merely to have been
  configured. What that does not do is test the ITS, which is six hundred
  lines this board has no equivalent of.
- The x86_64 QEMU image executes the complete common process/thread, filesystem,
  networking, SSH/SFTP, control, security, AI Cell and telemetry service set.
  Modern PCI VirtIO block/network and emulated NVMe pass focused correctness
  gates. The platform matrix reaches 256 vCPUs with x2APIC.
- Physical x86 firmware, interrupt routing, NIC, NVMe durability, NUMA locality,
  AVX2/AVX-512/VNNI/AMX state, security exposure and performance remain
  unvalidated. QEMU parity is not a physical support claim.
- Physical Apple, Intel desktop, Xeon, SMMU/IOMMU, NVMe, NIC, NUMA, many-core,
  thermal, power, and performance evidence is not present.
- The macOS TCG/EDK2 harness permits at most two nonfatal startup retries and
  saves each failed serial log. Guest panic/assertion markers are never retried.
  This is emulator robustness handling, not physical boot evidence.

## Networking and SSH

- Networking drives every virtqueue pair a device offers. The driver negotiates
  `VIRTIO_NET_F_MQ`, allocates each advertised pair at its own queue indices,
  posts receive buffers on all of them, polls them round-robin so a busy pair
  cannot starve the others, and only then sends
  `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` -- that order is not cosmetic, since a
  device told to use four pairs delivers on four immediately and the command
  sent before the buffers exist drops every frame landing on a queue nobody
  reads. Transmit fans out by CPU rather than by cursor, `smp_cpu_id() %
  active_pairs` chosen before the lock is taken, because the point of a second
  transmit queue is that two CPUs sending at once do not queue behind one lock.
  `VIRTIO_NET_F_RSS` is negotiated too, with all six four-tuple hash types, a
  sixteen-entry indirection table and a fixed forty-byte key. What this rests
  on is one four-queue tap on one Debian host under TCG: SLIRP is single-queue
  and macOS has no tap device, so every gate that runs on the default network
  cannot tell a driver servicing four pairs from one servicing one, and the
  measured distribution across pairs is correctness evidence carrying no
  throughput claim.
- FreeBSD 15.1, native macOS, and Debian 13 OpenSSH clients pass bounded QEMU
  interoperability suites. This is not a production Internet deployment or an
  independent security audit.
- The normal QEMU boot requires the interface to hold a usable IPv4 address
  before SSH binds. It probes no external DNS name and no external TCP
  endpoint, so SSH availability does not depend on a third party -- and
  equally, nothing about that check proves the machine can reach anything.
  Failure reports a numeric startup error. A local shell is available after
  PBKDF2 authentication in the default development image (`admin` / `xaios`,
  or the six-digit console PIN `012345`); key-only and release consoles stay
  locked. The PIN is console-only and never accepted over SSH. Its search
  space is 10^6, so it is protected only by a 60-second lockout after five
  consecutive failures; it is a development convenience and is not a
  production-strength credential.
- The SSH service deliberately supports 32 transports and two active channels
  per transport, backed by 64 asynchronous child-channel records. Fleet-scale
  identity, audit, replay, and connection policy remains unresolved.
- SSH prefers hybrid `mlkem768x25519-sha256` with classical
  `curve25519-sha256` fallback. Known-answer and OpenSSH interoperability gates
  pass; independent cryptographic, downgrade-policy, side-channel and physical
  deployment review remain open.
- The dedicated outbound SSH/SCP process supports password, Ed25519 identity
  file and forwarded-agent authentication, encrypted OpenSSH keys, persistent
  Ed25519 TOFU, IPv4/IPv6 literals, DNS A/AAAA results, and one
  password-authenticated `-J user@host[:port]` jump host with a separately
  authenticated target. Multi-hop `-J`, `ProxyCommand`, `-J` agent
  authentication, and the complete OpenSSH matrix are not provided.
- DNS performs asynchronous A/AAAA resolution with timeout, retry, bounded TTL
  cache, and DNS-over-TCP fallback. It locally validates DNSKEY, DS, and RRSIG
  chains from compiled root DS anchors and accepts signed exact-owner NSEC NODATA proofs.
  It also resolves names under an unsigned delegation, proving the absent DS
  from a signed NSEC3 the parent serves, including the opt-out form, and then
  accepting the unsigned answer as insecure rather than refusing it as bogus.
  Insecure answers are counted separately from authenticated ones, because
  they carry a weaker guarantee. NSEC3 iteration counts above 150 are refused
  rather than computed. NXDOMAIN, CNAME/DNAME and wildcard synthesis, plus
  production root-anchor rollover/update policy, remain unsupported and fail
  closed.
- The SNTP client validates request binding, server mode/version, stratum, and
  bounded retry/timeout behavior, then applies corrections through a monotonic
  500-ppm slew after initial calibration. Boot performs one bounded, non-fatal
  synchronization against a fixed server address before services start, and an
  offset from an unset clock is stepped rather than slewed. QEMU's PL031 RTC may
  report epoch zero, and public UDP/123 may be filtered; a filtered port leaves
  boot on the RTC reading after a bounded pause, so both conditions remain
  explicit.
  Production NTP authentication, source policy, oscillator characterization,
  and physical RTC qualification remain open.
- TCP implements retained segments, cumulative and partial ACK handling,
  RTT/RTO backoff, SACK, fast retransmit, zero-window handling, bounded
  reordering, keepalive, and FIN bookkeeping. Repeated-loss physical-network
  soak and congestion-control tuning remain unverified.
- Bounded IPv4/IPv6 reassembly and source fragmentation pass maximum-size UDP
  echo under dual-client load and focused QEMU gates on all three
  architectures.
  Deterministic and coverage-guided sanitizer campaigns plus packet-fault and
  recovery gates pass; physical lossy-link behavior remains.

## Storage and persistence

- Power-loss behaviour is covered in three ways, and one of them is now a
  device that really loses writes. The crash gate kills the emulator
  mid-ingest, and constructs two states directly because a kill almost never
  lands on either: a superblock caught half-written, and a superblock that is
  whole while the catalog it points at was never written -- the state a
  volatile write cache leaves behind. Both must be rejected by the slot's own
  hash, with the volume coming back from the other slot a commit older. The
  ordering gate separately requires a flush between the catalog and the
  superblock that publishes it. Neither of those provokes the loss; the
  emulator does not lose an acknowledged write by being killed, and the premise
  that a cache mode could make it do so is wrong. `cache=unsafe` and
  `cache.no-flush=on` only make flushes no-ops -- a write QEMU has
  acknowledged already reached the host through `pwrite`, and killing QEMU
  does not take the host's page cache with it. `make qemu-write-cache-probe`
  is that measured rather than asserted, on the same block layer with
  `qemu-io`, and kept runnable so the claim can be rechecked against a future
  QEMU. `make qemu-power-loss-gate` closes the loop a different way: the models
  volume is attached through QEMU's `blklogwrites` filter, which passes every
  request through and records header, payload and flush markers in issue
  order, and `tools/xaios_write_log.py` replays the recording honouring the one
  promise a volatile cache makes -- everything before the last completed flush
  is durable, everything since survived or did not, independently. Every byte
  it replays is a byte the guest wrote. What remains open is physical
  controller-cache behaviour on real hardware, which no emulator settles.
- VirtIO block/network use interrupt-assisted completions, indirect
  descriptors, and bounded queued work. The x86 block gate records whether
  the post-reset completion arrived through MSI-X and otherwise verifies the
  bounded polling fallback. Repeated block MSI-X delivery after a device reset
  is not claimed from QEMU. Emulated NVMe covers focused
  identify/write/flush/read and backing-byte checks.
- AArch64 and x86_64 QEMU negotiate four NVMe I/O queues and pass four-page PRP
  and SGL 16 KiB write/read/flush operations with async submission, direct
  aligned buffers, cancellation, malformed-completion rejection, queue
  affinity, and host backing-byte verification. Every queue must deliver its
  canary through APIC/MSI-X on x86_64 or GICv3 ITS LPIs on AArch64. RISC-V
  negotiates one queue -- the driver asks for one per online CPU and the
  secondary harts are still at the scheduler rendezvous when NVMe initialises
  -- and runs the same gate on both of its boards, polled on the PLIC one and
  delivered by an IMSIC message on `virt,aia=aplic-imsic`. Physical
  durability, discard behavior, and throughput remain open.
- xaiFS supports signed registration, resumable staging, verification,
  immutable activation, scrub/quarantine, cleanup/reuse, and free-only trim
  under hosted and QEMU tests.
- Offline trusted-replica repair is implemented for a selected unmounted
  xaiFS partition with exact signed package identity and full payload
  verification. Production signing/key custody, replica enrollment, physical
  multi-terabyte transfer, and model-v2 execution admission are not complete.
- xaiFS activation and xaibootFS audit persistence are separate durability
  domains. A post-publication audit failure cannot roll back an already
  published active generation.
- xaibootFS keeps two metadata copies and alternates writes between them,
  so a write interrupted by power loss damages only the copy that is not
  currently authoritative and mount falls back to the survivor. The mirror
  sits past the data region, so volumes written before it keep mounting, and
  a volume with no room for it operates single-copy. When both copies are
  damaged the mount still refuses rather than formatting, because falling
  back is a recovery and not a licence to discard data. Host tests damage
  each copy in turn and require the volume to mount with contents intact.
- xaibootFS v6 is intentionally bounded to 1024 nodes, 256 open handles and
  1 GiB of data space, and a device too small for it is still formatted v5 at
  256 nodes and 4 MiB. Either way the file read/write API stages a whole file
  in one buffer and so refuses a write past 256 KiB, below what the format
  itself allows. Interactive `nano` is further bounded to a
  32 KiB editing buffer. This is suitable for OS state and small user files,
  not general bulk storage or model weights.
- Tar/ZIP exchange is bounded by that 256 KiB file limit. Tar extraction accepts
  ustar, PAX paths, GNU long names and one gzip member; ZIP accepts stored and
  Deflate entries. Symlinks, device nodes, encrypted ZIP, ZIP64, multi-member
  gzip and gzip creation are explicitly unsupported.

## Administration and security

- `xaios.control.v1` operations are bounded to 16 active keys, 16 revoked
  fingerprints, 64 audit/replay records, and 16 shell contexts. These are
  implementation limits, not fleet-scale targets.
- Role, capability, replay, rollback, host-key rotation, sensitive-path denial,
  and secret-redaction behavior pass QEMU/OpenSSH gates but have not received an
  independent production security review.
- `xapt` supports TLS 1.2, validating the certificate chain against compiled-in
  ISRG roots with server-name and validity checks, or an exact RSA public-key
  pin for a private origin. Chain validation depends on the realtime clock set
  during boot and refuses an unset one. The shipped configuration currently
  sets `tls=off` and fetches over plain HTTP; signed catalogs and per-artifact
  hashes remain the authenticity layer, and transport confidentiality is
  forfeited until TLS is restored. It supports signed
  release-root rotation, revocation, offline recovery, and rollback of an
  interrupted trust/catalog activation. The checked-in TLS and signing private
  fixtures are public; production key custody and release authorization remain
  unresolved. Transfer encoding, compression, proxies, mirrors, deltas,
  dependencies, and unattended updates are not supported.
- External applications are bounded to 256 KiB by the current xaibootFS/app
  loader, and only one previous version is retained. Shipped applications,
  including `xapt`, `nano`, `xtop`, and `pong`, are standalone ELFs; publishing
  them as independently upgradable repository packages still requires signed
  package manifests and architecture-specific payloads.
- QEMU verifies persistent clean/unclean lifecycle records, rescue selection,
  reset/poweroff dispatch, and block flush completion. It cannot establish
  physical power-loss durability or platform reset correctness. Thermal and PMU
  support reports remain explicitly unavailable until physical backends exist.

## Inference engine and model support

- The kernel model-v1 path is a deterministic fixture. It does not execute a
  transformer and must not be described as real inference.
- Model-v2 parsing, streaming writing, architecture/backend registries,
  immutable readers, sessions, and scalar packed kernels are foundations only.
  Model-v2 packages are not yet executed end to end.
- No official tokenizer importer, real Qwen tensor importer, transformer plan,
  logits parity, or deterministic 32-token decode parity exists.
- Qwen 3.8 is the next active correctness workstream now that the declared
  QEMU platform gate passes. Kimi K3 and DeepSeek V4 Flash 0731 remain later
  roadmap targets.
- A miniature Kimi K3 reference covers reduced KDA recurrence, causal Gated
  MLA, exact top-16 routing across 20 experts, shared-expert reduction, SiTU,
  and one native MXFP4 block. AttnRes, production dimensions, tokenizer/text
  parity, real checkpoints, and multimodal execution are not implemented.
- Scalar INT4/INT6 and experimental NEON/AVX2 packed kernels pass bounded
  correctness tests. An SVE2 arithmetic canary and per-task Z/P/FFR context
  preservation pass under QEMU, but an SVE inference backend does not exist.
  Physical AVX2 validation,
  AVX-512/VNNI, AMX, SVE,
  tiled prefill/verification, persistent worker gangs, and bandwidth autotuning
  remain incomplete.
- No complete model-executing native macOS process, Metal backend, physical
  model-parity run, or immutable performance artifact exists. The cluster data
  plane is no longer on that list: sealed frames cross a real network between
  XAIOS guests, membership is decided from heartbeats that actually arrived,
  and two-node, three-node and partition gates run it between independent
  machines. What is still missing above it is distributed activation
  *execution*, which waits on real local inference rather than on transport.

## Evidence policy

Sparse files above 4 GiB or 100 GiB prove address width and bounded-memory
behavior, not physical transfer throughput. High-vCPU QEMU gates prove dynamic
metadata capacity, not server scalability. Performance claims require physical
artifacts satisfying `docs/BENCHMARK-CONTRACT.md`.

See [[Project Tracker|Project-Tracker]].
