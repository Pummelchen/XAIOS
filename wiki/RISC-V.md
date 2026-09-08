# RISC-V (rv64gc)

**Status: functional parity on one emulated board, and nowhere else.** XAIOS
runs the same shared kernel on RISC-V that it runs on AArch64 and x86_64. On
the QEMU `virt` board it boots to 100% across four harts with 87 self-tests
and no errors, offers a login prompt, and runs an SSH server that answers:
logging in returns the machine's real service state and filesystem. It has
never been run on RISC-V hardware or on a RISC-V hypervisor, so nothing here
supports a claim about firmware behaviour, timing, or scaling on a real
machine.

Progress status and ownership live only in
[[Project Tracker|Project-Tracker]].

## What runs

- **Sv48 paging where the hart has it and Sv39 where it does not**, chosen at
  run time rather than demanded. This used to be Sv48 only, and panicked on a
  hart that refused it, because `XAIOS_USER_BASE` sat at 511 GiB -- not a
  representable Sv39 address, since a 39-bit space reaches 256 GiB and
  anything above it sign-extends somewhere else entirely. The window is at
  255 GiB now, which both modes can address. Six of the thirteen CPU models
  QEMU implements offer Sv39 and nothing more -- `rva22s64` and `rva23s64`
  among them, the profiles real silicon is certified against -- so the old
  constant was excluding most of the family for no reason anything needed.
  The two modes are not two sets of tables:
  `index_at` is the same arithmetic either way, so Sv48's level-2 table under
  root slot 0 *is* Sv39's root table, and selecting Sv39 is entering the
  structure one level lower rather than building a second one. The kernel
  image is still mapped one section at a time -- `.text` read and execute,
  `.rodata` read-only, `.data` read and write -- in 4 KiB pages, because a
  2 MiB leaf spanning the boundary between two sections would have to be
  granted the union of their permissions.
- **2 MiB and 1 GiB leaves**, in whichever of the two modes the hart gave us,
  which is not the same test twice: a 1 GiB leaf is a level-2 entry, and that
  is an entry one step below the root under Sv48 and an entry in the root
  itself under Sv39, so the Sv48 boots alone would never have covered it.
  Each leaf is dereferenced through an alias of memory the kernel owns, so
  the hardware's own walker witnesses the mapping and not only the kernel's
  bookkeeping.
- **Remote TLB shootdown** through SBI's RFENCE extension. `sfence.vma` is
  hart-local by definition, so a kernel mapping withdrawn on one hart stayed
  live in every other hart's TLB until this existed; the unmap and remap paths
  now issue `REMOTE_SFENCE_VMA` with the hart mask built from firmware's hart
  ids rather than from the kernel's CPU numbers, because those are not the
  same sequence on every boot.
- **Traps and system calls** over a frame of all thirty-one registers plus
  `sepc`, `scause`, `stval` and `sstatus`. `sscratch` holds the kernel stack
  while a thread is in user mode and zero while the kernel runs, so one swap
  both distinguishes the two cases and lands on the right stack. System calls
  arrive by `ecall` with the number in `a7`.
- **PLIC** interrupts, found by compatible string rather than by node name,
  on QEMU's default `virt` board.
- **APLIC and IMSIC** -- the Advanced Interrupt Architecture -- on
  `-machine virt,aia=aplic-imsic`, which is the same kernel image selecting a
  different controller at run time from the device tree. The IMSIC receives
  messages and the APLIC, programmed in MSI delivery mode, translates wired
  devices onto the same path, so PCI and virtio-mmio both arrive as messages
  and NVMe reports `controller=aia-imsic`. Both controllers are found by what
  they are attached to -- the supervisor IMSIC is the one whose
  `interrupts-extended` names cause 9 -- never by address and never by
  position, because a board with AIA publishes machine-mode counterparts with
  identical compatible strings and programming firmware's controller is
  accepted silently and delivers nothing.
- **PCI** enumerated through ECAM, with base addresses assigned by the kernel.
- **virtio** block and network devices over the modern PCI transport.
- **The filesystem, IPv6 and userspace**, unchanged from the shared kernel.
- **Four harts**, brought up through SBI's hart state management extension.
- **Both virtio transports.** The boot volume arrives over MMIO at the window
  read from the device tree, and the model volume over the other. QEMU's
  virtio-mmio transports default to the legacy interface, which the driver
  refuses, so `-global virtio-mmio.force-legacy=false` is required -- without
  it every MMIO slot reads as empty and the model volume is simply absent.
- **A login prompt and sshd**, with the terminal applications sshd hosts.
- **A real-time clock**, so timestamps start from the actual Unix epoch.

## What this architecture required that no other did

**Firmware assigns no PCI base addresses.** Every other machine XAIOS runs on
boots through firmware that assigns them -- UEFI does, and so does the
firmware inside a hypervisor. A board that boots straight from an SBI
implementation has no such stage, and its devices arrive present, enumerable,
correctly identified and unreachable, every base address still zero. The
kernel assigns them from the windows the host bridge's `ranges` declares,
touching only addresses firmware left empty.

**Firmware does not always hand over on hart 0.** OpenSBI picks whichever hart
wins its own internal race; on this board it has been observed as 0, 1, 2 and
3 across consecutive runs of an identical command. `_start` draws a lottery
rather than assuming, and the harts that lose stop themselves through SBI so
they can be started properly later.

**Hart id is not CPU number.** Firmware numbers harts however it likes. The
hart id is hardware identity and lives in a table used for SBI calls; the CPU
number is the kernel's own index and starts at zero on whichever hart won.

**The real-time clock latches.** The Goldfish RTC's two registers must be
read low half first, because the low half latches the high one. Reading the
other way round is correct except across a rollover of the low word -- a bug
that appears once every four seconds and never in a test.

**The boot stack has to be inside a section.** It sat after `.bss`, outside
every output section, so no program header covered it -- and anything that
computes the kernel's extent from the program headers, which is what the UEFI
loader does, did not know it existed. The page allocator excludes exactly that
range, so it handed the kernel's own stack out as free memory, the heap got
it, and a memset wrote over the frame it was running on. It presented as a
loop that restarted forever with no fault and no message. AArch64 had always
placed its stack inside `.bss`; RISC-V was the odd one out.

**The timer has no acknowledge.** A pending supervisor timer interrupt is
cleared by writing a new comparator and by nothing else, so the rearm path
always reprograms even when no period is set.

**There is no memory-type field in a page table entry.** Device versus normal
memory follows the physical address on RISC-V, so the kernel records the
device attribute in the two bits the specification reserves for software --
which keeps its own bookkeeping honest without claiming the hardware enforces
anything it does not.

### What the release configuration found

Every RISC-V gate booted the boot-test configuration, where the shell's
commands are built into the kernel and no application is ever launched as a
process. The first time the release configuration ran -- to take a screenshot
of xtop over SSH -- the first on-demand application faulted the kernel, and
three defects came out in a row, each hidden by the last:

- **There were no per-process address spaces.** Every user page went into
  the one shared root, the per-process table list the shared interface hands
  around was allocated and ignored, and switching address spaces was a TLB
  flush. Every process is linked at the same address, so loading a child
  overwrote its parent's mappings and reclaiming it removed them. Sv48 now
  does what x86-64 does: each hart has its own root, its own copy of the
  table under slot zero, and a user directory that switching points at a
  process's leaf tables; the kernel's own mappings stay shared, and a new
  entry at either copied level is mirrored into every hart's copies.
- **The supervisor-user-memory depth counter was one counter for all
  harts.** Four harts interleaving their increments and decrements let one
  hart's inner `end` see zero and clear its own SUM mid-syscall. It only
  bites when a hart nests -- a syscall running a transient child, whose exit
  is the nested window -- which is why every ordinary syscall worked. It is
  per hart now, as `sstatus` is.
- **The idle wait armed nothing.** `timer_idle_until` was `wfi` in a loop,
  which waits for whatever interrupt comes; worker harts keep their timer
  masked by design, so a wait from a syscall on one slept forever. xtop's
  first request is a quarter-second wait. It now arms a one-shot comparator
  at the deadline and enables the timer interrupt around the `wfi`, as
  AArch64 does.

A fourth, smaller one: the per-CPU usage table was sized when only the boot
hart was online, because RISC-V starts its secondaries at the scheduler
rendezvous rather than before the process table exists, so the monitor
reported a four-hart machine as having one CPU. CPUs now register their
record the first time they run a process.

## The hosted C99 library

picolibc, compiler-rt's quad-precision builtins and the XAIOS runtime all
build for riscv64, and the symbol probe force-links all 464 mandatory ISO C99
functions with nothing unresolved. The kernel runs the termination probes
during boot: the runtime smoke test and the void-main form exit zero, the exit
probe returns 23 and the abort probe 134.

Two things this needed that the other architectures did not. picolibc has to
be built with `-mcmodel=medany`, because userspace links at `0x3fc0000000` and
the default code model addresses through `lui`, which reaches only the lowest
and highest two gigabytes. And the quad-precision builtins call two
floating-point mode helpers with no RISC-V implementation -- riscv64 lp64d has
a 128-bit `long double` like AArch64, so it needs the same soft-float set, and
without those two functions the library does not link at all.

`xapt` builds and is packaged, with BearSSL and the libc sysroot it needs.

## The boot medium

`scripts/build-riscv64-boot-media.sh` produces an EFI System Partition with a
loader at the removable-media path and the kernel beside it. Under EDK2 on the
virt board, firmware loads that loader, the loader loads the kernel off the
same disk, exits boot services and starts it.

The loader's container is the part that is genuinely different. UEFI loads
PE/COFF images and LLVM has no RISC-V COFF backend -- `clang --target=
riscv64-unknown-windows` silently produces ELF and `lld-link` cannot link it
-- so `scripts/elf-to-efi.py` wraps a position-independent ELF in a PE
container instead, the way the Linux EFI stub does. `R_RISCV_RELATIVE` and
PE's `DIR64` relocation mean the same thing, with one difference: RELA keeps
the addend in the relocation entry and leaves the target word zero, while PE
adds the delta to whatever the target holds. So the addend is written into the
image and `ImageBase` is zero.

Run it with `-machine virt,acpi=off`. With ACPI on, this EDK2 build publishes
no device tree, and the RISC-V port reads the interrupt controller, the
timebase and the virtio window from one.

`make qemu-riscv64-boot-media-gate` boots the medium under EDK2 with no
`-kernel` at all and requires the whole chain: firmware finds the loader at
the removable-media path, the loader reads the kernel off that same disk, and
the kernel comes up to a login prompt with sshd listening.

## What is missing

- **Hardware qualification of any kind.** One emulated board is the whole
  evidence. AArch64 is qualified on VMware Fusion and x86_64 on a physical
  Intel host; RISC-V has run on QEMU's `virt` and nothing else, so no claim
  about firmware behaviour, timing or scaling on a real machine is supported
  by anything here. This is the difference that matters and no amount of work
  on this machine closes it.
- **Message-signalled interrupts on the default board.** This is now a
  property of the board rather than of the port, which it was not before
  `kernel/arch/riscv64/aia.c` existed. QEMU's plain `virt` publishes a PLIC,
  which carries wires and no messages: MMIO virtio takes wired interrupts
  there -- including the network, since this machine grew a second interface
  on `virtio-mmio-bus.2` and the stack finds that before it falls back to PCI
  -- and the PCI devices poll. NVMe runs its queues on polled completion,
  which is a mode the driver already had rather than a concession: its wait
  path polls the completion queues every turn while waiting.
  `-machine virt,aia=aplic-imsic` is the board that does deliver messages, and
  `make qemu-riscv64-aia-gate` boots the same kernel image on both and
  requires each to say the opposite thing about itself, because either half
  alone can be passed by a broken build -- a kernel that lost its AIA driver
  would still pass a PLIC-only gate, and one that claimed messages
  unconditionally would still pass an AIA-only gate while lying on every other
  RISC-V gate here, all of which run the default board. What it asserts on the
  AIA board is delivery and not configuration, because every driver here can
  also poll: an IMSIC loopback, an APLIC-asserted wire arriving as a message,
  at least one real wired device announcing its first delivery, and an NVMe
  completion arriving with nobody polling the queue. `make qemu-nvme-gate`
  runs both RISC-V boards for the same reason, and holds each to the same
  answers as the other two architectures -- controller ready, identify, async
  round trip, cancellation, scatter-gather, four malformed commands refused,
  and the bytes the guest wrote present on the host's disk -- differing only
  in `msix=0` with the skipped self-test on the PLIC board and `msix=1` with
  `controller=aia-imsic` on the AIA one. What is still refused rather than
  half-driven: `aia=aplic` direct delivery, and multi-group IMSICs.
- **An IOMMU.** There is none on this board -- `smmu_init` says so in one line
  and DMA is unmediated. Nor has x86_64, whose `smmu_initialized()` also reports zero;
  this is an AArch64 capability rather than something RISC-V is behind the
  other two on.
- **A second NVMe queue.** The driver asks for one per online CPU, and on
  this architecture the secondary harts are not online yet when NVMe
  initialises: one queue here, four on the other two. Nothing depends on it,
  and moving hart bring-up ahead of device probing is a boot-order change
  that would need its own evidence.
- **A fourth hart, when booting through UEFI.** EDK2 starts one secondary for
  its own multiprocessor services and leaves it started, and SBI has no way
  to take a running hart back: `sbi_hart_start` answers ALREADY_AVAILABLE and
  the machine comes up with three. Which hart it keeps varies between boots.
  This is visible in every UEFI boot here and costs a core, not correctness --
  and it is what exposed two shared defects that assumed CPU ids run 0,1,2,3
  with no gaps.
- **An accelerated SHA-256.** AArch64 has the crypto extension and x86_64 has
  SHA-NI; rv64gc has neither, so the engine dispatches its scalar backend and
  every hashed read pays for it. `make qemu-riscv64-storage-bench` measures
  the cost rather than leaving it to be guessed at: cold model reads run at
  about 2 MB/s here against 123 MB/s on AArch64, while the block path -- which
  hashes nothing -- is *faster* here, 3.5 GB/s against 1.6. Some of that
  ratio is the emulator rather than the silicon; the shape of it is not.
  Closing it means Zknh, which is not in this profile, or a faster scalar
  core; neither is work anything currently needs.

## Test coverage

Fifty-nine `make` targets, of which fifty-seven are gates, plus legs in the shared unified-image and xapt gates. They fall into
three groups, and the split matters more than the count.

**Gates this architecture has of its own.** These exist because the shared
suite cannot ask these questions, and a third architecture that is only ever
asked the first two's questions is being tested as an imitation of them.

| Gate | What it proves |
| --- | --- |
| `make qemu-riscv64-isa-gate` | Sv48 is live rather than the Sv39 a machine may default to; kernel text is executable and not writable and writable data is not executable, read back from the page tables that enforce it; `fence.i` is accepted; firmware answers a probe for an extension that cannot exist with "no", and hart state management refuses a hart that does not exist -- the two controls that make every other SBI answer mean something. What the machine reports about itself -- SBI version and extensions, whether a misaligned load completes, the PLIC's address -- is printed rather than asserted, because a different board may answer differently without anything being broken. |
| `make qemu-riscv64-gate` | The kernel boots to a login prompt with sshd listening, 87 self-tests, no errors. |
| `make qemu-riscv64-durability-gate` | State written on one boot is read back on the next, and survives a boot killed outright with no shutdown and no flush -- the filesystem reports no checksum errors afterwards. |
| `make qemu-riscv64-boot-media-gate` | The machine boots from its own disk through EDK2 with no `-kernel`, from the verified signed A/B system slot. |
| `make qemu-riscv64-matrix-gate` | It boots at 1, 2, 4 and 8 harts, four independent times, and answers an SSH login each time. |
| `make qemu-riscv64-release-gate` | The release configuration -- what the other architectures ship as `make image` -- logs in over SSH and runs `hello`, `sysinfo` and `xtop` as processes, reports every hart in the monitor, and keeps answering afterwards. The boot-test gates never launch a process: the shell's commands are built into that kernel. |
| `make qemu-riscv64-aia-gate` | One kernel image on both of this architecture's boards, held to opposite answers about interrupts: the PLIC board must say positively that nothing was delivered by message and that the PLIC is what is serving, and the `virt,aia=aplic-imsic` board must show four kinds of arrival -- an IMSIC loopback, an APLIC wire forwarded as a message, a real wired device's first delivery, and an NVMe completion nobody polled for. Separate from the NVMe gate because it also covers the wired half, which NVMe does not touch: an NVMe MSI comes from PCI and never passes through an APLIC. |

**The shared suite, run here.** `make qemu-riscv64-smoke` and the milestone
gates behind it -- `filesystem`, `app-agent`, `network-full`,
`cpu-ai-runtime`, `ai-cell`, `security`, `update` -- plus `process`, `osctl`,
`fault-injection`, `persistence-reboot`, `local-console`, `write-ordering`,
`storage-crash-test`, `crash-safety`, `power-loss`, `framebuffer`,
`keyboard-input`, `routing-prefix`, `storage-bench`,
`instruction-cost`, `dhcpv6`, `outbound-fragmentation`, `model-sftp`,
`boot-loop`, `benchmark`, `preview`, `libc`, `fault-matrix`, `nvme`, `soak`, `parallel-network-load`,
`docker-network-suite`, `xapt`, `console-xtop`, `cluster`, `cluster-two-node`,
`cluster-three-node`, `cluster-partition`,
`cpu-matrix`, `installed-disk`, `netboot`, `setup`, `ssh-session-exhaustion`,
the two FreeBSD suites, and the `userspace`, `network`,
`cpu-ai` and `regression` suites that bundle them. Each is the same script
the other two architectures run, taking `--arch riscv64`, rather than a
RISC-V copy of it: one place decides what a boot is, and one place knows that
this machine's runner reads `XAIOS_RISCV64_*`.

Two of those needed the machine to grow something first, which is worth
naming because it is the difference between porting a gate and pretending to:

- `write-ordering` needed the builder to accept `XAIOS_IO_TRACE` and
  `XAIOS_CRASH_WRITER`, which it did not offer at all. The kernel could
  always do it; there was no way to ask.
- `storage-crash-test` needed the runner to be able to start the machine
  through UEFI. With `-kernel` there is no loader, so nothing has chosen a
  system slot, the guest logs `system-slot: unavailable`, and a power-loss
  test on A/B metadata would have watched a machine that never writes any.
  `XAIOS_RISCV64_BOOT=uefi` is that switch, and the gate's negative control
  is exactly this: the same armed volume booted with `-kernel` reaches no
  crash point.

**What the ports found.** Porting a gate here has repeatedly turned up
something that was missing rather than something that was broken, and the
pattern is worth naming: this architecture's builders and image were written
alongside the port and never revisited against what the other two had grown.
So far that has been the trace and crash-writer switches, the storage
benchmark, the stress applications, the controlled-fault switch, an SSH
account list and an authorized key, the applications that fail on purpose,
and -- found by an external client asking for `stat` over SSH -- the twenty
three file, text and archive utilities, which this image carried none of.

Two were defects rather than omissions, both in the user-fault path and both
invisible until something faulted a user process here on purpose:

- The kernel read the faulting instruction to step over it, from a user
  address, with user access just closed. A process that faulted took the
  kernel down with it. Nothing needs stepping over -- noting the fault ends
  the process -- and AArch64 has always advanced nothing.
- The same path closed the user-access window without putting it back, so
  the syscall that had entered user mode -- sshd running an application on
  someone's behalf -- got its window closed underneath it and faulted on the
  next byte it wrote to its own caller.

**The shipped image, on this architecture.** `make unified-image-gate` boots
the one release ISO on five environments and this is now the third of them.
Getting there found two things. The image build did not build the RISC-V
half at all -- it picked up whatever `build/` happened to hold, which is how
build 5's ISO came to carry a build 4 RISC-V kernel. And the gate attached
the tree's own A/B system volume, which the loader prefers over the kernel on
the medium: every log it had ever produced said "loaded verified A/B system
slot", so it had been proving that the image's *loader* boots and then
running a kernel from `build/`. All three QEMU legs now boot with no system
volume, which is what a first boot on a real machine looks like, and all
three report the fallback path and build 5.

**Still short.** The NUMA gate, which reads SRAT/SLIT/HMAT at two nodes and
then SLIT distances alone at four, is x86_64's alone -- there is no AArch64
one either, so this is a firmware-table gate rather than something RISC-V is
behind the other two on. `make qemu-readonly-medium-gate` and
`make qemu-slaac-gate` are AArch64-only in the same way: each asks a question
about one board's devices or one host network rather than about an
architecture, and neither has been pointed at a second machine. What RISC-V
*is* included in is `make qemu-memory-matrix`, which boots all three
architectures at 1, 2 and 4 GiB and requires each to report managed memory
that rises with what the machine was given.

The boot gates share `tests/scripts/riscv64_gate_lib.py` for booting the machine and
`qemu_gate_lib.py` for comparing markers, rather than each carrying its own
copy of the same thirty lines. Copies of a boot routine drift the way any
other copies do, and the ways they drift -- a timeout generous in one and
tight in another, a kill that terminates politely in one and not the other --
are exactly the ways a gate stops testing what it says it tests.
