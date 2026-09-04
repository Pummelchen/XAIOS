# RISC-V (rv64gc)

**Status: functional parity on one emulated board, and nowhere else.** XAIOS
runs the same shared kernel on RISC-V that it runs on AArch64 and x86_64. On
the QEMU `virt` board it boots to 100% across four harts with 81 self-tests
and no errors, offers a login prompt, and runs an SSH server that answers:
logging in returns the machine's real service state and filesystem. It has
never been run on RISC-V hardware or on a RISC-V hypervisor, so nothing here
supports a claim about firmware behaviour, timing, or scaling on a real
machine.

Progress status and ownership live only in
[[Project Tracker|Project-Tracker]].

## What runs

- **Sv48 paging**, not Sv39: `XAIOS_USER_BASE` is at 512 GiB, past what Sv39
  can address. The kernel image is mapped one section at a time -- `.text`
  read and execute, `.rodata` read-only, `.data` read and write -- in 4 KiB
  pages, because a 2 MiB leaf spanning the boundary between two sections would
  have to be granted the union of their permissions.
- **Traps and system calls** over a frame of all thirty-one registers plus
  `sepc`, `scause`, `stval` and `sstatus`. `sscratch` holds the kernel stack
  while a thread is in user mode and zero while the kernel runs, so one swap
  both distinguishes the two cases and lands on the right stack. System calls
  arrive by `ecall` with the number in `a7`.
- **PLIC** interrupts, found by compatible string rather than by node name.
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

## The hosted C99 library

picolibc, compiler-rt's quad-precision builtins and the XAIOS runtime all
build for riscv64, and the symbol probe force-links all 464 mandatory ISO C99
functions with nothing unresolved. The kernel runs the termination probes
during boot: the runtime smoke test and the void-main form exit zero, the exit
probe returns 23 and the abort probe 134.

Two things this needed that the other architectures did not. picolibc has to
be built with `-mcmodel=medany`, because userspace links at `0x7fc0000000` and
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
- **Interrupt-driven virtio.** The interrupt each MMIO slot is wired to is
  read from the device tree now -- the PLIC numbers them from 1 where the
  compiled-in default was AArch64's 48 -- but the drivers still poll. Setting
  the base does make them take interrupts, and then the shared asynchronous
  queue self-test fails: it submits a full queue and asserts every request is
  still outstanding and that one more is refused, and neither holds once the
  device can complete during submission. Making that test independent of the
  completion model is shared work on two architectures qualified on hardware
  that cannot be re-qualified from here.
- **An IOMMU.** So has x86_64, whose `smmu_initialized()` also reports zero;
  this is an AArch64 capability rather than something RISC-V is behind the
  other two on.
- **Message-signalled interrupts.** The PLIC takes wires, not messages. The
  board can present AIA, and a driver for it is real work that nothing
  currently needs -- virtio reaches the kernel over wired interrupts.

## Test coverage

Three gates, against roughly seventy for the other two:

| Gate | What it proves |
| --- | --- |
| `make qemu-riscv64-gate` | The kernel boots to a login prompt with sshd listening, 81 self-tests, no errors. |
| `make qemu-riscv64-boot-media-gate` | The same machine boots from its own disk through EDK2 with no `-kernel`, from the verified signed A/B system slot. |
| `make qemu-riscv64-matrix-gate` | It boots at 1, 2, 4 and 8 harts, four independent times, and answers an SSH login each time. |

That is far short of what AArch64 and x86_64 are held to -- network suites,
storage crash safety, write ordering, soak, NUMA, NVMe, cluster and fault
injection all run on those and not here. The features are present; the
evidence that they hold under stress is not.
