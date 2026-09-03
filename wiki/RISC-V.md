# RISC-V (rv64gc)

**Status: boots as an operating system on one emulated board, and nowhere
else.** XAIOS runs the same shared kernel on RISC-V that it runs on AArch64
and x86_64. On the QEMU `virt` board it boots to the first-run setup prompt
across four harts with 75 self-tests passing and no errors. It has never been
run on RISC-V hardware or on a RISC-V hypervisor, so nothing here supports a
claim about firmware behaviour, timing, or scaling on a real machine.

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

**The timer has no acknowledge.** A pending supervisor timer interrupt is
cleared by writing a new comparator and by nothing else, so the rearm path
always reprograms even when no period is set.

**There is no memory-type field in a page table entry.** Device versus normal
memory follows the physical address on RISC-V, so the kernel records the
device attribute in the two bits the specification reserves for software --
which keeps its own bookkeeping honest without claiming the hardware enforces
anything it does not.

## What is missing

- **Hardware qualification of any kind.** One emulated board is the whole
  evidence.
- **Inter-processor interrupts.** Nothing in the shared kernel signals a CPU
  when it queues work for it, so secondary harts spin rather than sleep.
- **A narrower user-access window.** `sstatus.SUM` is set for the whole
  kernel rather than only around the syscall path, so a stray kernel
  dereference of a user pointer is not caught by hardware here.
- **`xapt` and the C99 libc**, which have not been built for this
  architecture.
- **A boot medium.** It boots via OpenSBI rather than UEFI, so it is not part
  of any released image.
- **A real-time clock.** Wall time advances from an unknown epoch.

## Building and running

```
scripts/build-riscv64.sh          # the kernel
scripts/build-riscv64-image.sh    # the initial filesystem and its applications
make qemu-riscv64-gate            # both, then boot and check what ran
```

The gate runs with four harts deliberately, so every run draws a different
boot hart. It reads QEMU's serial output through a file sink rather than a
pipe: QEMU block-buffers its console when stdout is redirected and drops the
buffer when it is killed, which makes a timed-out run read back as a kernel
that printed nothing at all.

See also [[Hardware Support|Hardware-Support]] and
[[Testing XAIOS|Testing-XAIOS]].
