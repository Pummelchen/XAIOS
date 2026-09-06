/* RISC-V rv64gc, QEMU `virt`.
 *
 * 0x80200000 is not a choice. QEMU's virt board puts RAM at 0x80000000 and
 * loads OpenSBI there; OpenSBI occupies the first two mebibytes and hands
 * control to whatever sits directly above it. Linking anywhere else means
 * the firmware jumps into the middle of nothing.
 *
 * Fixed rather than position-independent, unlike the AArch64 kernel. That
 * kernel is relocatable because UEFI firmware chooses where to put it and
 * the address varies per machine; here the address is the ABI between
 * OpenSBI and the kernel, so there is nothing to relocate to. B-19 is the
 * reason that distinction is stated rather than assumed: a kernel whose
 * placement is decided elsewhere has to say so.
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
  . = 0x80200000;
  __kernel_start = .;

  __text_start = .;
  .text : ALIGN(0x1000) {
    *(.text.entry)
    *(.text .text.*)
  }
  . = ALIGN(0x1000);
  __text_end = .;

  __rodata_start = .;
  .rodata : ALIGN(0x1000) {
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
  }
  . = ALIGN(0x1000);
  __rodata_end = .;

  .data : ALIGN(0x1000) {
    *(.data .data.*)
    *(.sdata .sdata.*)
  }

  .bss : ALIGN(0x1000) {
    __bss_start = .;
    *(.sbss .sbss.*)
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(16);
    __bss_end = .;

    /* The boot stack, inside .bss rather than after it.
     *
     * It sat outside every output section, which made it a range no program
     * header covered: the ELF's last LOAD segment ended at __bss_end and the
     * stack lived past it. Anything that computes the kernel's extent from
     * the program headers -- which is what the UEFI loader does, and what it
     * puts in kernel_phys_end -- therefore did not know the stack existed,
     * and the page allocator, which excludes exactly that range, handed the
     * kernel's own stack out as free memory. The heap got it and a memset
     * wrote over the frame it was running on, which presented as a loop that
     * restarted forever with no fault and no message.
     *
     * AArch64 has always placed its stack inside .bss for this reason. Being
     * in a NOBITS section costs nothing in the file; it only makes the
     * section's memory size tell the truth.
     *
     * __bss_end stays below it deliberately, so the entry code's zeroing loop
     * still skips the stack rather than clearing 64 KiB nothing has used. */
    /* A page below the stack that nothing may touch.
     *
     * The stack grows down from __stack_top, and what lies below
     * __stack_bottom is the tail of .bss -- the last few statics the linker
     * happened to place there. An overflow therefore did not fault; it
     * quietly overwrote them. The casualty was whatever came last, which was
     * the per-CPU current-process table in kernel/user/user.c: a running
     * program lost its binding, every later syscall was refused for a
     * capability it had, and nothing connected that to the disk install whose
     * call chain had done it. Found by printing the table and seeing
     * capacity=0 on a machine that had logged "process table for 4 cpus,
     * storage=allocated" at boot.
     *
     * vmm_init unmaps this page once paging is on, so the next overflow is a
     * page fault at a named address instead of a corruption that surfaces
     * somewhere else entirely. */
    . = ALIGN(0x1000);
    __stack_guard = .;
    . += 0x1000;

    /* And more of it. Sixty-four kilobytes was enough for every path this
       kernel took until an installer walked a FAT directory from inside a
       syscall from inside osctl; the deepest chain here is storage, and it is
       deeper than anything AArch64 reaches because that architecture is
       handed a stack by firmware rather than carving its own. Two hundred and
       fifty-six with a guard below it is headroom that announces itself when
       it runs out. */
    . = ALIGN(0x1000);
    __stack_bottom = .;
    . += 0x40000;
    __stack_top = .;
  }

  . = ALIGN(0x1000);
  __kernel_end = .;

  /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame) }
}
