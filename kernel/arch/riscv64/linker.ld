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

  .text : ALIGN(0x1000) {
    *(.text.entry)
    *(.text .text.*)
  }

  .rodata : ALIGN(0x1000) {
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
  }

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
  }

  /* The boot stack lives here rather than in .bss so its address is a
     symbol the entry code can load before any C runs -- there is no stack
     to call a helper on yet. */
  . = ALIGN(0x1000);
  __stack_bottom = .;
  . += 0x10000;
  __stack_top = .;

  __kernel_end = .;

  /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame) }
}
