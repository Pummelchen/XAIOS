ENTRY(_start)

SECTIONS
{
  . = 0x3fc0000000;

  .text : ALIGN(0x1000) {
    *(.text .text.* .ltext .ltext.*)
  }

  .rodata : ALIGN(0x1000) {
    *(.rodata .rodata.* .lrodata .lrodata.*)
    *(.srodata .srodata.*)
  }

  .data : ALIGN(0x1000) {
    /* RISC-V small data. The kernel's own linker script has collected these
       since the port landed; these two did not, so under a toolchain that
       emits them -- clang 18 does, clang 23 does not -- they were placed as
       orphan sections wherever the linker chose. A hosted C99 application
       built that way reached userspace and then failed its first printf,
       exiting 1 after a single syscall, which the kernel asserts on. It cost
       the RISC-V CI job every run it has ever had. See B-61. */
    *(.data .data.* .ldata .ldata.*)
    *(.sdata .sdata.*)
  }

  .bss : ALIGN(0x1000) {
    *(.bss .bss.* .lbss .lbss.* COMMON)
    *(.sbss .sbss.*)
  }
}

ASSERT(. < 0x7fd0000000, "Userspace image exceeds the 16 MiB code/data window")
