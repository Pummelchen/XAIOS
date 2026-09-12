ENTRY(_start)

SECTIONS
{
  . = 0x3fc0000000;

  . = ALIGN(0x1000);
  .text : {
    KEEP(*(.text.start))
    *(.text .text.* .ltext .ltext.*)
  }

  . = ALIGN(0x1000);
  .rodata : {
    *(.rodata .rodata.* .lrodata .lrodata.*)
    *(.srodata .srodata.*)
    *(.eh_frame_hdr)
    *(.eh_frame .eh_frame.*)
    *(.gcc_except_table .gcc_except_table.*)
  }

  . = ALIGN(0x1000);
  .data : {
    *(.got .got.*)
    __preinit_array_start = .;
    __bothinit_array_start = .;
    KEEP(*(.preinit_array))
    __preinit_array_end = .;
    __init_array_start = .;
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array .init_array_*))
    __init_array_end = .;
    __bothinit_array_end = .;
    __fini_array_start = .;
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array .fini_array_*))
    __fini_array_end = .;
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

  . = ALIGN(0x1000);
  .bss (NOLOAD) : {
    *(.bss .bss.* .lbss .lbss.* COMMON)
    *(.sbss .sbss.*)
  }

  /DISCARD/ : { *(.comment .note .note.*) }
}

ASSERT(. < 0x7fd0000000, "Hosted userspace image exceeds the 16 MiB code/data window")
