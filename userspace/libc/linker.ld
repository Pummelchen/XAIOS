ENTRY(_start)

SECTIONS
{
  . = 0x7fc0000000;

  . = ALIGN(0x1000);
  .text : {
    KEEP(*(.text.start))
    *(.text .text.* .ltext .ltext.*)
  }

  . = ALIGN(0x1000);
  .rodata : {
    *(.rodata .rodata.* .lrodata .lrodata.*)
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
    *(.data .data.* .ldata .ldata.*)
  }

  . = ALIGN(0x1000);
  .bss (NOLOAD) : {
    *(.bss .bss.* .lbss .lbss.* COMMON)
  }

  /DISCARD/ : { *(.comment .note .note.*) }
}

ASSERT(. < 0x7fd0000000, "Hosted userspace image exceeds the 16 MiB code/data window")
