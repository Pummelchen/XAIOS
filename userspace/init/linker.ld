ENTRY(_start)

SECTIONS
{
  . = 0x7fc0000000;

  .text : ALIGN(0x1000) {
    *(.text .text.* .ltext .ltext.*)
  }

  .rodata : ALIGN(0x1000) {
    *(.rodata .rodata.* .lrodata .lrodata.*)
  }

  .data : ALIGN(0x1000) {
    *(.data .data.* .ldata .ldata.*)
  }

  .bss : ALIGN(0x1000) {
    *(.bss .bss.* .lbss .lbss.* COMMON)
  }
}

ASSERT(. < 0x7fd0000000, "Userspace image exceeds the 16 MiB code/data window")
