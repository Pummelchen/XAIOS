ENTRY(_start)

SECTIONS
{
  . = 0x100000000;

  .text : ALIGN(0x1000) {
    *(.text .text.*)
  }

  .rodata : ALIGN(0x1000) {
    *(.rodata .rodata.*)
  }

  .data : ALIGN(0x1000) {
    *(.data .data.*)
  }

  .bss : ALIGN(0x1000) {
    *(.bss .bss.* COMMON)
  }
}

ASSERT(. < 0x102000000, "Userspace image exceeds the 2 MiB code/data window")
