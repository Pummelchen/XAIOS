ENTRY(kernel_entry)

SECTIONS
{
  . = 0x40200000;
  __kernel_start = .;

  .text : ALIGN(0x1000) {
    __text_start = .;
    *(.text.entry)
    *(.text.secondary)
    *(.text.vectors)
    *(.text .text.*)
    __text_end = .;
    . = ALIGN(0x1000);
    __user_text_start = .;
    *(.user.text)
    __user_text_end = .;
  }

  .rodata : ALIGN(0x1000) {
    __rodata_start = .;
    *(.rodata .rodata.*)
    __rodata_end = .;
    . = ALIGN(0x1000);
    __user_rodata_start = .;
    *(.user.rodata)
    __user_rodata_end = .;
  }

  .data : ALIGN(0x1000) {
    __data_start = .;
    *(.data .data.*)
    __data_end = .;
  }

  .bss : ALIGN(0x1000) {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    __bss_end = .;
    . = ALIGN(0x1000);
    __user_stack_start = .;
    *(.user.stack)
    __user_stack_end = .;
  }

  . = ALIGN(0x1000);
  __kernel_end = .;
}

/* Static process metadata currently requires more than the original 16 MB cap. */
ASSERT(__kernel_end - __kernel_start < 32M, "Kernel too large (max 32 MB)")
ASSERT(__kernel_end <= 0x100000000, "Kernel overlaps userspace virtual range")
