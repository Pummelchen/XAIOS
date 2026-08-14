ENTRY(kernel_entry)

SECTIONS
{
  . = 0x100000;
  __kernel_start = .;

  .text : ALIGN(0x1000) {
    __text_start = .;
    *(.text.entry)
    *(.ap_trampoline)
    *(.text .text.* .ltext .ltext.*)
    __text_end = .;
  }

  . = ALIGN(0x1000);
  .rodata : {
    __rodata_start = .;
    *(.rodata .rodata.* .lrodata .lrodata.*)
    __rodata_end = .;
  }

  . = ALIGN(0x1000);
  .data : {
    __data_start = .;
    *(.data .data.*)
    __data_end = .;
  }

  . = ALIGN(0x1000);
  .bss : {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    __bss_end = .;
  }

  .user_test (NOLOAD) : ALIGN(0x200000) {
    __user_test_start = .;
    *(.user_test)
    __user_test_end = .;
  }

  . = ALIGN(0x1000);
  __kernel_end = .;
}
