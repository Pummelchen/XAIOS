.section .text.secondary, "ax"
.global aarch64_secondary_entry
.type aarch64_secondary_entry, %function

aarch64_secondary_entry:
  msr daifset, #0xf
  adrp x1, __exception_vectors
  add x1, x1, :lo12:__exception_vectors
  msr vbar_el1, x1
  mrs x1, cpacr_el1
  orr x1, x1, #0x300000
  msr cpacr_el1, x1
  isb
  ldr x1, =g_secondary_stacks
  mov x2, #4096
  madd x1, x0, x2, x1
  add x1, x1, x2
  mov sp, x1
  bl smp_secondary_main
1:
  wfe
  b 1b
