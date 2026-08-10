.section .text.entry, "ax"
.global kernel_entry
.type kernel_entry, %function
.global aarch64_enter_user
.type aarch64_enter_user, %function
.global aarch64_return_from_user_exit
.type aarch64_return_from_user_exit, %function

kernel_entry:
  msr daifset, #0xf
  mrs x1, cpacr_el1
  orr x1, x1, #0x300000
  msr cpacr_el1, x1
  isb
  /* Set VBAR_EL1 to kernel exception vectors immediately, before any
   * C code runs. This ensures HVF (Apple Hypervisor.framework) can
   * properly decode exception syndrome information from the very
   * first cycle — without it, an early timer interrupt or page fault
   * triggers hvf.c:2275 assertion (isv == 0). */
  adrp x1, __exception_vectors
  add x1, x1, :lo12:__exception_vectors
  msr vbar_el1, x1
  isb
  mov x20, x0
  ldr x0, =__bss_start
  ldr x1, =__bss_end
  mov x2, #0
1:
  cmp x0, x1
  b.hs 2f
  str x2, [x0], #8
  b 1b
2:
  /* Seed stack canary from CNTVCT_EL0 */
  isb
  mrs x1, cntvct_el0
  ldr x2, =0x5841494F535F4341
  eor x1, x1, x2
  ldr x2, =g_stack_canary
  str x1, [x2]
  mov x0, x20
  bl kmain
3:
  wfe
  b 3b

aarch64_enter_user:
  sub sp, sp, #112
  stp x19, x20, [sp, #0]
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  stp x29, x30, [sp, #80]
  mrs x3, tpidr_el1
  str x3, [sp, #96]
  mov x9, sp
  msr tpidr_el1, x9
  mov x2, #0
  msr sp_el0, x1
  msr elr_el1, x0
  msr spsr_el1, x2
  eret

.global aarch64_enter_user_thread
.type aarch64_enter_user_thread, %function
aarch64_enter_user_thread:
  sub sp, sp, #112
  stp x19, x20, [sp, #0]
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  stp x29, x30, [sp, #80]
  mrs x9, tpidr_el1
  str x9, [sp, #96]
  mov x10, sp
  msr tpidr_el1, x10
  msr sp_el0, x1
  msr elr_el1, x0
  mov x0, x2
  mov x30, x3
  mov x9, #0
  msr spsr_el1, x9
  eret

aarch64_return_from_user_exit:
  mrs x9, tpidr_el1
  mov sp, x9
  ldr x10, [sp, #96]
  ldp x19, x20, [sp, #0]
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x29, x30, [sp, #80]
  add sp, sp, #112
  msr tpidr_el1, x10
  ret
