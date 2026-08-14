.arch armv8.5-a+sve2
.section .text.context, "ax"

/* IRQ full-frame entry: saves integer, exception and SIMD/FP state.
 * Frame layout (816 bytes, 16-byte aligned):
 *   [sp+0]   x0   [sp+8]   x1
 *   [sp+16]  x2   [sp+32]  x3
 *   ...
 *   [sp+232] x28  [sp+240] x29
 *   [sp+240] x30
 *   [sp+248] sp_el1 (pre-interrupt kernel sp)
 *   [sp+256] sp_el0
 *   [sp+264] elr_el1
 *   [sp+272] spsr_el1
 *   [sp+280..287] padding
 *   [sp+288] q0 ... [sp+784] q31
 *   [sp+800] fpcr [sp+808] fpsr
 */

.global irq_entry_full
.type irq_entry_full, %function
irq_entry_full:
  /* Reserve the fixed frame plus maximum architectural SVE state:
   * 32 * 256-byte Z, 16 * 32-byte P, and one 32-byte FFR slot. */
  sub sp, sp, #2, lsl #12
  sub sp, sp, #1360
  stp x0, x1, [sp, #0]
  stp x2, x3, [sp, #16]
  stp x4, x5, [sp, #32]
  stp x6, x7, [sp, #48]
  stp x8, x9, [sp, #64]
  stp x10, x11, [sp, #80]
  stp x12, x13, [sp, #96]
  stp x14, x15, [sp, #112]
  stp x16, x17, [sp, #128]
  stp x18, x19, [sp, #144]
  stp x20, x21, [sp, #160]
  stp x22, x23, [sp, #176]
  stp x24, x25, [sp, #192]
  stp x26, x27, [sp, #208]
  stp x28, x29, [sp, #224]
  str x30, [sp, #240]
  add x1, sp, #2, lsl #12
  add x1, x1, #1360
  str x1, [sp, #248]
  mrs x1, sp_el0
  str x1, [sp, #256]
  mrs x1, elr_el1
  str x1, [sp, #264]
  mrs x1, spsr_el1
  str x1, [sp, #272]
  str xzr, [sp, #280]
  stp q0, q1, [sp, #288]
  stp q2, q3, [sp, #320]
  stp q4, q5, [sp, #352]
  stp q6, q7, [sp, #384]
  stp q8, q9, [sp, #416]
  stp q10, q11, [sp, #448]
  stp q12, q13, [sp, #480]
  stp q14, q15, [sp, #512]
  stp q16, q17, [sp, #544]
  stp q18, q19, [sp, #576]
  stp q20, q21, [sp, #608]
  stp q22, q23, [sp, #640]
  stp q24, q25, [sp, #672]
  stp q26, q27, [sp, #704]
  stp q28, q29, [sp, #736]
  stp q30, q31, [sp, #768]
  mrs x1, fpcr
  str x1, [sp, #800]
  mrs x1, fpsr
  str x1, [sp, #808]
  adrp x9, g_aarch64_sve_enabled
  ldr x9, [x9, :lo12:g_aarch64_sve_enabled]
  cbz x9, 40f
  add x9, sp, #816
  str z0, [x9, #0, mul vl]
  str z1, [x9, #1, mul vl]
  str z2, [x9, #2, mul vl]
  str z3, [x9, #3, mul vl]
  str z4, [x9, #4, mul vl]
  str z5, [x9, #5, mul vl]
  str z6, [x9, #6, mul vl]
  str z7, [x9, #7, mul vl]
  str z8, [x9, #8, mul vl]
  str z9, [x9, #9, mul vl]
  str z10, [x9, #10, mul vl]
  str z11, [x9, #11, mul vl]
  str z12, [x9, #12, mul vl]
  str z13, [x9, #13, mul vl]
  str z14, [x9, #14, mul vl]
  str z15, [x9, #15, mul vl]
  str z16, [x9, #16, mul vl]
  str z17, [x9, #17, mul vl]
  str z18, [x9, #18, mul vl]
  str z19, [x9, #19, mul vl]
  str z20, [x9, #20, mul vl]
  str z21, [x9, #21, mul vl]
  str z22, [x9, #22, mul vl]
  str z23, [x9, #23, mul vl]
  str z24, [x9, #24, mul vl]
  str z25, [x9, #25, mul vl]
  str z26, [x9, #26, mul vl]
  str z27, [x9, #27, mul vl]
  str z28, [x9, #28, mul vl]
  str z29, [x9, #29, mul vl]
  str z30, [x9, #30, mul vl]
  str z31, [x9, #31, mul vl]
  add x10, x9, #2, lsl #12
  str p0, [x10, #0, mul vl]
  str p1, [x10, #1, mul vl]
  str p2, [x10, #2, mul vl]
  str p3, [x10, #3, mul vl]
  str p4, [x10, #4, mul vl]
  str p5, [x10, #5, mul vl]
  str p6, [x10, #6, mul vl]
  str p7, [x10, #7, mul vl]
  str p8, [x10, #8, mul vl]
  str p9, [x10, #9, mul vl]
  str p10, [x10, #10, mul vl]
  str p11, [x10, #11, mul vl]
  str p12, [x10, #12, mul vl]
  str p13, [x10, #13, mul vl]
  str p14, [x10, #14, mul vl]
  str p15, [x10, #15, mul vl]
  rdffr p0.b
  add x11, x10, #512
  str p0, [x11]
40:
  mov x19, sp
  mov x0, sp
  adrp x1, aarch64_irq_handler
  add x1, x1, :lo12:aarch64_irq_handler
  blr x1
  mov x12, x0
  adrp x9, g_aarch64_sve_enabled
  ldr x9, [x9, :lo12:g_aarch64_sve_enabled]
  cbz x9, 41f
  add x9, x19, #816
  add x10, x9, #2, lsl #12
  add x11, x10, #512
  ldr p0, [x11]
  wrffr p0.b
  ldr p0, [x10, #0, mul vl]
  ldr p1, [x10, #1, mul vl]
  ldr p2, [x10, #2, mul vl]
  ldr p3, [x10, #3, mul vl]
  ldr p4, [x10, #4, mul vl]
  ldr p5, [x10, #5, mul vl]
  ldr p6, [x10, #6, mul vl]
  ldr p7, [x10, #7, mul vl]
  ldr p8, [x10, #8, mul vl]
  ldr p9, [x10, #9, mul vl]
  ldr p10, [x10, #10, mul vl]
  ldr p11, [x10, #11, mul vl]
  ldr p12, [x10, #12, mul vl]
  ldr p13, [x10, #13, mul vl]
  ldr p14, [x10, #14, mul vl]
  ldr p15, [x10, #15, mul vl]
  ldr z0, [x9, #0, mul vl]
  ldr z1, [x9, #1, mul vl]
  ldr z2, [x9, #2, mul vl]
  ldr z3, [x9, #3, mul vl]
  ldr z4, [x9, #4, mul vl]
  ldr z5, [x9, #5, mul vl]
  ldr z6, [x9, #6, mul vl]
  ldr z7, [x9, #7, mul vl]
  ldr z8, [x9, #8, mul vl]
  ldr z9, [x9, #9, mul vl]
  ldr z10, [x9, #10, mul vl]
  ldr z11, [x9, #11, mul vl]
  ldr z12, [x9, #12, mul vl]
  ldr z13, [x9, #13, mul vl]
  ldr z14, [x9, #14, mul vl]
  ldr z15, [x9, #15, mul vl]
  ldr z16, [x9, #16, mul vl]
  ldr z17, [x9, #17, mul vl]
  ldr z18, [x9, #18, mul vl]
  ldr z19, [x9, #19, mul vl]
  ldr z20, [x9, #20, mul vl]
  ldr z21, [x9, #21, mul vl]
  ldr z22, [x9, #22, mul vl]
  ldr z23, [x9, #23, mul vl]
  ldr z24, [x9, #24, mul vl]
  ldr z25, [x9, #25, mul vl]
  ldr z26, [x9, #26, mul vl]
  ldr z27, [x9, #27, mul vl]
  ldr z28, [x9, #28, mul vl]
  ldr z29, [x9, #29, mul vl]
  ldr z30, [x9, #30, mul vl]
  ldr z31, [x9, #31, mul vl]
  b 42f
41:
  ldp q0, q1, [x12, #288]
  ldp q2, q3, [x12, #320]
  ldp q4, q5, [x12, #352]
  ldp q6, q7, [x12, #384]
  ldp q8, q9, [x12, #416]
  ldp q10, q11, [x12, #448]
  ldp q12, q13, [x12, #480]
  ldp q14, q15, [x12, #512]
  ldp q16, q17, [x12, #544]
  ldp q18, q19, [x12, #576]
  ldp q20, q21, [x12, #608]
  ldp q22, q23, [x12, #640]
  ldp q24, q25, [x12, #672]
  ldp q26, q27, [x12, #704]
  ldp q28, q29, [x12, #736]
  ldp q30, q31, [x12, #768]
42:
  mov sp, x12
  ldr x1, [sp, #800]
  msr fpcr, x1
  ldr x1, [sp, #808]
  msr fpsr, x1
  ldr x1, [sp, #256]
  msr sp_el0, x1
  ldr x1, [sp, #264]
  msr elr_el1, x1
  ldr x1, [sp, #272]
  msr spsr_el1, x1
  ldp x0, x1, [sp, #0]
  ldp x2, x3, [sp, #16]
  ldp x4, x5, [sp, #32]
  ldp x6, x7, [sp, #48]
  ldp x8, x9, [sp, #64]
  ldp x10, x11, [sp, #80]
  ldp x12, x13, [sp, #96]
  ldp x14, x15, [sp, #112]
  ldp x16, x17, [sp, #128]
  ldp x18, x19, [sp, #144]
  ldp x20, x21, [sp, #160]
  ldp x22, x23, [sp, #176]
  ldp x24, x25, [sp, #192]
  ldp x26, x27, [sp, #208]
  ldp x28, x29, [sp, #224]
  ldr x30, [sp, #240]
  add sp, sp, #2, lsl #12
  add sp, sp, #1360
  eret
.size irq_entry_full, . - irq_entry_full

/* void context_switch(xaios_context_frame_t *old,
 *                     const xaios_context_frame_t *new_frame)
 * Cooperative context switch: saves callee-saved state to *old,
 * restores from *new_frame. Returns to caller in the NEW context.
 */
.global context_switch
.type context_switch, %function
context_switch:
  /* save callee-saved registers to old frame */
  stp x19, x20, [x0, #152]
  stp x21, x22, [x0, #168]
  stp x23, x24, [x0, #184]
  stp x25, x26, [x0, #200]
  stp x27, x28, [x0, #216]
  stp x29, x30, [x0, #232]
  mov x2, sp
  str x2, [x0, #248]
  stp q8, q9, [x0, #416]
  stp q10, q11, [x0, #448]
  stp q12, q13, [x0, #480]
  stp q14, q15, [x0, #512]
  mrs x2, fpcr
  str x2, [x0, #800]
  mrs x2, fpsr
  str x2, [x0, #808]
  /* restore callee-saved from new frame */
  ldp x19, x20, [x1, #152]
  ldp x21, x22, [x1, #168]
  ldp x23, x24, [x1, #184]
  ldp x25, x26, [x1, #200]
  ldp x27, x28, [x1, #216]
  ldp x29, x30, [x1, #232]
  ldr x2, [x1, #248]
  ldp q8, q9, [x1, #416]
  ldp q10, q11, [x1, #448]
  ldp q12, q13, [x1, #480]
  ldp q14, q15, [x1, #512]
  ldr x3, [x1, #800]
  msr fpcr, x3
  ldr x3, [x1, #808]
  msr fpsr, x3
  mov sp, x2
  ret /* returns via new frame's x30 */
.size context_switch, . - context_switch

/* uint64_t context_save(xaios_context_frame_t *frame)
 * Saves callee-saved regs and sp. Returns 0 (initial save). */
.global context_save
.type context_save, %function
context_save:
  stp x19, x20, [x0, #152]
  stp x21, x22, [x0, #168]
  stp x23, x24, [x0, #184]
  stp x25, x26, [x0, #200]
  stp x27, x28, [x0, #216]
  stp x29, x30, [x0, #232]
  mov x1, sp
  str x1, [x0, #248]
  stp q8, q9, [x0, #416]
  stp q10, q11, [x0, #448]
  stp q12, q13, [x0, #480]
  stp q14, q15, [x0, #512]
  mrs x1, fpcr
  str x1, [x0, #800]
  mrs x1, fpsr
  str x1, [x0, #808]
  mov x0, #0
  ret
.size context_save, . - context_save

/* void context_restore(const xaios_context_frame_t *frame)
 * Restores callee-saved regs and sp. Returns via saved x30. */
.global context_restore
.type context_restore, %function
context_restore:
  ldp x19, x20, [x0, #152]
  ldp x21, x22, [x0, #168]
  ldp x23, x24, [x0, #184]
  ldp x25, x26, [x0, #200]
  ldp x27, x28, [x0, #216]
  ldp x29, x30, [x0, #232]
  ldr x1, [x0, #248]
  ldp q8, q9, [x0, #416]
  ldp q10, q11, [x0, #448]
  ldp q12, q13, [x0, #480]
  ldp q14, q15, [x0, #512]
  ldr x2, [x0, #800]
  msr fpcr, x2
  ldr x2, [x0, #808]
  msr fpsr, x2
  mov sp, x1
  ret
.size context_restore, . - context_restore

/* A live interrupt canary. q0 and q31 are caller-clobbered by the C ABI, so
 * preserving them proves the IRQ frame, not an ordinary function prologue. */
.global aarch64_simd_irq_self_test
.type aarch64_simd_irq_self_test, %function
aarch64_simd_irq_self_test:
  sub sp, sp, #64
  stp q0, q31, [sp, #0]
  mrs x9, fpcr
  mrs x10, fpsr
  stp x9, x10, [sp, #32]
  str x30, [sp, #48]

  movz x1, #0x3210
  movk x1, #0x7654, lsl #16
  movk x1, #0xba98, lsl #32
  movk x1, #0xfedc, lsl #48
  movz x2, #0xcdef
  movk x2, #0x89ab, lsl #16
  movk x2, #0x4567, lsl #32
  movk x2, #0x0123, lsl #48
  ins v0.d[0], x1
  ins v0.d[1], x2
  ins v31.d[0], x2
  ins v31.d[1], x1
  mov x3, #0x400000
  msr fpcr, x3
  mov x3, #0x08000000
  msr fpsr, x3

  adrp x4, g_aarch64_irq_count
  add x4, x4, :lo12:g_aarch64_irq_count
  ldr x5, [x4]
  msr daifclr, #2
  isb
1:
  wfi
  ldr x6, [x4]
  cmp x6, x5
  b.eq 1b

  umov x6, v0.d[0]
  cmp x6, x1
  b.ne 20f
  umov x6, v0.d[1]
  cmp x6, x2
  b.ne 21f
  umov x6, v31.d[0]
  cmp x6, x2
  b.ne 22f
  umov x6, v31.d[1]
  cmp x6, x1
  b.ne 23f
  mrs x6, fpcr
  mov x7, #0x400000
  cmp x6, x7
  b.ne 24f
  mrs x6, fpsr
  mov x7, #0x08000000
  cmp x6, x7
  b.ne 25f
  mov x0, #1
  b 30f
20:
  mov x0, #2
  b 30f
21:
  mov x0, #3
  b 30f
22:
  mov x0, #4
  b 30f
23:
  mov x0, #5
  b 30f
24:
  mov x0, #6
  b 30f
25:
  mov x0, #7
30:
  ldp x9, x10, [sp, #32]
  msr fpcr, x9
  msr fpsr, x10
  ldp q0, q31, [sp, #0]
  ldr x30, [sp, #48]
  add sp, sp, #64
  ret
.size aarch64_simd_irq_self_test, . - aarch64_simd_irq_self_test
