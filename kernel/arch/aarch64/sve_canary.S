.arch armv8.5-a+sve2
.text
.align 4

.global aarch64_sve_vector_bytes
.type aarch64_sve_vector_bytes, %function
aarch64_sve_vector_bytes:
  rdvl x0, #1
  ret
.size aarch64_sve_vector_bytes, .-aarch64_sve_vector_bytes

.global aarch64_sve2_known_answer
.type aarch64_sve2_known_answer, %function
aarch64_sve2_known_answer:
  mov z0.d, #1
  mov z1.d, #2
  mov z2.d, #4
  eor3 z0.d, z0.d, z1.d, z2.d
  umov x0, v0.d[0]
  ret
.size aarch64_sve2_known_answer, .-aarch64_sve2_known_answer

.global aarch64_sve_irq_self_test
.type aarch64_sve_irq_self_test, %function
aarch64_sve_irq_self_test:
  stp x19, x30, [sp, #-16]!
  ptrue p0.b
  pfalse p15.b
  setffr
  mov z0.d, #5
  mov z31.d, #9
  adrp x19, g_aarch64_irq_count
  add x19, x19, :lo12:g_aarch64_irq_count
  ldr x9, [x19]
  msr daifclr, #2
  isb
1:
  wfi
  ldr x10, [x19]
  cmp x10, x9
  b.eq 1b
  mov z2.d, #5
  cmpeq p1.d, p0/z, z0.d, z2.d
  ptest p0, p1.b
  b.cc 20f
  mov z2.d, #9
  cmpeq p1.d, p0/z, z31.d, z2.d
  ptest p0, p1.b
  b.cc 21f
  ptest p0, p15.b
  b.ne 22f
  rdffr p2.b
  cntp x11, p0, p2.b
  rdvl x12, #1
  cmp x11, x12
  b.ne 23f
  mov x0, #1
  b 3f
20:
  mov x0, #2
  b 3f
21:
  mov x0, #3
  b 3f
22:
  mov x0, #4
  b 3f
23:
  mov x0, #5
3:
  ldp x19, x30, [sp], #16
  ret
.size aarch64_sve_irq_self_test, .-aarch64_sve_irq_self_test
