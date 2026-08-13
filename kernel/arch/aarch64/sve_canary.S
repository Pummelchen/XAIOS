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
