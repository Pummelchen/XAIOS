.section .text.start, "ax"
.global _start
.type _start, @function

#if defined(__aarch64__)
_start:
  mov x29, xzr
  mov x30, xzr
  bl xaios_libc_start
1:
  wfe
  b 1b
#elif defined(__x86_64__)
_start:
  xorq %rbp, %rbp
  andq $-16, %rsp
  call xaios_libc_start
1:
  pause
  jmp 1b
#else
#error "Unsupported XAIOS userspace architecture"
#endif
