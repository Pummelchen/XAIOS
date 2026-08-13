.section .text.start, "ax"
.global _start
.type _start, @function
.global xaios_thread_return_trampoline
.type xaios_thread_return_trampoline, @function

#if defined(__aarch64__)
_start:
  mov x29, xzr
  mov x30, xzr
  bl xaios_libc_start
1:
  wfe
  b 1b

xaios_thread_return_trampoline:
  mov x8, #45
  svc #0
2:
  wfe
  b 2b
#elif defined(__x86_64__)
_start:
  xorq %rbp, %rbp
  andq $-16, %rsp
  call xaios_libc_start
1:
  pause
  jmp 1b

xaios_thread_return_trampoline:
  movq %rax, %rdi
  movl $45, %eax
  int $0x80
2:
  pause
  jmp 2b
#else
#error "Unsupported XAIOS userspace architecture"
#endif
