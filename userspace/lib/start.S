.section .text, "ax"
.global _start
.type _start, @function
.global xaios_thread_return_trampoline
.type xaios_thread_return_trampoline, @function

#if defined(__aarch64__)
_start:
  bl main
  mov x8, #2
  svc #0

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
  andq $-16, %rsp
  call main
  movl %eax, %edi
  movl $2, %eax
  int $0x80
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
#elif defined(__riscv)
_start:
  call  main
  /* main's return value is already in a0, which is where the exit syscall
     wants it. */
  li    a7, 2
  ecall
1:
  j     1b

xaios_thread_return_trampoline:
  li    a7, 45
  ecall
2:
  j     2b
#else
#error "Unsupported XAIOS userspace architecture"
#endif
