.section .text, "ax"
.global _start
.type _start, @function

_start:
  leaq msg_start(%rip), %rdi
  movq $(msg_start_end-msg_start), %rsi
  xorq %rdx, %rdx
  movq $1, %rax
  int $0x80
  cmpq $-1, %rax
  je failed
  xorq %rdi, %rdi
  movq $2, %rax
  int $0x80
1:
  pause
  jmp 1b

failed:
  movq $1, %rdi
  movq $2, %rax
  int $0x80
  jmp 1b

.section .rodata, "a"
msg_start: .ascii "/worker: scheduled child process ran\n"
msg_start_end:
