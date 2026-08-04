.section .text, "ax"
.global _start
.type _start, %function
.global xaios_thread_return_trampoline
.type xaios_thread_return_trampoline, %function

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
