.section .text.entry, "ax"
.global kernel_entry
.type kernel_entry, @function

kernel_entry:
  cli
  mov %rcx, %r12
  lea __bss_start(%rip), %rdi
  lea __bss_end(%rip), %rcx
  sub %rdi, %rcx
  xor %rax, %rax
  shr $3, %rcx
  rep stosq
  mov %r12, %rdi
  call x86_64_kmain

1:
  hlt
  jmp 1b

.macro XAIOS_ISR_NOERR vector
.global x86_64_isr_\vector
.type x86_64_isr_\vector, @function
x86_64_isr_\vector:
  pushq $0
  pushq $\vector
  jmp x86_64_isr_common
.endm

.macro XAIOS_ISR_ERR vector
.global x86_64_isr_\vector
.type x86_64_isr_\vector, @function
x86_64_isr_\vector:
  pushq $\vector
  jmp x86_64_isr_common
.endm

XAIOS_ISR_NOERR 0
XAIOS_ISR_NOERR 1
XAIOS_ISR_NOERR 2
XAIOS_ISR_NOERR 3
XAIOS_ISR_NOERR 4
XAIOS_ISR_NOERR 5
XAIOS_ISR_NOERR 6
XAIOS_ISR_NOERR 7
XAIOS_ISR_ERR 8
XAIOS_ISR_NOERR 9
XAIOS_ISR_ERR 10
XAIOS_ISR_ERR 11
XAIOS_ISR_ERR 12
XAIOS_ISR_ERR 13
XAIOS_ISR_ERR 14
XAIOS_ISR_NOERR 15
XAIOS_ISR_NOERR 16
XAIOS_ISR_ERR 17
XAIOS_ISR_NOERR 18
XAIOS_ISR_NOERR 19
XAIOS_ISR_NOERR 20
XAIOS_ISR_ERR 21
XAIOS_ISR_NOERR 22
XAIOS_ISR_NOERR 23
XAIOS_ISR_NOERR 24
XAIOS_ISR_NOERR 25
XAIOS_ISR_NOERR 26
XAIOS_ISR_NOERR 27
XAIOS_ISR_NOERR 28
XAIOS_ISR_ERR 29
XAIOS_ISR_ERR 30
XAIOS_ISR_NOERR 31

.macro XAIOS_IRQ_NOERR vector
.global x86_64_irq_\vector
.type x86_64_irq_\vector, @function
x86_64_irq_\vector:
  pushq $0
  pushq $\vector
  jmp x86_64_irq_common
.endm

XAIOS_IRQ_NOERR 32
XAIOS_IRQ_NOERR 255

.global x86_64_isr_common
.type x86_64_isr_common, @function
x86_64_isr_common:
  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rsi
  pushq %rdi
  pushq %rbp
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  movq %rsp, %rdi
  call x86_64_exception_entry
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rbp
  popq %rdi
  popq %rsi
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rax
  addq $16, %rsp
  iretq

.global x86_64_irq_common
.type x86_64_irq_common, @function
x86_64_irq_common:
  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rsi
  pushq %rdi
  pushq %rbp
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  movq %rsp, %rdi
  call x86_64_interrupt_entry
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rbp
  popq %rdi
  popq %rsi
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rax
  addq $16, %rsp
  iretq
