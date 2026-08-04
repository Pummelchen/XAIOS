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
XAIOS_IRQ_NOERR 33
XAIOS_IRQ_NOERR 34
XAIOS_IRQ_NOERR 128
XAIOS_IRQ_NOERR 255

.global x86_64_load_gdt
.type x86_64_load_gdt, @function
x86_64_load_gdt:
  lgdt (%rdi)
  pushq $0x08
  leaq 1f(%rip), %rax
  pushq %rax
  lretq
1:
  movw $0x10, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  xor %eax, %eax
  movw %ax, %fs
  movw %ax, %gs
  ret

.global x86_64_load_tss
.type x86_64_load_tss, @function
x86_64_load_tss:
  movw $0x28, %ax
  ltr %ax
  ret

.global x86_64_enter_ring3
.type x86_64_enter_ring3, @function
x86_64_enter_ring3:
  movq %rsp, x86_64_ring0_resume_rsp(%rip)
  pushq $0x1b
  pushq %rsi
  pushfq
  popq %rax
  andq $~0x200, %rax
  pushq %rax
  pushq $0x23
  pushq %rdi
  iretq

.global x86_64_ring3_resume
.type x86_64_ring3_resume, @function
x86_64_ring3_resume:
  movq x86_64_ring0_resume_rsp(%rip), %rsp
  ret

.section .bss, "aw", @nobits
.align 8
x86_64_ring0_resume_rsp:
  .quad 0

.section .ap_trampoline, "ax"
.code16
.global x86_64_ap_trampoline_start
x86_64_ap_trampoline_start:
  cli
  cld
  movw %cs, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  lgdtw (x86_64_ap_trampoline_gdtr - x86_64_ap_trampoline_start)
  movl %cr0, %eax
  orl $0x1, %eax
  movl %eax, %cr0
  movl %cr4, %eax
  orl $0x20, %eax
  movl %eax, %cr4
  movl (x86_64_ap_trampoline_cr3 - x86_64_ap_trampoline_start), %eax
  movl %eax, %cr3
  movl $0xc0000080, %ecx
  rdmsr
  orl $0x900, %eax
  wrmsr
  movl %cr0, %eax
  orl $0x80010001, %eax
  movl %eax, %cr0
  ljmpl *(x86_64_ap_trampoline_far - x86_64_ap_trampoline_start)

.align 8
.global x86_64_ap_trampoline_cr3
x86_64_ap_trampoline_cr3:
  .long 0
x86_64_ap_trampoline_gdtr:
  .word 23
.global x86_64_ap_trampoline_gdt_base
x86_64_ap_trampoline_gdt_base:
  .long 0
x86_64_ap_trampoline_far:
.global x86_64_ap_trampoline_long_ip
x86_64_ap_trampoline_long_ip:
  .long 0
  .word 0x08
.align 8
x86_64_ap_trampoline_gdt:
  .quad 0x0000000000000000
  .quad 0x00af9a000000ffff
  .quad 0x00cf92000000ffff

.code64
x86_64_ap_trampoline_long:
  movw $0x10, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  movw %ax, %fs
  movw %ax, %gs
  .byte 0x48, 0xbc
.global x86_64_ap_trampoline_stack
x86_64_ap_trampoline_stack:
  .quad 0
  .byte 0xbf
.global x86_64_ap_trampoline_ordinal
x86_64_ap_trampoline_ordinal:
  .long 0
  .byte 0x48, 0xb8
.global x86_64_ap_trampoline_entry
x86_64_ap_trampoline_entry:
  .quad 0
  call *%rax
1:
  cli
  hlt
  jmp 1b

.global x86_64_ap_trampoline_long_offset
.set x86_64_ap_trampoline_long_offset, \
     x86_64_ap_trampoline_long - x86_64_ap_trampoline_start
.global x86_64_ap_trampoline_gdt_offset
.set x86_64_ap_trampoline_gdt_offset, \
     x86_64_ap_trampoline_gdt - x86_64_ap_trampoline_start
.global x86_64_ap_trampoline_end
x86_64_ap_trampoline_end:

.section .text, "ax"

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
  testq %rax, %rax
  jnz 1f
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
1:
  jmp *%rax
