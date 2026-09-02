/* First instructions on RISC-V.
 *
 * OpenSBI hands over in S-mode with a0 holding this hart's id and a1 the
 * physical address of the device tree. Those two registers are the whole of
 * the boot protocol here -- there is no structure to parse and no firmware
 * call to make first -- so they are preserved and passed straight through
 * rather than being rediscovered later.
 *
 * Secondary harts arrive here too on a board that starts them all. Only hart
 * 0 continues; the rest park in a wait-for-interrupt loop rather than racing
 * through a bring-up that has one stack. Bringing them up properly is SMP
 * work this port has not done, and parking them is the honest version of
 * not having done it -- a hart that runs on into shared state nobody
 * initialised does not look like a missing feature, it looks like memory
 * corruption.
 */
  .section .text.entry, "ax"
  .globl _start
_start:
  /* Interrupts off until a trap vector exists. A trap before stvec is set
     goes to whatever address that CSR happened to hold, which on this board
     is zero. */
  csrw  sie, zero
  csrci sstatus, 2          /* clear SIE */

  mv    s0, a0              /* hart id, preserved across the clear below */
  mv    s1, a1              /* device tree pointer */

  /* Park every hart but the first. */
  bnez  a0, park

  la    sp, __stack_top

  /* Zero .bss before any C touches it. The C code below assumes static
     storage starts at zero, which is a language guarantee the language
     cannot provide on its own here. */
  la    t0, __bss_start
  la    t1, __bss_end
1:
  bgeu  t0, t1, 2f
  sd    zero, 0(t0)
  addi  t0, t0, 8
  j     1b
2:

  mv    a0, s0
  mv    a1, s1
  call  riscv64_boot

  /* riscv64_boot asks SBI to power the machine off and does not return. If
     it ever does, stop here rather than executing whatever follows. */
park:
  wfi
  j     park

/* Trap entry.
 *
 * Deliberately minimal: enough to prove a trap is taken, identified and
 * returned from, which is the milestone this port is claiming. It saves the
 * caller-saved registers it actually uses and nothing else, because a full
 * context switch belongs with the scheduler work this port has not done and
 * a half-written one would be worse than an absent one.
 */
  .section .text, "ax"
  .globl riscv64_trap_entry
  .align 4
riscv64_trap_entry:
  addi  sp, sp, -64
  sd    ra, 0(sp)
  sd    a0, 8(sp)
  sd    a1, 16(sp)
  sd    a2, 24(sp)
  sd    a3, 32(sp)
  sd    a4, 40(sp)
  sd    a5, 48(sp)

  csrr  a0, scause
  csrr  a1, sepc
  csrr  a2, stval
  call  riscv64_trap_handler
  /* The handler returns the address to resume at, which for a synchronous
     exception is the faulting instruction's successor. Writing it back is
     what makes the trap survivable rather than a loop. */
  csrw  sepc, a0

  ld    ra, 0(sp)
  ld    a0, 8(sp)
  ld    a1, 16(sp)
  ld    a2, 24(sp)
  ld    a3, 32(sp)
  ld    a4, 40(sp)
  ld    a5, 48(sp)
  addi  sp, sp, 64
  sret
