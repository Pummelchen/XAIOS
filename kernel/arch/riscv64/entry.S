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

  /* Translation off, whatever the previous stage left on.
   *
   * SBI firmware hands over with satp already zero, so this is a no-op there
   * and was easy to leave out. UEFI does not: EDK2 runs in supervisor mode
   * with its own page tables and does not tear them down at ExitBootServices,
   * so the kernel inherited a map covering firmware's world and not the
   * board's. The first write to the interrupt controller then took a store
   * page fault at an address the kernel had every right to expect, twenty
   * lines before vmm_init would have mapped it itself. Both entry paths now
   * start bare, and the kernel's map is the only one it ever runs under.
   *
   * Safe from either path because EDK2's mapping of this range is one to one
   * -- the instruction after this one is at the same address with translation
   * off as with it on. */
  csrw  satp, zero
  sfence.vma zero, zero

  mv    s0, a0              /* hart id, preserved across the clear below */
  mv    s1, a1              /* device tree pointer */

  /* Which hart continues, decided by a race rather than by number.
   *
   * This parked every hart whose id was not zero, which is wrong on any
   * machine with more than one: firmware picks its own boot hart, and on
   * QEMU's virt board with four harts that is whichever one wins OpenSBI's
   * internal race -- observed as 0, 1 and 2 across consecutive runs of the
   * same command. Three times in four the kernel therefore parked the one
   * hart that had been given control and nothing ran at all, with not one
   * character of output to say so. It looked like a hang before the first
   * instruction; it was the first instruction.
   *
   * The lottery lives in .data because .bss has not been zeroed yet -- and
   * the winner is what zeroes it, so a flag kept there would be cleared out
   * from under the harts still reading it. */
  la    t0, riscv64_boot_lottery
  li    t1, 1
  amoswap.w t2, t1, (t0)
  bnez  t2, park

  /* tp carries this hart's *logical* CPU number, not its hart id.
   *
   * They are not the same thing and conflating them was a bug: firmware
   * numbers harts however it likes and hands over on whichever one it chose,
   * so a kernel that used the hart id as its CPU index reported a machine
   * whose only CPU was number 3 -- and shared code, reasonably, expects CPU 0
   * to exist. The hart id is hardware identity and belongs in the table that
   * makes SBI calls; the CPU number is the kernel's own index and starts at
   * zero. The hart that wins the lottery is CPU 0 by definition. */
  mv    tp, zero

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
/* Where every hart that lost the lottery goes.
 *
 * Stopped through SBI rather than spun, so firmware puts it back in the state
 * it started from and smp_release_secondary_schedulers can start it later at
 * the secondary entry point. A hart parked in a wait loop is still "started"
 * as far as SBI is concerned, and asking to start it again is refused -- so
 * spinning here would have cost the machine every core but one, quietly. The
 * wait loop remains as the fallback for firmware without hart state
 * management, where spinning is all there is. */
park:
  li    a7, 0x48534D        /* "HSM" */
  li    a6, 1               /* hart_stop */
  ecall
1:
  wfi
  j     1b

  .section .data, "aw"
  .align 2
riscv64_boot_lottery:
  .word 0

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
  /* Which stack this runs on.
   *
   * The first version of this ran on whatever sp the trap arrived with, which
   * is correct for a kernel that never leaves supervisor mode and catastrophic
   * for one that does: a trap from user mode would have pushed a kernel trap
   * frame onto the user's stack, where the user chose the address and can read
   * what lands there. sscratch holds the kernel stack while a thread is in
   * user mode and zero while the kernel is running, so one swap distinguishes
   * the two cases and lands on the right stack in both. */
  csrrw sp, sscratch, sp
  bnez  sp, 1f
  /* Zero came back, so this trap is from the kernel and sp was already
     right; put it back and leave sscratch as it was. */
  csrrw sp, sscratch, sp
1:
  addi  sp, sp, -288
  sd    ra, 0(sp)
  sd    gp, 16(sp)
  sd    tp, 24(sp)
  sd    t0, 32(sp)
  sd    t1, 40(sp)
  sd    t2, 48(sp)
  sd    s0, 56(sp)
  sd    s1, 64(sp)
  sd    a0, 72(sp)
  sd    a1, 80(sp)
  sd    a2, 88(sp)
  sd    a3, 96(sp)
  sd    a4, 104(sp)
  sd    a5, 112(sp)
  sd    a6, 120(sp)
  sd    a7, 128(sp)
  sd    s2, 136(sp)
  sd    s3, 144(sp)
  sd    s4, 152(sp)
  sd    s5, 160(sp)
  sd    s6, 168(sp)
  sd    s7, 176(sp)
  sd    s8, 184(sp)
  sd    s9, 192(sp)
  sd    s10, 200(sp)
  sd    s11, 208(sp)
  sd    t3, 216(sp)
  sd    t4, 224(sp)
  sd    t5, 232(sp)
  sd    t6, 240(sp)

  /* The interrupted stack pointer, which is in sscratch for a trap from user
     mode and is this stack for one from the kernel. */
  csrr  t0, sscratch
  bnez  t0, 2f
  addi  t0, sp, 288
2:
  sd    t0, 8(sp)
  /* Cleared so a nested trap taken while the kernel is running takes the
     kernel branch above rather than switching to a stack already in use. */
  csrw  sscratch, zero

  csrr  t0, sepc
  sd    t0, 248(sp)
  csrr  t0, scause
  sd    t0, 256(sp)
  csrr  t0, stval
  sd    t0, 264(sp)
  csrr  t0, sstatus
  sd    t0, 272(sp)

  mv    a0, sp
  call  riscv64_trap_handler
  /* Non-zero means the process this trap came from has exited and there is
     nothing to return to. */
  bnez  a0, riscv64_return_from_user_exit

  /* sepc is restored from the frame, which the handler may have advanced past
     the faulting instruction or left alone for an interrupt. */
  ld    t0, 248(sp)
  csrw  sepc, t0
  ld    t0, 272(sp)
  csrw  sstatus, t0

  /* Going back to user mode means sscratch has to hold this kernel stack
     again, or the next syscall from that thread finds zero and stays on the
     user stack -- the bug this whole dance exists to prevent, reintroduced on
     the second call rather than the first. */
  li    t1, 0x100
  and   t1, t0, t1
  bnez  t1, 3f
  addi  t0, sp, 288
  csrw  sscratch, t0
3:
  ld    ra, 0(sp)
  ld    gp, 16(sp)
  ld    tp, 24(sp)
  ld    t0, 32(sp)
  ld    t1, 40(sp)
  ld    t2, 48(sp)
  ld    s0, 56(sp)
  ld    s1, 64(sp)
  ld    a0, 72(sp)
  ld    a1, 80(sp)
  ld    a2, 88(sp)
  ld    a3, 96(sp)
  ld    a4, 104(sp)
  ld    a5, 112(sp)
  ld    a6, 120(sp)
  ld    a7, 128(sp)
  ld    s2, 136(sp)
  ld    s3, 144(sp)
  ld    s4, 152(sp)
  ld    s5, 160(sp)
  ld    s6, 168(sp)
  ld    s7, 176(sp)
  ld    s8, 184(sp)
  ld    s9, 192(sp)
  ld    s10, 200(sp)
  ld    s11, 208(sp)
  ld    t3, 216(sp)
  ld    t4, 224(sp)
  ld    t5, 232(sp)
  ld    t6, 240(sp)
  ld    sp, 8(sp)
  sret

/* The SIMD/FP interrupt canary the scheduler checks before enabling
   preemption.
 *
 * Named aarch64_* and called unconditionally from shared code, which is the
 * same identity leak the interrupt-controller interface has: x86-64 already
 * defines it under this name in its own entry.S for exactly this reason. The
 * name is inherited rather than chosen.
 *
 * What it means is "floating-point state survives a trap". This writes a
 * known value into an FP register, takes a trap, and checks the value came
 * back -- which is a real test on RISC-V, where fs in sstatus can leave the
 * FP unit off and a save that never happened looks identical to one that did
 * until something reads a register.
 */
  .globl aarch64_simd_irq_self_test
  .type aarch64_simd_irq_self_test, @function
aarch64_simd_irq_self_test:
  /* Enable the FP unit if it is off: fs = Initial. A kernel that traps on
     its first FP instruction cannot report why. */
  li    t0, 0x2000
  csrs  sstatus, t0

  li    t1, 0x5A
  fcvt.d.l fa0, t1          /* a value only this test would produce */
  ebreak                    /* take a trap with it live */
  fcvt.l.d t2, fa0, rtz     /* and read it back afterwards */

  li    t3, 0x5A
  li    a0, 1
  beq   t2, t3, 1f
  li    a0, 0               /* the value did not survive the trap */
1:
  ret
  .size aarch64_simd_irq_self_test, . - aarch64_simd_irq_self_test

/* Enter a user thread, and come back when it is done.
 *
 * Named aarch64_* for the same inherited reason as the SIMD canary: the
 * shared scheduler declares it that way and x86-64 defines it under that
 * name too.
 *
 * a0 entry, a1 stack top, a2 argument, a3 return address.
 *
 * The mechanism is sret with sstatus.SPP cleared, which is what takes a hart
 * to user mode -- the same instruction that returns from a trap, because
 * RISC-V has only the one. Coming back therefore arrives as a trap, not as a
 * return, so the kernel's context has to be somewhere the trap handler can
 * find it: saved on this stack, with the stack pointer parked in sscratch.
 */
  .globl aarch64_enter_user_thread
  .type aarch64_enter_user_thread, @function
aarch64_enter_user_thread:
  addi  sp, sp, -112
  sd    ra, 0(sp)
  sd    s0, 8(sp)
  sd    s1, 16(sp)
  sd    s2, 24(sp)
  sd    s3, 32(sp)
  sd    s4, 40(sp)
  sd    s5, 48(sp)
  sd    s6, 56(sp)
  sd    s7, 64(sp)
  sd    s8, 72(sp)
  sd    s9, 80(sp)
  sd    s10, 88(sp)
  sd    s11, 96(sp)

  /* Where the trap handler finds the kernel stack to return onto. */
  csrw  sscratch, sp

  /* SPP = 0 selects user mode for the sret below; SPIE = 1 so interrupts are
     enabled once there. A user thread entered with interrupts off cannot be
     preempted, which is a scheduler that does not schedule. */
  li    t0, 0x100           /* SSTATUS_SPP */
  csrc  sstatus, t0
  li    t0, 0x20            /* SSTATUS_SPIE */
  csrs  sstatus, t0

  csrw  sepc, a0            /* entry */
  mv    t1, a1              /* user stack top */
  mv    t2, a2              /* argument */
  mv    t3, a3              /* return address the thread exits through */
  mv    sp, t1
  mv    a0, t2
  mv    ra, t3
  sret

/* Where a user thread comes back to, entered from the trap handler once it
   has decided the thread is finished. a0 carries the encoded result the
   scheduler expects. */
/* Leaving user mode for good.
 *
 * Entered from the trap stub with sp still pointing at the trap frame and a0
 * holding the encoded exit result, which is what aarch64_enter_user returns.
 * The kernel stack that entered user mode is exactly 288 bytes above the
 * frame -- the stub subtracted that much from the value sscratch held -- so
 * unwinding is arithmetic rather than another saved pointer.
 */
  .globl riscv64_return_from_user_exit
  .type riscv64_return_from_user_exit, @function
riscv64_return_from_user_exit:
  addi  sp, sp, 288
  ld    ra, 0(sp)
  ld    s0, 8(sp)
  ld    s1, 16(sp)
  ld    s2, 24(sp)
  ld    s3, 32(sp)
  ld    s4, 40(sp)
  ld    s5, 48(sp)
  ld    s6, 56(sp)
  ld    s7, 64(sp)
  ld    s8, 72(sp)
  ld    s9, 80(sp)
  ld    s10, 88(sp)
  ld    s11, 96(sp)
  addi  sp, sp, 112
  ret
  .size aarch64_enter_user_thread, . - aarch64_enter_user_thread

/* The other user entry, taking argc and argv rather than a single argument.
   Two entry points exist because processes and threads are started
   differently; the mechanism is identical, so this forwards rather than
   duplicating the register dance above. */
  .globl aarch64_enter_user
  .type aarch64_enter_user, @function
aarch64_enter_user:
  /* a0 entry, a1 stack, a2 argc, a3 argv -> entry, stack, argument=argc,
     return=argv is wrong; a process returns through its own exit syscall, so
     the return address is not used and argv goes in a1 of the user frame.
     Passing argc as the argument and leaving argv where the ABI puts a second
     parameter keeps the same convention userspace already expects. */
  /* Its own return address, saved -- which it was not.
   *
   * `call` puts the return address in ra, and aarch64_enter_user_thread
   * restores ra from its own frame when the process exits, which is the
   * address just after that call. So this returned into itself, executed
   * `ret` with ra still pointing at that same instruction, and looped between
   * two instructions forever. From outside it looked like a process that had
   * exited -- the kernel had logged it as exited -- and never came back. */
  addi  sp, sp, -16
  sd    ra, 0(sp)
  /* argv is not passed through: the thread entry uses a1 for the user stack
     and a3 for the address a thread returns through, and a process returns
     through its own exit syscall instead. Zeroed rather than left holding a
     pointer the user frame would never read. */
  mv    a3, zero
  call  aarch64_enter_user_thread
  ld    ra, 0(sp)
  addi  sp, sp, 16
  ret
  .size aarch64_enter_user, . - aarch64_enter_user

/* Where a secondary hart begins.
 *
 * SBI hands control here with translation off, this hart's id in a0 and the
 * opaque value from hart_start in a1 -- which is why the record it points at
 * has to be reachable without a page table, and why this runs from the
 * identity-mapped kernel image rather than anywhere clever.
 *
 * The order matters. A stack has to exist before any call, translation has to
 * be on before the C code touches anything the boot hart published through
 * the kernel mapping, and the trap vector has to be armed before interrupts
 * are enabled -- a secondary that takes a trap with stvec still zero
 * disappears into address zero with no message.
 */
  .globl riscv64_secondary_entry
  .type riscv64_secondary_entry, @function
riscv64_secondary_entry:
  /* a1 points at { stack_top, satp, cpu_id } for this hart. */
  ld    sp, 0(a1)
  ld    t0, 8(a1)
  ld    tp, 16(a1)          /* logical CPU number, not the hart id */

  csrw  satp, t0
  sfence.vma zero, zero

  /* Supervisor access to user pages, matching the boot hart. Set per hart
     because sstatus is per hart: a secondary that ran a syscall without it
     would fault on the first user pointer it touched. */
  li    t1, 0x40000
  csrs  sstatus, t1

  csrw  sscratch, zero
  la    t2, riscv64_trap_entry
  csrw  stvec, t2

  mv    a0, tp
  call  smp_secondary_main
1:
  wfi
  j     1b
  .size riscv64_secondary_entry, . - riscv64_secondary_entry
