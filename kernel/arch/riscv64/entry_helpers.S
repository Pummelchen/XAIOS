/* The entry points that are neither the first instructions nor the trap
 * vector, split out of entry.S so that neither file is over the repository's
 * source-size limit.
 *
 * This is the first assembly file the size campaign has split, so the layout
 * contract is stated rather than assumed:
 *
 *   - Section. `.section .text, "ax"` is the directive entry.S uses for this
 *     code, spelled the same way, so both objects contribute to one output
 *     `.text`: linker.ld gathers `*(.text.entry)` first and then
 *     `*(.text .text.*)` in input order. `_start` therefore stays in
 *     `.text.entry` at 0x80200000, the `.data` block holding
 *     riscv64_boot_lottery stays in entry.S, and __text_start/__text_end
 *     still bracket every instruction of both.
 *
 *   - Order. These entries are separate global symbols reached by name from
 *     other translation units, so link order does not choose between them --
 *     with one exception, and it is a distance rather than an order. The trap
 *     vector's `bnez a0, riscv64_return_from_user_exit` reaches into this
 *     object with a PC-relative branch (R_RISCV_BRANCH, +/-4 KiB, and the
 *     build passes -mno-relax so the linker resolves it as written). This
 *     object must stay adjacent to entry.o: scripts/build-riscv64.sh compiles
 *     it immediately after entry.S, which leaves the target a few hundred
 *     bytes away, just as it was when both shared a file. Compiling it later
 *     in that script can push the target out of range.
 *
 *   - The sscratch window. riscv64_sscratch_window_begin and _end bracket the
 *     instructions a supervisor trap's sepc is checked against
 *     (exception.c). Every instruction between them was inside the moved
 *     range, so they moved together with it and still enclose the same code.
 *
 *   - Sizes. The order of the entries below is unchanged, which matters
 *     because `.size xaios_enter_user_thread` measures across
 *     riscv64_return_from_user_exit; splitting this run would have made that
 *     expression cross objects. It does not.
 */
  .section .text, "ax"

  /* The trap frame size, restated.
   *
   * TRAP_FRAME_BYTES is an assembler constant, not a linked symbol, so a
   * second translation unit cannot see the `.equ` in entry.S, and the moved
   * `riscv64_return_from_user_exit` needs it to unwind the frame the trap
   * vector pushed. The value is the same 560; entry.S keeps its own copy for
   * the vector, and both are declared local so the two copies cannot reach
   * the linker as competing definitions. A shared include file was
   * considered and rejected: the directive's search path cannot be verified
   * without compiling, which this work may not do. */
  .local TRAP_FRAME_BYTES
  .equ  TRAP_FRAME_BYTES, 560

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
  .globl xaios_enter_user_thread
  .type xaios_enter_user_thread, @function
xaios_enter_user_thread:
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

  /* Where the trap handler finds the kernel stack to return onto. The two
     labels around the section that follows are what the trap handler checks a
     supervisor trap's sepc against: anything trapped in here would be read as
     a trap from user mode, which is the corruption this window exists to
     prevent (B-108). */
  .globl riscv64_sscratch_window_begin
riscv64_sscratch_window_begin:
  csrw  sscratch, sp

  /* Interrupts off until we are actually in user mode, and that is a fix
     rather than a precaution.
   *
   * The trap entry decides where a trap came from by looking at sscratch: a
     non-zero value means a thread was in user mode and the frame must be
     pushed on the kernel stack it names, and zero means the kernel was running
     and the frame goes on the current stack. Between the store above and the
     sret below, sscratch is non-zero while the kernel is still running, so an
     interrupt taken in that window is read as a trap from user mode, saves the
     wrong stack pointer and leaves sscratch holding a kernel address instead of
     zero. The next trap from user mode then switches to a stack that is
     already in use, and the nested frames unwind to garbage -- measured as a
     return to program counter zero and later as a jump to address 4 with a
     zero stack pointer (B-108), the fault that no mask had fixed.
   *
   * Masking everything around `xaios_thread_run_pending` instead was tried and
   * is wrong for a different reason: it also masks the supervisor software
   * interrupt the scheduler uses to move work between harts, so a hart that
   * could not be woken spun forever. This window is a handful of instructions,
   * and SPIE is set below, so the thread still starts with interrupts enabled
   * -- user mode is not being masked here, only the kernel's last few
   * instructions before it. */
  csrci sstatus, 2

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
  .globl riscv64_sscratch_window_end
riscv64_sscratch_window_end:

/* Where a user thread comes back to, entered from the trap handler once it
   has decided the thread is finished. a0 carries the encoded result the
   scheduler expects. */
/* Leaving user mode for good.
 *
 * Entered from the trap stub with sp still pointing at the trap frame and a0
 * holding the encoded exit result, which is what xaios_enter_user returns.
 * The kernel stack that entered user mode is exactly one frame above the
 * frame -- the stub subtracted that much from the value sscratch held -- so
 * unwinding is arithmetic rather than another saved pointer.
 */
  .globl riscv64_return_from_user_exit
  .type riscv64_return_from_user_exit, @function
riscv64_return_from_user_exit:
  /* The kernel resumes with interrupts enabled, and with sscratch cleared.
   *
   * Both are missing from a bare `ret`, and both were measured the same way.
   * A trap from user mode clears `sstatus.SIE` and the *normal* return restores
   * it from the frame on the way out through `sret` -- but this path leaves
   * through `ret`, so the kernel continuation it returns into ran with
   * interrupts off for the rest of its life. Nothing notices while that
   * continuation is a few instructions from a `timer_disable()`, which is why
   * it survived; it stopped a scheduled user task dead, because the context
   * waiting to be handed the CPU back never got another tick.
   *
   * `sscratch` is the same class of state: the swap that brought the kernel
   * back left the *user* stack pointer in it, and the next trap entry reads a
   * non-zero sscratch as "this trap came from user mode" -- the misread
   * `B-108` was about -- so it would have pushed its frame onto a user address.
   */
  li    t0, 0x2             /* SIE */
  csrs  sstatus, t0
  csrw  sscratch, zero
  addi  sp, sp, TRAP_FRAME_BYTES
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
  .size xaios_enter_user_thread, . - xaios_enter_user_thread

/* The other user entry, taking argc and argv rather than a single argument.
   Two entry points exist because processes and threads are started
   differently; the mechanism is identical, so this forwards rather than
   duplicating the register dance above. */
  .globl xaios_enter_user
  .type xaios_enter_user, @function
xaios_enter_user:
  /* a0 entry, a1 stack, a2 argc, a3 argv -> entry, stack, argument=argc,
     return=argv is wrong; a process returns through its own exit syscall, so
     the return address is not used and argv goes in a1 of the user frame.
     Passing argc as the argument and leaving argv where the ABI puts a second
     parameter keeps the same convention userspace already expects. */
  /* Its own return address, saved -- which it was not.
   *
   * `call` puts the return address in ra, and xaios_enter_user_thread
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
  call  xaios_enter_user_thread
  ld    ra, 0(sp)
  addi  sp, sp, 16
  ret
  .size xaios_enter_user, . - xaios_enter_user

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
