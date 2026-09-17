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
  /* Bytes the trap stub reserves for one frame, and where the floating-point
     state lives inside it. The field offsets are the C view in
     `riscv64_trap_frame_t`; this constant is the stub's, and it is 560 rather
     than 552 because the psABI wants sp 16-byte aligned at the trap and the
     eight bytes of padding are cheaper than an unaligned stack. */
  .equ  TRAP_FRAME_BYTES, 560
  .equ  TRAP_FRAME_FP, 288
  .equ  TRAP_FRAME_FCSR, 544
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
  addi  sp, sp, -TRAP_FRAME_BYTES
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

  /* The floating-point state, saved with the rest of the context because a
     switched-to task has to resume with *its* floating-point registers.
   *
   * The unit is switched on for the duration of this stub first: `sstatus.FS`
   * can be Off, and an `fsd` executed then is an illegal instruction taken
   * inside the trap entry, which is a trap in a trap. The frame keeps the
   * interrupted `sstatus` untouched, so a context that was not using the unit
   * resumes with it still off, and the restore below is skipped for it. */
  csrr  t0, sstatus
  li    t1, 0x2000          /* FS = Initial */
  csrs  sstatus, t1
  frcsr t0
  sd    t0, TRAP_FRAME_FCSR(sp)
  fsd   f0, TRAP_FRAME_FP+0(sp)
  fsd   f1, TRAP_FRAME_FP+8(sp)
  fsd   f2, TRAP_FRAME_FP+16(sp)
  fsd   f3, TRAP_FRAME_FP+24(sp)
  fsd   f4, TRAP_FRAME_FP+32(sp)
  fsd   f5, TRAP_FRAME_FP+40(sp)
  fsd   f6, TRAP_FRAME_FP+48(sp)
  fsd   f7, TRAP_FRAME_FP+56(sp)
  fsd   f8, TRAP_FRAME_FP+64(sp)
  fsd   f9, TRAP_FRAME_FP+72(sp)
  fsd   f10, TRAP_FRAME_FP+80(sp)
  fsd   f11, TRAP_FRAME_FP+88(sp)
  fsd   f12, TRAP_FRAME_FP+96(sp)
  fsd   f13, TRAP_FRAME_FP+104(sp)
  fsd   f14, TRAP_FRAME_FP+112(sp)
  fsd   f15, TRAP_FRAME_FP+120(sp)
  fsd   f16, TRAP_FRAME_FP+128(sp)
  fsd   f17, TRAP_FRAME_FP+136(sp)
  fsd   f18, TRAP_FRAME_FP+144(sp)
  fsd   f19, TRAP_FRAME_FP+152(sp)
  fsd   f20, TRAP_FRAME_FP+160(sp)
  fsd   f21, TRAP_FRAME_FP+168(sp)
  fsd   f22, TRAP_FRAME_FP+176(sp)
  fsd   f23, TRAP_FRAME_FP+184(sp)
  fsd   f24, TRAP_FRAME_FP+192(sp)
  fsd   f25, TRAP_FRAME_FP+200(sp)
  fsd   f26, TRAP_FRAME_FP+208(sp)
  fsd   f27, TRAP_FRAME_FP+216(sp)
  fsd   f28, TRAP_FRAME_FP+224(sp)
  fsd   f29, TRAP_FRAME_FP+232(sp)
  fsd   f30, TRAP_FRAME_FP+240(sp)
  fsd   f31, TRAP_FRAME_FP+248(sp)

  /* The interrupted stack pointer, which is in sscratch for a trap from user
     mode and is this stack for one from the kernel. */
  csrr  t0, sscratch
  bnez  t0, 2f
  addi  t0, sp, TRAP_FRAME_BYTES
2:
  sd    t0, 8(sp)
  /* And the stack this context's *next* trap from user mode must land on, which
     is the frame's own top either way: for a trap from user mode that is the
     kernel stack sscratch held, and for one from the kernel it is the stack the
     kernel is already on. Kept in the frame because a context switch has to
     re-arm sscratch from the incoming task's value, not the outgoing one's
     (`B-132`); see the epilogue below. */
  addi  t0, sp, TRAP_FRAME_BYTES
  sd    t0, 280(sp)
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
     the second call rather than the first.
   *
   * It is read from the frame rather than computed from this sp, because a
   * scheduler tick may have replaced the frame with the task it chose: the
   * stack this trap was taken on then belongs to the task being left, and
   * arming sscratch with it would send the *incoming* task's next syscall onto
   * the outgoing task's stack, where it would unwind that task's continuation
   * with its own exit code (B-132). The entry wrote this frame's own top there,
   * so a machine that never switches behaves exactly as it did before. */
  li    t1, 0x100
  and   t1, t0, t1
  bnez  t1, 3f
  ld    t1, 280(sp)
  bnez  t1, 4f
  addi  t1, sp, TRAP_FRAME_BYTES
4:
  csrw  sscratch, t1
3:
  /* The floating-point registers of whichever context this frame describes,
     skipped for a context that had the unit off -- its frame's values are not
     live, and an `fld` with FS off is the same illegal instruction the save
     above avoids. `t0` still holds the restored `sstatus`. */
  li    t1, 0x6000          /* FS mask */
  and   t1, t0, t1
  beqz  t1, 5f
  ld    t0, TRAP_FRAME_FCSR(sp)
  csrw  fcsr, t0
  fld   f0, TRAP_FRAME_FP+0(sp)
  fld   f1, TRAP_FRAME_FP+8(sp)
  fld   f2, TRAP_FRAME_FP+16(sp)
  fld   f3, TRAP_FRAME_FP+24(sp)
  fld   f4, TRAP_FRAME_FP+32(sp)
  fld   f5, TRAP_FRAME_FP+40(sp)
  fld   f6, TRAP_FRAME_FP+48(sp)
  fld   f7, TRAP_FRAME_FP+56(sp)
  fld   f8, TRAP_FRAME_FP+64(sp)
  fld   f9, TRAP_FRAME_FP+72(sp)
  fld   f10, TRAP_FRAME_FP+80(sp)
  fld   f11, TRAP_FRAME_FP+88(sp)
  fld   f12, TRAP_FRAME_FP+96(sp)
  fld   f13, TRAP_FRAME_FP+104(sp)
  fld   f14, TRAP_FRAME_FP+112(sp)
  fld   f15, TRAP_FRAME_FP+120(sp)
  fld   f16, TRAP_FRAME_FP+128(sp)
  fld   f17, TRAP_FRAME_FP+136(sp)
  fld   f18, TRAP_FRAME_FP+144(sp)
  fld   f19, TRAP_FRAME_FP+152(sp)
  fld   f20, TRAP_FRAME_FP+160(sp)
  fld   f21, TRAP_FRAME_FP+168(sp)
  fld   f22, TRAP_FRAME_FP+176(sp)
  fld   f23, TRAP_FRAME_FP+184(sp)
  fld   f24, TRAP_FRAME_FP+192(sp)
  fld   f25, TRAP_FRAME_FP+200(sp)
  fld   f26, TRAP_FRAME_FP+208(sp)
  fld   f27, TRAP_FRAME_FP+216(sp)
  fld   f28, TRAP_FRAME_FP+224(sp)
  fld   f29, TRAP_FRAME_FP+232(sp)
  fld   f30, TRAP_FRAME_FP+240(sp)
  fld   f31, TRAP_FRAME_FP+248(sp)
5:
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

/* The port's other entry points -- the SIMD/FP canary, the two user entry
   paths, the sscratch window, the user-exit return and the secondary hart
   entry -- live in entry_helpers.S beside this file, moved there so neither
   file exceeds the repository's source-size limit. They are the same globals
   this file has always exported; what stays here is the boot path, the boot
   lottery and the trap vector. That file's own header states the one piece
   of link layout the split depends on. */
