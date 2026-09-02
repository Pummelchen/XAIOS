/* The scheduled child process, for RISC-V.
 *
 * The same program as worker.S, in the calling convention this architecture
 * uses: the syscall number in a7, arguments from a0, and ecall in place of
 * svc. The one thing that does not translate is the idle loop -- AArch64's
 * wfe is permitted in EL0, and RISC-V's wfi traps from user mode, so a
 * process that has said everything it has to say simply spins.
 */
.section .text, "ax"
.global _start
.type _start, %function

_start:
  la    a0, msg_start
  la    a1, msg_start_end
  sub   a1, a1, a0
  li    a7, 1
  ecall
  li    t0, -1
  beq   a0, t0, failed

  li    a0, 0
  li    a7, 2
  ecall

1:
  j     1b

failed:
  li    a0, 1
  li    a7, 2
  ecall
  j     1b

.section .rodata, "a"
msg_start:
  .ascii "/worker: scheduled child process ran\n"
msg_start_end:
