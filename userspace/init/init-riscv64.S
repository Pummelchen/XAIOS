/* /init, for RISC-V.
 *
 * A line-for-line translation of init.S: the syscall number moves from x8 to
 * a7, arguments from x0/x1 to a0/a1, svc becomes ecall, and the "did this
 * return -1" check that AArch64 writes as cmn/b.ne becomes an explicit
 * comparison against -1. The message lengths are the same constants, because
 * they describe the same strings.
 *
 * The idle loops spin rather than waiting: wfi is a privileged instruction
 * here and would trap out of the process that executed it.
 */
.section .text, "ax"
.global _start
.type _start, %function

_start:
  li    a0, 0
  li    a1, 0
  li    a7, 99
  ecall
  li    t0, -1
  bne   a0, t0, bad_syscall_failed

  li    a0, 0
  li    a1, 8
  li    a7, 1
  ecall
  li    t0, -1
  bne   a0, t0, bad_syscall_failed

  la    a0, msg_bad_syscalls
  li    a1, 32
  li    a7, 1
  ecall

  la    a0, msg_start
  li    a1, 22
  li    a7, 1
  ecall

  la    a0, cmd_configure
  li    a1, 63
  li    a7, 3
  ecall

  la    a0, cmd_log_ready
  li    a1, 31
  li    a7, 3
  ecall

  la    a0, msg_policy_ready
  li    a1, 36
  li    a7, 1
  ecall

  la    a0, cmd_status
  li    a1, 20
  li    a7, 3
  ecall

  la    a0, cmd_restart
  li    a1, 21
  li    a7, 3
  ecall
  li    t0, -1
  bne   a0, t0, manager_policy_failed

  la    a0, msg_restart_denied
  li    a1, 32
  li    a7, 1
  ecall

  la    a0, cmd_start
  li    a1, 19
  li    a7, 3
  ecall

  la    a0, cmd_status
  li    a1, 20
  li    a7, 3
  ecall

  la    a0, msg_done
  li    a1, 30
  li    a7, 1
  ecall

  li    a0, 0
  li    a7, 2
  ecall

1:
  j     1b

bad_syscall_failed:
  la    a0, msg_bad_failed
  li    a1, 32
  li    a7, 1
  ecall
  li    a0, 1
  li    a7, 2
  ecall
  j     1b

manager_policy_failed:
  la    a0, msg_manager_failed
  li    a1, 36
  li    a7, 1
  ecall
  li    a0, 1
  li    a7, 2
  ecall
  j     1b

.section .rodata, "a"
msg_bad_syscalls:
  .ascii "/init: bad syscall tests passed\n"
msg_bad_failed:
  .ascii "/init: bad syscall tests failed\n"
msg_manager_failed:
  .ascii "/init: service manager policy failed\n"
msg_start:
  .ascii "/init: hello from ELF\n"
msg_policy_ready:
  .ascii "/init: service manager policy ready\n"
msg_restart_denied:
  .ascii "/init: restart denied by policy\n"
cmd_configure:
  .ascii "service configure /init restart=never log=serial max_restarts=0"
cmd_log_ready:
  .ascii "service log /init manager-ready"
cmd_restart:
  .ascii "service restart /init"
cmd_start:
  .ascii "service start /init"
cmd_status:
  .ascii "service status /init"
msg_done:
  .ascii "/init: service setup complete\n"
