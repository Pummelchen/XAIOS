.section .text, "ax"
.global _start
.type _start, @function

.macro syscall3 number, arg0, arg1, arg2
  movq \arg0, %rdi
  movq \arg1, %rsi
  movq \arg2, %rdx
  movq $\number, %rax
  int $0x80
.endm

.macro log_message label
  leaq \label(%rip), %rdi
  movq $(\label\()_end-\label), %rsi
  xorq %rdx, %rdx
  movq $1, %rax
  int $0x80
.endm

.macro osctl label
  leaq \label(%rip), %rdi
  movq $(\label\()_end-\label), %rsi
  xorq %rdx, %rdx
  movq $3, %rax
  int $0x80
.endm

_start:
  syscall3 99, $0, $0, $0
  cmpq $-1, %rax
  jne init_failed
  syscall3 1, $0, $8, $0
  cmpq $-1, %rax
  jne init_failed
  log_message msg_bad_syscalls
  log_message msg_start
  osctl cmd_configure
  osctl cmd_log_ready
  log_message msg_policy_ready
  osctl cmd_status
  osctl cmd_restart
  cmpq $-1, %rax
  jne manager_failed
  log_message msg_restart_denied
  osctl cmd_start
  osctl cmd_status
  log_message msg_done
  syscall3 2, $0, $0, $0
1:
  pause
  jmp 1b

init_failed:
  log_message msg_bad_failed
  syscall3 2, $1, $0, $0
  jmp 1b

manager_failed:
  log_message msg_manager_failed
  syscall3 2, $1, $0, $0
  jmp 1b

.section .rodata, "a"
msg_bad_syscalls: .ascii "/init: bad syscall tests passed\n"
msg_bad_syscalls_end:
msg_bad_failed: .ascii "/init: bad syscall tests failed\n"
msg_bad_failed_end:
msg_manager_failed: .ascii "/init: service manager policy failed\n"
msg_manager_failed_end:
msg_start: .ascii "/init: hello from ELF\n"
msg_start_end:
msg_policy_ready: .ascii "/init: service manager policy ready\n"
msg_policy_ready_end:
msg_restart_denied: .ascii "/init: restart denied by policy\n"
msg_restart_denied_end:
cmd_configure: .ascii "service configure /init restart=never log=serial max_restarts=0"
cmd_configure_end:
cmd_log_ready: .ascii "service log /init manager-ready"
cmd_log_ready_end:
cmd_restart: .ascii "service restart /init"
cmd_restart_end:
cmd_start: .ascii "service start /init"
cmd_start_end:
cmd_status: .ascii "service status /init"
cmd_status_end:
msg_done: .ascii "/init: service setup complete\n"
msg_done_end:
