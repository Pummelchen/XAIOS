.section .text, "ax"
.global _start
.type _start, @function

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
  cmpq $-1, %rax
  je manager_failed
.endm

.macro service_call number, label
  leaq \label(%rip), %rdi
  movq $(\label\()_end-\label), %rsi
  xorq %rdx, %rdx
  movq $\number, %rax
  int $0x80
.endm

_start:
  log_message msg_hello

  leaq descriptor_buffer(%rip), %rdi
  movq $256, %rsi
  xorq %rdx, %rdx
  movq $4, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed
  log_message msg_descriptor_loaded

  service_call 9, service_init
  cmpq $-1, %rax
  jne manager_failed
  service_call 10, update_signature
  cmpq $-1, %rax
  jne manager_failed
  log_message msg_missing_caps

  osctl cmd_define_child
  service_call 6, service_child
  cmpq $-1, %rax
  je manager_failed
  service_call 5, service_child
  cmpq $-1, %rax
  je manager_failed
  service_call 8, service_child
  cmpq $-1, %rax
  jne manager_failed
  log_message msg_child_supervised

  osctl cmd_configure_child
  osctl cmd_log_child
  osctl cmd_crash_child
  service_call 5, service_child
  cmpq $-1, %rax
  je manager_failed
  log_message msg_child_crash_supervised

  osctl cmd_admin_policy
  osctl cmd_admin_status_child
  osctl cmd_admin_export_child
  osctl cmd_admin_logs_child
  log_message msg_admin_ready
  osctl cmd_admin_safe_status
  leaq cmd_admin_safe_shell(%rip), %rdi
  movq $(cmd_admin_safe_shell_end-cmd_admin_safe_shell), %rsi
  xorq %rdx, %rdx
  movq $3, %rax
  int $0x80
  cmpq $-1, %rax
  jne manager_failed
  log_message msg_admin_safe

  osctl cmd_osctl_status
  osctl cmd_osctl_ps
  osctl cmd_osctl_services
  osctl cmd_osctl_cells
  osctl cmd_osctl_fs
  osctl cmd_osctl_net
  osctl cmd_osctl_telemetry
  osctl cmd_osctl_update
  osctl cmd_osctl_rollback
  log_message msg_osctl_ready

  leaq fs_path(%rip), %rdi
  movq $(fs_path_end-fs_path), %rsi
  movq $7, %rdx
  movq $11, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed
  movq %rax, %r12

  movq %r12, %rdi
  leaq fs_payload(%rip), %rsi
  movq $(fs_payload_end-fs_payload), %rdx
  movq $13, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed
  movq %r12, %rdi
  movq $14, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed

  leaq fs_path(%rip), %rdi
  movq $(fs_path_end-fs_path), %rsi
  movq $1, %rdx
  movq $11, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed
  movq %rax, %r12
  movq %r12, %rdi
  leaq fs_buffer(%rip), %rsi
  movq $64, %rdx
  movq $12, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed
  movq %r12, %rdi
  movq $14, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed

  leaq fs_path(%rip), %rdi
  movq $(fs_path_end-fs_path), %rsi
  leaq fs_stat(%rip), %rdx
  movq $15, %rax
  int $0x80
  cmpq $-1, %rax
  je manager_failed
  log_message msg_fs_ready
  log_message msg_done
  xorq %rdi, %rdi
  movq $2, %rax
  int $0x80
1:
  pause
  jmp 1b

manager_failed:
  log_message msg_failed
  movq $1, %rdi
  movq $2, %rax
  int $0x80
  jmp 1b

.section .rodata, "a"
msg_hello: .ascii "/service-manager: hello from ELF\n"
msg_hello_end:
msg_descriptor_loaded: .ascii "/service-manager: descriptor loaded\n"
msg_descriptor_loaded_end:
msg_missing_caps: .ascii "/service-manager: missing capability tests passed\n"
msg_missing_caps_end:
msg_child_supervised: .ascii "/service-manager: child service supervised\n"
msg_child_supervised_end:
msg_child_crash_supervised: .ascii "/service-manager: child crash supervised\n"
msg_child_crash_supervised_end:
msg_admin_ready: .ascii "/service-manager: admin status exported\n"
msg_admin_ready_end:
msg_admin_safe: .ascii "/service-manager: remote-safe checks passed\n"
msg_admin_safe_end:
msg_osctl_ready: .ascii "/service-manager: osctl command surface passed\n"
msg_osctl_ready_end:
msg_fs_ready: .ascii "/service-manager: mutable fs syscalls passed\n"
msg_fs_ready_end:
msg_done: .ascii "/service-manager: control plane complete\n"
msg_done_end:
msg_failed: .ascii "/service-manager: control failed\n"
msg_failed_end:
cmd_define_child: .ascii "service define /svc/source-index parent=/init restart=never"
cmd_define_child_end:
cmd_configure_child: .ascii "service configure /svc/source-index restart=always log=serial max_restarts=2"
cmd_configure_child_end:
cmd_log_child: .ascii "service log /svc/source-index crash-test"
cmd_log_child_end:
cmd_crash_child: .ascii "service crash /svc/source-index code=7"
cmd_crash_child_end:
cmd_admin_policy: .ascii "admin policy"
cmd_admin_policy_end:
cmd_admin_status_child: .ascii "admin status /svc/source-index"
cmd_admin_status_child_end:
cmd_admin_export_child: .ascii "admin export /svc/source-index"
cmd_admin_export_child_end:
cmd_admin_logs_child: .ascii "admin logs /svc/source-index"
cmd_admin_logs_child_end:
cmd_admin_safe_status: .ascii "admin remote-safe status"
cmd_admin_safe_status_end:
cmd_admin_safe_shell: .ascii "admin remote-safe shell"
cmd_admin_safe_shell_end:
cmd_osctl_status: .ascii "osctl status"
cmd_osctl_status_end:
cmd_osctl_ps: .ascii "osctl ps"
cmd_osctl_ps_end:
cmd_osctl_services: .ascii "osctl services"
cmd_osctl_services_end:
cmd_osctl_cells: .ascii "osctl cells"
cmd_osctl_cells_end:
cmd_osctl_fs: .ascii "osctl fs"
cmd_osctl_fs_end:
cmd_osctl_net: .ascii "osctl net"
cmd_osctl_net_end:
cmd_osctl_telemetry: .ascii "osctl telemetry"
cmd_osctl_telemetry_end:
cmd_osctl_update: .ascii "osctl update"
cmd_osctl_update_end:
cmd_osctl_rollback: .ascii "osctl rollback"
cmd_osctl_rollback_end:
fs_path: .ascii "/logs/el0-fs.log"
fs_path_end:
fs_payload: .ascii "el0-fs=syscall-ok\n"
fs_payload_end:
service_child: .ascii "/svc/source-index"
service_child_end:
service_init: .ascii "/init"
service_init_end:
update_signature: .ascii "signed-update-test"
update_signature_end:

.section .bss, "aw", @nobits
.balign 16
descriptor_buffer: .skip 256
fs_buffer: .skip 128
fs_stat: .skip 32
