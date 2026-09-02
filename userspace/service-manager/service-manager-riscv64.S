/* The service manager, for RISC-V.
 *
 * A mechanical translation of service-manager.S. The syscall number moves
 * from x8 to a7 and arguments from x0-x2 to a0-a2; svc becomes ecall; adr
 * becomes la, which the assembler expands to a pc-relative pair; and the
 * cmn/b.eq idiom for "did that call return -1" becomes an explicit compare
 * against -1, because RISC-V has no condition flags to set.
 *
 * x19 is AArch64's first callee-saved scratch and s1 is this architecture's.
 * That it survives a syscall is not an assumption: the trap frame saves and
 * restores every register, so a value left in s1 across an ecall comes back.
 */
.section .text, "ax"
.global _start
.type _start, %function

_start:
  la    a0, msg_hello
  li    a1, 33
  li    a7, 1
  ecall

  la    a0, descriptor_buffer
  li    a1, 256
  li    a7, 4
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, msg_descriptor_loaded
  li    a1, 36
  li    a7, 1
  ecall

  la    a0, service_init
  li    a1, 5
  li    a7, 9
  ecall
  li    t0, -1
  bne   a0, t0, manager_failed

  la    a0, update_signature
  li    a1, 18
  li    a7, 10
  ecall
  li    t0, -1
  bne   a0, t0, manager_failed

  la    a0, msg_missing_caps
  li    a1, 50
  li    a7, 1
  ecall

  la    a0, cmd_define_child
  li    a1, 59
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, service_child
  li    a1, 17
  li    a7, 6
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, service_child
  li    a1, 17
  li    a7, 5
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, service_child
  li    a1, 17
  li    a7, 8
  ecall
  li    t0, -1
  bne   a0, t0, manager_failed

  la    a0, msg_child_supervised
  li    a1, 43
  li    a7, 1
  ecall

  la    a0, cmd_configure_child
  li    a1, 76
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_log_child
  li    a1, 40
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_crash_child
  li    a1, 38
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, service_child
  li    a1, 17
  li    a7, 5
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, msg_child_crash_supervised
  li    a1, 41
  li    a7, 1
  ecall

  la    a0, cmd_admin_policy
  li    a1, 12
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_admin_status_child
  li    a1, 30
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_admin_export_child
  li    a1, 30
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_admin_logs_child
  li    a1, 28
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, msg_admin_ready
  li    a1, 40
  li    a7, 1
  ecall

  la    a0, cmd_admin_safe_status
  li    a1, 24
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_admin_safe_shell
  li    a1, 23
  li    a7, 3
  ecall
  li    t0, -1
  bne   a0, t0, manager_failed

  la    a0, msg_admin_safe
  li    a1, 44
  li    a7, 1
  ecall

  la    a0, cmd_osctl_status
  la    a1, cmd_osctl_status_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_ps
  la    a1, cmd_osctl_ps_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_services
  la    a1, cmd_osctl_services_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_cells
  la    a1, cmd_osctl_cells_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_fs
  la    a1, cmd_osctl_fs_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_net
  la    a1, cmd_osctl_net_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_telemetry
  la    a1, cmd_osctl_telemetry_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_update
  la    a1, cmd_osctl_update_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, cmd_osctl_rollback
  la    a1, cmd_osctl_rollback_end
  sub   a1, a1, a0
  li    a7, 3
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, msg_osctl_ready
  la    a1, msg_osctl_ready_end
  sub   a1, a1, a0
  li    a7, 1
  ecall

  la    a0, fs_path
  la    a1, fs_path_end
  sub   a1, a1, a0
  li    a2, 7
  li    a7, 11
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed
  mv    s1, a0

  mv    a0, s1
  la    a1, fs_payload
  la    a2, fs_payload_end
  sub   a2, a2, a1
  li    a7, 13
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  mv    a0, s1
  li    a7, 14
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, fs_path
  la    a1, fs_path_end
  sub   a1, a1, a0
  li    a2, 1
  li    a7, 11
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed
  mv    s1, a0

  mv    a0, s1
  la    a1, fs_buffer
  li    a2, 64
  li    a7, 12
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  mv    a0, s1
  li    a7, 14
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, fs_path
  la    a1, fs_path_end
  sub   a1, a1, a0
  la    a2, fs_stat
  li    a7, 15
  ecall
  li    t0, -1
  beq   a0, t0, manager_failed

  la    a0, msg_fs_ready
  la    a1, msg_fs_ready_end
  sub   a1, a1, a0
  li    a7, 1
  ecall

  la    a0, msg_done
  li    a1, 41
  li    a7, 1
  ecall

  li    a0, 0
  li    a7, 2
  ecall

1:
  j     1b

manager_failed:
  la    a0, msg_failed
  li    a1, 33
  li    a7, 1
  ecall
  li    a0, 1
  li    a7, 2
  ecall
  j     1b

.section .rodata, "a"
msg_hello:
  .ascii "/service-manager: hello from ELF\n"
msg_descriptor_loaded:
  .ascii "/service-manager: descriptor loaded\n"
msg_missing_caps:
  .ascii "/service-manager: missing capability tests passed\n"
msg_child_supervised:
  .ascii "/service-manager: child service supervised\n"
msg_child_crash_supervised:
  .ascii "/service-manager: child crash supervised\n"
msg_admin_ready:
  .ascii "/service-manager: admin status exported\n"
msg_admin_safe:
  .ascii "/service-manager: remote-safe checks passed\n"
msg_osctl_ready:
  .ascii "/service-manager: osctl command surface passed\n"
msg_osctl_ready_end:
msg_fs_ready:
  .ascii "/service-manager: mutable fs syscalls passed\n"
msg_fs_ready_end:
msg_done:
  .ascii "/service-manager: control plane complete\n"
msg_failed:
  .ascii "/service-manager: control failed\n"
cmd_define_child:
  .ascii "service define /svc/source-index parent=/init restart=never"
cmd_configure_child:
  .ascii "service configure /svc/source-index restart=always log=serial max_restarts=2"
cmd_log_child:
  .ascii "service log /svc/source-index crash-test"
cmd_crash_child:
  .ascii "service crash /svc/source-index code=7"
cmd_admin_policy:
  .ascii "admin policy"
cmd_admin_status_child:
  .ascii "admin status /svc/source-index"
cmd_admin_export_child:
  .ascii "admin export /svc/source-index"
cmd_admin_logs_child:
  .ascii "admin logs /svc/source-index"
cmd_admin_safe_status:
  .ascii "admin remote-safe status"
cmd_admin_safe_shell:
  .ascii "admin remote-safe shell"
cmd_osctl_status:
  .ascii "osctl status"
cmd_osctl_status_end:
cmd_osctl_ps:
  .ascii "osctl ps"
cmd_osctl_ps_end:
cmd_osctl_services:
  .ascii "osctl services"
cmd_osctl_services_end:
cmd_osctl_cells:
  .ascii "osctl cells"
cmd_osctl_cells_end:
cmd_osctl_fs:
  .ascii "osctl fs"
cmd_osctl_fs_end:
cmd_osctl_net:
  .ascii "osctl net"
cmd_osctl_net_end:
cmd_osctl_telemetry:
  .ascii "osctl telemetry"
cmd_osctl_telemetry_end:
cmd_osctl_update:
  .ascii "osctl update"
cmd_osctl_update_end:
cmd_osctl_rollback:
  .ascii "osctl rollback"
cmd_osctl_rollback_end:
fs_path:
  .ascii "/logs/el0-fs.log"
fs_path_end:
fs_payload:
  .ascii "el0-fs=syscall-ok\n"
fs_payload_end:
service_child:
  .ascii "/svc/source-index"
service_init:
  .ascii "/init"
update_signature:
  .ascii "signed-update-test"

.section .bss, "aw", %nobits
.balign 16
descriptor_buffer:
  .skip 256
fs_buffer:
  .skip 128
fs_stat:
  .skip 32
