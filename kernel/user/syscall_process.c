/*
 * The process syscall family. See syscall_family.h.
 *
 * Lifted out of syscall_dispatch in syscall.c, whose blocks for these
 * numbers are reproduced here verbatim: same guards, same order, same
 * error reasons.
 */

#include <xaios/agent_protocol.h>
#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/boot_ui.h>
#include <xaios/child_channel.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/control_protocol.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/initramfs.h>
#include <xaios/ipv4.h>
#include <xaios/network_config.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/local_ports.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/net_device.h>
#include <xaios/network_stack.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/socket_buffer.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>

#include "syscall_internal.h"
#include "syscall_table.h"
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/user.h>
#include <xaios/vfs.h>
#include <xaios/vmm.h>
#include "syscall_family.h"

uint64_t syscall_process(uint64_t syscall, uint64_t arg0,
                                                         uint64_t arg1, uint64_t arg2) {
  (void)arg2;

  if (syscall == XAIOS_SYSCALL_EXIT) {
    const xaios_user_process_t *process = user_current_process();
    const char *name = process != 0 && process->name != 0 ? process->name : "";
    if (service_exit(name, (int)arg0) != XAIOS_OK) {
      klog("user: %s exit without service record status=%u\n",
           name, (unsigned)arg0);
    }
    user_process_note_syscall(0);
    klog("user: %s exited status=%u syscalls=%lu rejected=%lu\n",
         name, (unsigned)arg0, process != 0 ? process->syscall_count : 0,
         process != 0 ? process->rejected_syscall_count : 0);
    return user_process_note_exit((int)arg0);
  }

  if (syscall == XAIOS_SYSCALL_SMP_RUN) {
    xaios_syscall_smp_request_t request;
    uint64_t ran_workers = 0;
    uint64_t checksum = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-smp-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_workers, sizeof(ran_workers),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_checksum, sizeof(checksum),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "smp-run-denied");
    }
    if (smp_run_user_task_set(request.worker_count, request.iterations,
                              &ran_workers, &checksum) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "smp-run-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_workers, &ran_workers,
               sizeof(ran_workers));
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_checksum, &checksum,
               sizeof(checksum));
    return syscall_dispatch_complete(ran_workers);
  }

  if (syscall == XAIOS_SYSCALL_THREAD_GROUP_RUN) {
    xaios_syscall_thread_group_request_t request;
    uint64_t ran_threads = 0;
    uint64_t checksum = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-thread-group-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_threads, sizeof(ran_threads),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_checksum, sizeof(checksum),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-group-denied");
    }
    if (smp_run_user_thread_group(request.thread_count, request.iterations,
                                  &ran_threads, &checksum) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-group-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_threads, &ran_threads,
               sizeof(ran_threads));
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_checksum, &checksum,
               sizeof(checksum));
    return syscall_dispatch_complete(ran_threads);
  }

  if (syscall == XAIOS_SYSCALL_THREAD_CREATE) {
    xaios_syscall_thread_create_request_t request;
    uint64_t thread_id = 0U;
    const xaios_user_process_t *process = user_current_process();
    if (arg1 != sizeof(request) || process == 0 ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-thread-create-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    xaios_status_t entry_status =
        vmm_validate_user_buffer(request.entry, 4U, XAIOS_VMM_EXECUTABLE);
    xaios_status_t return_status = vmm_validate_user_buffer(
        request.return_address, 4U, XAIOS_VMM_EXECUTABLE);
    xaios_status_t stack_status = vmm_validate_user_buffer(
        request.stack, request.stack_size, XAIOS_VMM_WRITABLE);
    xaios_status_t output_status = vmm_validate_user_buffer(
        request.out_thread_id, sizeof(thread_id), XAIOS_VMM_WRITABLE);
    if (request.stack_size < 4096U || request.stack_size > 1048576U ||
        request.stack + request.stack_size < request.stack ||
        request.out_thread_id == 0U ||
        entry_status != XAIOS_OK || return_status != XAIOS_OK ||
        stack_status != XAIOS_OK || output_status != XAIOS_OK ||
        (request.preferred_cpu != UINT64_MAX &&
         request.preferred_cpu > UINT32_MAX)) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-create-denied");
    }
    uint64_t stack_top =
        (request.stack + request.stack_size) & ~UINT64_C(15);
    uint32_t preferred = request.preferred_cpu == UINT64_MAX
                             ? XAIOS_THREAD_CPU_ANY
                             : (uint32_t)request.preferred_cpu;
    if (stack_top <= request.stack ||
        xaios_user_thread_create(request.entry, request.argument, stack_top,
                                 request.return_address, preferred,
                                 process->pid, &thread_id) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-create-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_thread_id, &thread_id,
               sizeof(thread_id));
    user_process_note_syscall(0);
    return thread_id;
  }

  if (syscall == XAIOS_SYSCALL_THREAD_JOIN) {
    xaios_syscall_thread_join_request_t request;
    uint64_t result = 0U;
    const xaios_user_process_t *process = user_current_process();
    if (arg1 != sizeof(request) || process == 0 ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-thread-join-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.timeout_ns > UINT64_C(60000000000) ||
        vmm_validate_user_buffer(request.out_result, sizeof(result),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        xaios_user_thread_join(request.thread_id, process->pid,
                               request.timeout_ns, &result) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-join-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_result, &result, sizeof(result));
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_THREAD_CANCEL) {
    const xaios_user_process_t *process = user_current_process();
    if (process == 0 ||
        xaios_user_thread_cancel(arg0, process->pid) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-cancel-failed");
    }
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_THREAD_EXIT) {
    user_process_note_syscall(0);
    uint64_t encoded = xaios_user_thread_exit(arg0);
    if (encoded == UINT64_MAX) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "thread-exit-outside-thread");
    }
    return encoded;
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
