/*
 * The compute syscall family. See syscall_family.h.
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

static uint32_t g_cpu_ai_app_bound;

static xaios_status_t ensure_app_cpu_ai_binding(void) {
  if (g_cpu_ai_app_bound != 0) {
    return XAIOS_OK;
  }

  const xaios_arena_t *kv = 0;
  xaios_status_t status =
      arena_create(30, XAIOS_ARENA_KV_CACHE, 3, "cpu-ai-user-kv", 4096, 0,
                   &kv);
  if (status != XAIOS_OK || kv == 0) {
    return status;
  }
  status = cpu_ai_runtime_bind_model_with_kv(3, 2, kv->base, kv->size);
  if (status != XAIOS_OK) {
    (void)arena_destroy(30);
    return status;
  }
  g_cpu_ai_app_bound = 1;
  return XAIOS_OK;
}

uint64_t syscall_compute(uint64_t syscall, uint64_t arg0,
                                                         uint64_t arg1, uint64_t arg2) {
  (void)arg2;

  if (syscall == XAIOS_SYSCALL_CPU_AI_DECODE) {
    xaios_syscall_cpu_ai_decode_request_t request;
    uint8_t input[32];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-cpu-ai-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.input_size == 0 || request.input_size > sizeof(input) ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.input, request.input_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "cpu-ai-denied");
    }
    syscall_dispatch_bytes_copy(input, (const void *)(uintptr_t)request.input,
               request.input_size);
    xaios_status_t decode_status = cpu_ai_runtime_decode_piece(
        3, input, request.input_size, (char *)(uintptr_t)request.output,
        request.output_size, &out_size);
    if (decode_status == XAIOS_ERR_UNSUPPORTED) {
      klog("syscall: production CPU-AI decode is not implemented; fixture decode is available only through explicit ML fixture mode\n");
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      (void)syscall_dispatch_reject(syscall, arg0, arg1,
                           "cpu-ai-production-unsupported");
      return (uint64_t)(int64_t)XAIOS_ERR_UNSUPPORTED;
    }
    if (decode_status != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "cpu-ai-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return syscall_dispatch_complete(out_size);
  }

  if (syscall == XAIOS_SYSCALL_ML_RUN) {
    xaios_syscall_ml_run_request_t request;
    uint8_t input[64];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-ml-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.input_size == 0 || request.input_size > sizeof(input) ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.input, request.input_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "ml-run-denied");
    }
    syscall_dispatch_bytes_copy(input, (const void *)(uintptr_t)request.input,
               request.input_size);
    if (ensure_app_cpu_ai_binding() != XAIOS_OK ||
        cpu_ai_runtime_run_model(3, request.model_kind, input,
                                 request.input_size,
                                 (char *)(uintptr_t)request.output,
                                 request.output_size, &out_size) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "ml-run-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return syscall_dispatch_complete(out_size);
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
