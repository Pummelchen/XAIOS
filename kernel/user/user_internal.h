/*
 * Private declarations shared by kernel/user/user.c and the two modules it
 * was split into, user_process.c and user_runtime.c.
 *
 * Nothing here crosses the public API in <xaios/user.h>. The globals are
 * defined once, in user_process.c, and declared here. The helpers below are
 * `static inline`: they carry no state of their own, and inlining them is what
 * keeps the three translation units inside the file-size budget rather than
 * repeating them or exporting generic names such as `bytes_zero`.
 *
 * The include set is the one user.c itself carried, kept here so the three
 * translation units agree on it rather than each re-deriving a subset.
 */

#ifndef XAIOS_KERNEL_USER_USER_INTERNAL_H
#define XAIOS_KERNEL_USER_USER_INTERNAL_H

#include <xaios/assert.h>
#include <xaios/arch_cpu.h>
#include <xaios/context.h>
#include <xaios/elf_loader.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/user.h>
#include <xaios/vmm.h>

#define PAGE_SIZE UINT64_C(4096)
#define USER_STACK_PAGES UINT64_C(64)
/* The first pid a transient process may take; below it are the fixed
   processes. */
#define XAIOS_TRANSIENT_PID_FIRST 32U

/* The process table and its per-CPU current-process bindings, defined in
   user_process.c. */
extern xaios_user_process_t g_user_process_table[XAIOS_MAX_USER_PROCESSES];
extern xaios_user_process_t **g_user_current_process_by_cpu;
extern uint32_t g_user_current_process_capacity;
extern xaios_user_process_t *g_user_boot_current_process;

/* The lifecycle and scheduling totals, defined in user_process.c and read by
   the statistics getters in user_runtime.c. */
extern uint64_t g_user_process_transition_count;
extern uint64_t g_user_process_loaded_count;
extern uint64_t g_user_process_runnable_count;
extern uint64_t g_user_process_running_count;
extern uint64_t g_user_process_waiting_count;
extern uint64_t g_user_process_exited_count;
extern uint64_t g_user_process_failed_count;
extern uint64_t g_user_process_reclaim_count;
extern uint64_t g_user_process_scheduled_count;
extern uint64_t g_user_process_wait_count;
extern uint64_t g_user_process_wake_count;

static inline void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static inline void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static inline void copy_process(xaios_user_process_t *dst,
                                const xaios_user_process_t *src) {
  dst->pid = src->pid;
  dst->owner_token = src->owner_token;
  dst->parent_pid = src->parent_pid;
  dst->name = src->name;
  dst->state = src->state;
  dst->exit_code = src->exit_code;
  dst->capability_mask = src->capability_mask;
  dst->syscall_count = src->syscall_count;
  dst->rejected_syscall_count = src->rejected_syscall_count;
  dst->entry = src->entry;
  dst->stack_top = src->stack_top;
  dst->argv_user = src->argv_user;
  dst->argc = src->argc;
  dst->reserved_args = src->reserved_args;
  dst->stack_guard_low = src->stack_guard_low;
  dst->stack_guard_high = src->stack_guard_high;
  dst->mapped_low = src->mapped_low;
  dst->mapped_high = src->mapped_high;
  dst->scheduler_ticks = src->scheduler_ticks;
  dst->started_ns = src->started_ns;
  dst->runtime_ns = src->runtime_ns;
  dst->running_since_ns = src->running_since_ns;
  dst->resident_pages = src->resident_pages;
  dst->running_cpu_id = src->running_cpu_id;
  dst->runtime_sequence = src->runtime_sequence;
  bytes_copy(&dst->aspace, &src->aspace, sizeof(xaios_process_aspace_t));
}

static inline const char *process_state_name(xaios_user_process_state_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_EMPTY:
    return "empty";
  case XAIOS_USER_PROCESS_LOADED:
    return "loaded";
  case XAIOS_USER_PROCESS_RUNNABLE:
    return "runnable";
  case XAIOS_USER_PROCESS_RUNNING:
    return "running";
  case XAIOS_USER_PROCESS_WAITING:
    return "waiting";
  case XAIOS_USER_PROCESS_EXITED:
    return "exited";
  case XAIOS_USER_PROCESS_FAILED:
    return "failed";
  default:
    return "unknown";
  }
}

/* The per-CPU binding slot, and the lvalue the three units assign through.
 *
 * This is the file-scope helper user.c already had, unchanged apart from
 * living here: the pointer it returns is the table entry (or the boot
 * fallback) itself, so it may be used for the duration of a call and assigned
 * through, never as a scratch buffer. */
static inline xaios_user_process_t **current_process_slot(void) {
  uint32_t cpu_id = smp_cpu_id();
  if (g_user_current_process_by_cpu != 0 &&
      cpu_id < g_user_current_process_capacity) {
    return &g_user_current_process_by_cpu[cpu_id];
  }
  return &g_user_boot_current_process;
}

#define g_current_process (*current_process_slot())

/* The three helpers that now cross a translation unit. */
void user_process_transition(xaios_user_process_t *process,
                             xaios_user_process_state_t state, int exit_code);
void user_process_reset_slot(xaios_user_process_t *process);
uint32_t user_process_next_owner_token(void);
void user_cpu_usage_init(void);

#endif /* XAIOS_KERNEL_USER_USER_INTERNAL_H */
