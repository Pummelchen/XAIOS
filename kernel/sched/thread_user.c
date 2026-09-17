/* The user-thread path.
 *
 * Split out of thread.c, which was 824 lines. The per-CPU context slot, the
 * worker that enters user mode, the create that allocates and hands its
 * context to the table, the join and cancel gates (kernel and owner-checked
 * forms together, so the two never drift), the drain an exiting process runs
 * and the exit syscall all live here because they are the only readers and
 * writers of the per-CPU context slot.
 *
 * The thread-table state stays in thread.c and is named here through
 * thread_internal.h, so the order xaios_thread_runtime_init establishes --
 * table allocated first, then the per-CPU context array -- is unchanged, and
 * the release_context handoff on which the join depends still frees the
 * caller-owned context exactly once.
 */

#include "thread_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/vmm.h>

/* In the port's assembly, and named for the system rather than for the one
   port that had it first -- see kernel/arch/aarch64/entry.S (B-109). */
extern uint64_t xaios_enter_user_thread(uint64_t entry, uint64_t stack,
                                          uint64_t argument,
                                          uint64_t return_address);

/* The last exit this kernel serviced, for the B-02 diagnostic below: a worker
   whose own context was never marked needs to say which context was. */
static volatile uint64_t g_last_exit_context;
static volatile uint32_t g_last_exit_cpu = UINT32_MAX;
static volatile uint64_t g_last_exit_count;

static uint64_t user_thread_worker(void *opaque) {
  xaios_user_thread_context_t *context =
      (xaios_user_thread_context_t *)opaque;
  uint32_t cpu_id = smp_cpu_id();
  /* B-02. Five conditions here used to return the same UINT64_MAX, so a thread
     that failed told the joiner only that something went wrong -- which is why
     an intermittent failure under load has twice been recorded and twice gone
     unexplained. Each one now names itself. The cost is a klog on paths that
     already end in failure.
     A cpu_id of UINT32_MAX is the case to watch: smp_cpu_id() returns that
     when the running CPU cannot find itself among the online ones, which would
     mean a CPU executing a thread while its own state says it is not there. */
  if (context == 0) {
    klog("threads: worker abandoned; no context\n");
    return UINT64_MAX;
  }
  if (cpu_id >= g_current_user_thread_capacity) {
    klog("threads: worker abandoned; cpu_id=%u capacity=%u owner=%u\n", cpu_id,
         g_current_user_thread_capacity, context->owner_pid);
    return UINT64_MAX;
  }
  if (user_bind_current_process(context->owner_pid) != XAIOS_OK) {
    klog("threads: worker abandoned; cannot bind owner=%u on cpu=%u\n",
         context->owner_pid, cpu_id);
    return UINT64_MAX;
  }
  /* Save what this CPU was doing before borrowing it.

     A user process waiting in xaios_thread_join runs pending threads on its
     own CPU while it waits, so this worker can be entered from inside that
     process's syscall -- the CPU already has a current process bound and its
     address space active. Clearing to the kernel on the way out, which is
     what this did, left the outer syscall with no current process and the
     kernel's address space: every later capability check on it fails and
     every user pointer it touches resolves in the wrong space.

     That is B-02's shape. The failure needs a thread still pending when join
     runs, which is what a loaded host produces and why it was intermittent,
     and it lands on a later thread than the one that caused it, which is why
     it never pointed at itself. */
  const xaios_user_process_t *previous_process = user_current_process();
  uint32_t previous_pid = previous_process != 0 ? previous_process->pid : 0U;
  xaios_user_thread_context_t *previous_context =
      g_current_user_thread_by_cpu[cpu_id];

  user_switch_address_space(context->owner_pid);
  context->entry_cpu = cpu_id;
  context->exit_cpu = UINT32_MAX;
  g_current_user_thread_by_cpu[cpu_id] = context;
  uint64_t started_ns = timer_now_ns();
  user_thread_runtime_start(context->owner_pid, cpu_id, started_ns);
  uint64_t encoded = xaios_enter_user_thread(
      context->entry, context->stack_top, context->argument,
      context->return_address);
  user_thread_runtime_stop(context->owner_pid, cpu_id, started_ns,
                           timer_now_ns());
  /* Put back what was there rather than clearing, so a nested run is
     invisible to whatever was interrupted. */
  g_current_user_thread_by_cpu[cpu_id] = previous_context;
  if (previous_pid != 0U &&
      user_bind_current_process(previous_pid) == XAIOS_OK) {
    user_switch_address_space(previous_pid);
  } else {
    user_clear_current_process();
    vmm_activate_kernel();
  }
  if ((encoded & XAIOS_USER_EXIT_RETURN_MASK) != XAIOS_USER_EXIT_RETURN_MAGIC) {
    klog("threads: worker returned without the exit magic; encoded=0x%lx "
         "owner=%u cpu=%u\n", encoded, context->owner_pid, cpu_id);
    return UINT64_MAX;
  }
  if (context->exited == 0U) {
    klog("threads: worker exit magic present but exited=0; owner=%u cpu=%u "
         "entry_cpu=%u exit_cpu=%u this=0x%lx last_exit=0x%lx last_cpu=%u "
         "exits=%lu encoded=0x%lx\n",
         context->owner_pid, cpu_id, context->entry_cpu, context->exit_cpu,
         (uint64_t)(uintptr_t)context, g_last_exit_context, g_last_exit_cpu,
         g_last_exit_count, encoded);
    return UINT64_MAX;
  }
  return context->exit_result;
}

xaios_status_t xaios_user_thread_create(uint64_t entry, uint64_t argument,
                                        uint64_t stack_top,
                                        uint64_t return_address,
                                        uint32_t preferred_cpu,
                                        uint32_t owner_pid,
                                        uint64_t *thread_id) {
  if (entry == 0U || stack_top == 0U || return_address == 0U ||
      owner_pid == 0U || thread_id == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t target_cpu = 0U;
  xaios_status_t status =
      xaios_thread_select_user_cpu(preferred_cpu, &target_cpu);
  if (status != XAIOS_OK) return status;
  xaios_user_thread_context_t *context =
      (xaios_user_thread_context_t *)kheap_calloc(sizeof(*context), 16U);
  if (context == 0) return XAIOS_ERR_NO_MEMORY;
  context->entry = entry;
  context->argument = argument;
  context->stack_top = stack_top;
  context->return_address = return_address;
  context->owner_pid = owner_pid;
  status = xaios_thread_create_on_cpu(user_thread_worker, context, target_cpu,
                                owner_pid, 1U, 0U, thread_id);
  if (status != XAIOS_OK) {
    kheap_free(context);
  } else {
    klog("threads: user create id=%lu owner=%u target_cpu=%u\n", *thread_id,
         owner_pid, target_cpu);
  }
  return status;
}

static xaios_status_t thread_join_owned(uint64_t thread_id, uint64_t timeout_ns,
                                        uint64_t *result, uint32_t owner_pid,
                                        uint32_t enforce_owner) {
  if (thread_id == 0U || result == 0 || g_threads == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t start = timer_now_ns();
  uint32_t current_cpu = smp_cpu_id();
  uint32_t reported_context_loss = 0U;
  for (;;) {
    xaios_spin_lock(&g_thread_lock);
    xaios_thread_record_t *thread = xaios_thread_find_locked(thread_id);
    if (thread == 0) {
      xaios_spin_unlock(&g_thread_lock);
      if (enforce_owner != 0U) {
        klog("threads: user join id=%lu owner=%u not found\n", thread_id,
             owner_pid);
      }
      return XAIOS_ERR_NOT_FOUND;
    }
    if (enforce_owner != 0U && thread->owner_pid != owner_pid) {
      uint32_t actual_owner = thread->owner_pid;
      xaios_spin_unlock(&g_thread_lock);
      klog("threads: user join id=%lu owner=%u actual_owner=%u\n", thread_id,
           owner_pid, actual_owner);
      return XAIOS_ERR_INVALID;
    }
    xaios_thread_state_t state =
        __atomic_load_n(&thread->state, __ATOMIC_ACQUIRE);
    if (state == XAIOS_THREAD_COMPLETE || state == XAIOS_THREAD_CANCELLED) {
      uint64_t value = thread->result;
      void *context = thread->release_context != 0U ? thread->context : 0;
      xaios_thread_bytes_zero(thread, sizeof(*thread));
      xaios_spin_unlock(&g_thread_lock);
      if (context != 0) kheap_free(context);
      *result = value;
      return state == XAIOS_THREAD_COMPLETE ? XAIOS_OK : XAIOS_ERR_BUSY;
    }
    xaios_spin_unlock(&g_thread_lock);

    if (current_cpu != UINT32_MAX) {
      /* Running a pending thread here borrows this CPU, which may already be
         inside the calling process's syscall. The worker restores what it
         found; this checks that it did, because the cost of it not having is
         a syscall that carries on with no process bound and the kernel's
         address space -- which returns a wrong answer rather than an error,
         and took two sightings to even name. Reported once per join so a
         recurrence says so instead of being inferred later. */
      const xaios_user_process_t *before = user_current_process();
      (void)xaios_thread_run_pending(current_cpu);
      const xaios_user_process_t *after = user_current_process();
      if (after != before && reported_context_loss == 0U) {
        reported_context_loss = 1U;
        klog("threads: join lost its process context id=%lu owner=%u cpu=%u "
             "before=%u after=%u\n",
             thread_id, owner_pid, current_cpu,
             before != 0 ? before->pid : 0U, after != 0 ? after->pid : 0U);
      }
    }
    if (timeout_ns != 0U && timer_now_ns() - start >= timeout_ns) {
      if (enforce_owner != 0U) {
        xaios_spin_lock(&g_thread_lock);
        thread = xaios_thread_find_locked(thread_id);
        uint32_t state = thread == 0 ? XAIOS_THREAD_UNUSED : thread->state;
        uint32_t target = thread == 0 ? UINT32_MAX : thread->target_cpu;
        uint32_t running = thread == 0 ? UINT32_MAX : thread->running_cpu;
        xaios_spin_unlock(&g_thread_lock);
        klog("threads: user join timeout id=%lu owner=%u state=%u target=%u "
             "running=%u\n",
             thread_id, owner_pid, state, target, running);
      }
      return XAIOS_ERR_BUSY;
    }
    xaios_cpu_relax();
  }
}

xaios_status_t xaios_thread_join(uint64_t thread_id, uint64_t timeout_ns,
                                 uint64_t *result) {
  return thread_join_owned(thread_id, timeout_ns, result, 0U, 0U);
}

xaios_status_t xaios_user_thread_join(uint64_t thread_id, uint32_t owner_pid,
                                      uint64_t timeout_ns, uint64_t *result) {
  return thread_join_owned(thread_id, timeout_ns, result, owner_pid, 1U);
}

static xaios_status_t thread_cancel_owned(uint64_t thread_id,
                                          uint32_t owner_pid,
                                          uint32_t enforce_owner) {
  xaios_spin_lock(&g_thread_lock);
  xaios_thread_record_t *thread = xaios_thread_find_locked(thread_id);
  if (thread == 0) {
    xaios_spin_unlock(&g_thread_lock);
    return XAIOS_ERR_NOT_FOUND;
  }
  if (enforce_owner != 0U && thread->owner_pid != owner_pid) {
    xaios_spin_unlock(&g_thread_lock);
    return XAIOS_ERR_INVALID;
  }
  if (thread->state != XAIOS_THREAD_PENDING) {
    xaios_spin_unlock(&g_thread_lock);
    return XAIOS_ERR_BUSY;
  }
  __atomic_store_n(&thread->state, XAIOS_THREAD_CANCELLED, __ATOMIC_RELEASE);
  xaios_spin_unlock(&g_thread_lock);
  xaios_cpu_notify();
  return XAIOS_OK;
}

xaios_status_t xaios_thread_cancel(uint64_t thread_id) {
  return thread_cancel_owned(thread_id, 0U, 0U);
}

xaios_status_t xaios_user_thread_cancel(uint64_t thread_id,
                                        uint32_t owner_pid) {
  return thread_cancel_owned(thread_id, owner_pid, 1U);
}

xaios_status_t xaios_user_thread_drain(uint32_t owner_pid,
                                       uint64_t timeout_ns) {
  if (owner_pid == 0U || g_threads == 0) return XAIOS_ERR_INVALID;
  uint64_t started = timer_now_ns();
  for (;;) {
    void *context = 0;
    uint32_t owned = 0U;
    xaios_spin_lock(&g_thread_lock);
    for (uint32_t i = 0; i < g_thread_capacity; ++i) {
      xaios_thread_record_t *thread = &g_threads[i];
      if (thread->state == XAIOS_THREAD_UNUSED ||
          thread->owner_pid != owner_pid) {
        continue;
      }
      owned = 1U;
      xaios_thread_state_t state =
          __atomic_load_n(&thread->state, __ATOMIC_ACQUIRE);
      if (state == XAIOS_THREAD_PENDING) {
        __atomic_store_n(&thread->state, XAIOS_THREAD_CANCELLED,
                         __ATOMIC_RELEASE);
        state = XAIOS_THREAD_CANCELLED;
      }
      if (state == XAIOS_THREAD_COMPLETE || state == XAIOS_THREAD_CANCELLED) {
        context = thread->release_context != 0U ? thread->context : 0;
        xaios_thread_bytes_zero(thread, sizeof(*thread));
        break;
      }
    }
    xaios_spin_unlock(&g_thread_lock);
    if (context != 0) kheap_free(context);
    if (owned == 0U) return XAIOS_OK;
    if (timeout_ns != 0U && timer_now_ns() - started >= timeout_ns) {
      return XAIOS_ERR_BUSY;
    }
    xaios_cpu_relax();
  }
}

uint64_t xaios_user_thread_exit(uint64_t result) {
  uint32_t cpu_id = smp_cpu_id();
  if (cpu_id >= g_current_user_thread_capacity ||
      g_current_user_thread_by_cpu[cpu_id] == 0) {
    return UINT64_MAX;
  }
  xaios_user_thread_context_t *context = g_current_user_thread_by_cpu[cpu_id];
  context->exit_cpu = cpu_id;
  context->exit_result = result;
  context->exited = 1U;
  g_last_exit_context = (uint64_t)(uintptr_t)context;
  g_last_exit_cpu = cpu_id;
  __atomic_add_fetch(&g_last_exit_count, 1U, __ATOMIC_RELAXED);
  return XAIOS_USER_EXIT_RETURN_MAGIC;
}
