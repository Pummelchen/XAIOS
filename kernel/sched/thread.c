/* The thread table, the kernel-side lifecycle and the per-CPU dispatch.
 *
 * Split out of an 824-line thread.c: the user-thread path (create, join,
 * cancel, drain, exit) moved to thread_user.c and the group runner and
 * self-tests to thread_selftest.c, both of which reach this file's state
 * through thread_internal.h. What stays here is the table itself, its
 * initialization, the placement rules, the pending check and the run that
 * claims a pending record.
 *
 * The order xaios_thread_runtime_init establishes is unchanged -- the thread
 * table is allocated and kasserted before the per-CPU context array, ids
 * start at one, and the round-robin ordinal is cleared under the same lock
 * the create paths take.
 */

#include "thread_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/vmm.h>

#define XAIOS_THREADS_PER_CPU 8U

xaios_thread_record_t *g_threads;
uint32_t g_thread_capacity;
static uint64_t g_next_thread_id;
static uint32_t g_round_robin_ordinal;
xaios_user_thread_context_t **g_current_user_thread_by_cpu;
uint32_t g_current_user_thread_capacity;
xaios_spinlock_t g_thread_lock = XAIOS_SPINLOCK_INIT;

void xaios_thread_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) bytes[i] = 0;
}

xaios_thread_record_t *xaios_thread_find_locked(uint64_t id) {
  for (uint32_t i = 0; i < g_thread_capacity; ++i) {
    if (g_threads[i].state != XAIOS_THREAD_UNUSED && g_threads[i].id == id) {
      return &g_threads[i];
    }
  }
  return 0;
}

void xaios_thread_runtime_init(void) {
  uint64_t capacity = (uint64_t)smp_online_count() * XAIOS_THREADS_PER_CPU;
  if (capacity == 0U || capacity > UINT32_MAX) capacity = XAIOS_THREADS_PER_CPU;
  g_threads = (xaios_thread_record_t *)kheap_calloc(
      capacity * sizeof(xaios_thread_record_t), 16U);
  kassert(g_threads != 0);
  g_thread_capacity = (uint32_t)capacity;
  g_current_user_thread_capacity = smp_capacity();
  g_current_user_thread_by_cpu =
      (xaios_user_thread_context_t **)kheap_calloc(
          (uint64_t)g_current_user_thread_capacity *
              sizeof(*g_current_user_thread_by_cpu),
          64U);
  kassert(g_current_user_thread_capacity == 0U ||
          g_current_user_thread_by_cpu != 0);
  g_next_thread_id = 1U;
  g_round_robin_ordinal = 0U;
  xaios_spin_init(&g_thread_lock);
  klog("threads: runtime initialized capacity=%u online_cpus=%u\n",
       g_thread_capacity, smp_online_count());
}

xaios_status_t xaios_thread_create_on_cpu(
    xaios_thread_entry_t entry, void *context, uint32_t target_cpu,
    uint32_t owner_pid, uint32_t release_context, uint32_t detached,
    uint64_t *thread_id) {
  const xaios_cpu_state_t *cpu = smp_cpu_state(target_cpu);
  if (entry == 0 || thread_id == 0 || g_threads == 0 || cpu == 0 ||
      cpu->online == 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_thread_lock);
  xaios_thread_record_t *slot = 0;
  for (uint32_t i = 0; i < g_thread_capacity; ++i) {
    if (g_threads[i].state == XAIOS_THREAD_UNUSED) {
      slot = &g_threads[i];
      break;
    }
  }
  if (slot == 0) {
    xaios_spin_unlock(&g_thread_lock);
    return XAIOS_ERR_BUSY;
  }

  uint64_t id = g_next_thread_id++;
  if (id == 0U) id = g_next_thread_id++;
  slot->id = id;
  slot->entry = entry;
  slot->context = context;
  slot->result = 0U;
  slot->target_cpu = target_cpu;
  slot->running_cpu = UINT32_MAX;
  slot->owner_pid = owner_pid;
  slot->release_context = release_context;
  slot->detached = detached;
  __atomic_store_n(&slot->state, XAIOS_THREAD_PENDING, __ATOMIC_RELEASE);
  *thread_id = id;
  xaios_spin_unlock(&g_thread_lock);
  if (target_cpu != smp_cpu_id()) (void)smp_wake_cpu(target_cpu);
  xaios_cpu_notify();
  return XAIOS_OK;
}

xaios_status_t xaios_thread_create(xaios_thread_entry_t entry, void *context,
                                   uint32_t preferred_cpu,
                                   uint64_t *thread_id) {
  uint32_t target_cpu = preferred_cpu;
  if (target_cpu == XAIOS_THREAD_CPU_ANY) {
    uint32_t online = smp_online_count();
    if (online == 0U ||
        smp_cpu_id_at(__sync_fetch_and_add(&g_round_robin_ordinal, 1U) % online,
                      &target_cpu) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  }
  return xaios_thread_create_on_cpu(entry, context, target_cpu, 0U, 0U, 0U,
                              thread_id);
}

xaios_status_t xaios_thread_create_off_current_cpu(
    xaios_thread_entry_t entry, void *context, uint64_t *thread_id) {
  uint32_t current_cpu = smp_cpu_id();
  uint32_t online = smp_online_count();
  for (uint32_t ordinal = 0U; ordinal < online; ++ordinal) {
    uint32_t target_cpu = 0U;
    if (smp_cpu_id_at(ordinal, &target_cpu) != XAIOS_OK ||
        target_cpu == current_cpu) continue;
    const xaios_cpu_state_t *cpu = smp_cpu_state(target_cpu);
    if (cpu == 0 || cpu->online == 0U ||
        cpu->role != XAIOS_CPU_ROLE_SCHEDULING || cpu->lease_owner_id != 0U) {
      continue;
    }
    return xaios_thread_create_on_cpu(entry, context, target_cpu, 0U, 0U, 0U,
                                thread_id);
  }
  return XAIOS_ERR_UNSUPPORTED;
}

/* Whether a worker CPU has a thread claimed or waiting. A worker runs one
   thread to completion, so a CPU with one already is not somewhere a second
   long-lived thread can go: it would sit pending until the first exits. */
static uint32_t cpu_has_thread_locked(uint32_t cpu_id) {
  for (uint32_t i = 0; i < g_thread_capacity; ++i) {
    uint32_t state = __atomic_load_n(&g_threads[i].state, __ATOMIC_ACQUIRE);
    if ((state == XAIOS_THREAD_RUNNING && g_threads[i].running_cpu == cpu_id) ||
        (state == XAIOS_THREAD_PENDING && g_threads[i].target_cpu == cpu_id)) {
      return 1U;
    }
  }
  return 0U;
}

/* A worker CPU that is free, other than this one.
 *
 * This took the first eligible CPU every time, which is one CPU for every
 * child a session starts. A worker runs a thread to completion, and a child
 * such as the process monitor runs for the life of its session -- so the
 * second child a machine started sat pending behind the first and never
 * ran, while the sshd that launched it waited for frames that could not
 * come. Free workers are preferred; when every one is taken the answer is
 * "no worker CPU", said to the caller, rather than a thread that will never
 * be dispatched. */
xaios_status_t xaios_thread_create_detached_off_current_cpu(
    xaios_thread_entry_t entry, void *context) {
  uint32_t current_cpu = smp_cpu_id();
  uint32_t online = smp_online_count();
  uint64_t ignored_id = 0U;
  uint32_t chosen = UINT32_MAX;
  xaios_spin_lock(&g_thread_lock);
  for (uint32_t ordinal = 0U; ordinal < online; ++ordinal) {
    uint32_t target_cpu = 0U;
    if (smp_cpu_id_at(ordinal, &target_cpu) != XAIOS_OK ||
        target_cpu == current_cpu) continue;
    const xaios_cpu_state_t *cpu = smp_cpu_state(target_cpu);
    if (cpu == 0 || cpu->online == 0U ||
        cpu->role != XAIOS_CPU_ROLE_SCHEDULING || cpu->lease_owner_id != 0U) {
      continue;
    }
    if (cpu_has_thread_locked(target_cpu) != 0U) continue;
    chosen = target_cpu;
    break;
  }
  if (chosen == UINT32_MAX) {
    /* Said out loud, per CPU: a caller that is told "no worker CPU" needs
       to know whether the machine is small or the workers are all taken. */
    for (uint32_t ordinal = 0U; ordinal < online; ++ordinal) {
      uint32_t target_cpu = 0U;
      if (smp_cpu_id_at(ordinal, &target_cpu) != XAIOS_OK) continue;
      const xaios_cpu_state_t *cpu = smp_cpu_state(target_cpu);
      klog("threads: no free worker: cpu=%u %s role=%lu lease=%lu busy=%lu\n",
           target_cpu, target_cpu == current_cpu ? "(caller)" : "",
           cpu != 0 ? (uint64_t)cpu->role : UINT64_MAX,
           cpu != 0 ? (uint64_t)cpu->lease_owner_id : UINT64_MAX,
           (uint64_t)cpu_has_thread_locked(target_cpu));
    }
  }
  xaios_spin_unlock(&g_thread_lock);
  if (chosen == UINT32_MAX) return XAIOS_ERR_UNSUPPORTED;
  return xaios_thread_create_on_cpu(entry, context, chosen, 0U, 0U, 1U,
                              &ignored_id);
}

xaios_status_t xaios_thread_select_user_cpu(uint32_t preferred_cpu,
                                            uint32_t *target_cpu) {
  uint32_t current_cpu = smp_cpu_id();
  if (preferred_cpu != XAIOS_THREAD_CPU_ANY) {
    const xaios_cpu_state_t *cpu = smp_cpu_state(preferred_cpu);
    if (preferred_cpu == current_cpu || cpu == 0 || cpu->online == 0U ||
        cpu->role != XAIOS_CPU_ROLE_SCHEDULING || cpu->lease_owner_id != 0U) {
      return XAIOS_ERR_INVALID;
    }
    *target_cpu = preferred_cpu;
    return XAIOS_OK;
  }
  uint32_t online = smp_online_count();
  uint32_t start = online == 0U
                       ? 0U
                       : __sync_fetch_and_add(&g_round_robin_ordinal, 1U) %
                             online;
  /* Two passes: a CPU with nothing on it first, then any eligible CPU.
   *
   * A worker CPU runs one thread to completion, so a second thread placed on
   * a busy CPU does not run alongside the first -- it waits behind it, and
   * the waiting is invisible to the caller, which asked for a thread and got
   * a queue entry. The kernel-side placement has refused to double-book a CPU
   * since it was written (cpu_has_thread_locked); this path never asked.
   *
   * Round robin alone does not avoid it. The ordinal is shared with every
   * other placement in the kernel and the current CPU is skipped, so two
   * consecutive creates land on the same CPU whenever the ordinal wraps past
   * it -- which is exactly what a run that failed showed: ids 7 and 8 both
   * placed on CPU 1, id 9 on CPU 2, and the join for id 7 timing out at five
   * seconds with it still marked running.
   *
   * The second pass keeps the old behaviour rather than failing: a machine
   * with more runnable threads than worker CPUs has to queue somewhere, and
   * refusing the create would be worse than queueing it. */
  for (uint32_t pass = 0U; pass < 2U; ++pass) {
    for (uint32_t offset = 0U; offset < online; ++offset) {
      uint32_t cpu_id = 0U;
      if (smp_cpu_id_at((start + offset) % online, &cpu_id) != XAIOS_OK ||
          cpu_id == current_cpu) {
        continue;
      }
      const xaios_cpu_state_t *cpu = smp_cpu_state(cpu_id);
      if (cpu == 0 || cpu->online == 0U ||
          cpu->role != XAIOS_CPU_ROLE_SCHEDULING ||
          cpu->lease_owner_id != 0U) {
        continue;
      }
      if (pass == 0U) {
        xaios_spin_lock(&g_thread_lock);
        uint32_t busy = cpu_has_thread_locked(cpu_id);
        xaios_spin_unlock(&g_thread_lock);
        if (busy != 0U) continue;
      }
      *target_cpu = cpu_id;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_UNSUPPORTED;
}

uint32_t xaios_thread_pending_on_cpu(uint32_t cpu_id) {
  if (g_threads == 0) return 0U;
  uint32_t pending = 0U;
  xaios_spin_lock(&g_thread_lock);
  for (uint32_t i = 0; i < g_thread_capacity; ++i) {
    if (g_threads[i].state == XAIOS_THREAD_PENDING &&
        g_threads[i].target_cpu == cpu_id) {
      pending = 1U;
      break;
    }
  }
  xaios_spin_unlock(&g_thread_lock);
  return pending;
}

uint32_t xaios_thread_run_pending(uint32_t cpu_id) {
  if (g_threads == 0) return 0U;

  xaios_thread_record_t *claimed = 0;
  xaios_spin_lock(&g_thread_lock);
  for (uint32_t i = 0; i < g_thread_capacity; ++i) {
    if (g_threads[i].state == XAIOS_THREAD_PENDING &&
        g_threads[i].target_cpu == cpu_id) {
      __atomic_store_n(&g_threads[i].state, XAIOS_THREAD_RUNNING,
                       __ATOMIC_RELEASE);
      g_threads[i].running_cpu = cpu_id;
      claimed = &g_threads[i];
      break;
    }
  }
  xaios_spin_unlock(&g_thread_lock);
  if (claimed == 0) return 0U;

  if (claimed->owner_pid != 0U) {
    klog("threads: user dispatch id=%lu owner=%u cpu=%u\n", claimed->id,
         claimed->owner_pid, cpu_id);
  }
  uint64_t result = claimed->entry(claimed->context);
  claimed->result = result;
  if (claimed->owner_pid != 0U) {
    klog("threads: user complete id=%lu owner=%u cpu=%u result=%lu\n",
         claimed->id, claimed->owner_pid, cpu_id, result);
  }
  if (claimed->detached != 0U) {
    xaios_thread_bytes_zero(claimed, sizeof(*claimed));
  } else {
    __atomic_store_n(&claimed->state, XAIOS_THREAD_COMPLETE, __ATOMIC_RELEASE);
  }
  xaios_cpu_notify();
  return 1U;
}

uint32_t xaios_thread_capacity(void) { return g_thread_capacity; }

uint32_t xaios_thread_active_count(void) {
  uint32_t active = 0U;
  xaios_spin_lock(&g_thread_lock);
  for (uint32_t i = 0; i < g_thread_capacity; ++i) {
    if (g_threads[i].state != XAIOS_THREAD_UNUSED) ++active;
  }
  xaios_spin_unlock(&g_thread_lock);
  return active;
}
