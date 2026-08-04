#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/thread.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/vmm.h>

#define XAIOS_THREADS_PER_CPU 8U
#define XAIOS_THREAD_SELF_TEST_TIMEOUT_NS UINT64_C(30000000000)

typedef struct xaios_thread_record {
  uint64_t id;
  xaios_thread_entry_t entry;
  void *context;
  uint64_t result;
  uint32_t target_cpu;
  uint32_t running_cpu;
  uint32_t owner_pid;
  uint32_t release_context;
  xaios_thread_state_t state;
} xaios_thread_record_t;

typedef struct xaios_user_thread_context {
  uint64_t entry;
  uint64_t argument;
  uint64_t stack_top;
  uint64_t return_address;
  uint64_t exit_result;
  uint32_t owner_pid;
  uint32_t exited;
} xaios_user_thread_context_t;

typedef struct xaios_group_context {
  uint64_t ordinal;
  uint64_t iterations;
  uint32_t expected_cpu;
  uint32_t actual_cpu;
} xaios_group_context_t;

typedef struct xaios_cancel_test_context {
  uint32_t started;
  uint32_t release;
} xaios_cancel_test_context_t;

static xaios_thread_record_t *g_threads;
static uint32_t g_thread_capacity;
static uint64_t g_next_thread_id;
static uint32_t g_round_robin_ordinal;
static xaios_user_thread_context_t **g_current_user_thread_by_cpu;
static uint32_t g_current_user_thread_capacity;
static xaios_spinlock_t g_thread_lock = XAIOS_SPINLOCK_INIT;

extern uint64_t aarch64_enter_user_thread(uint64_t entry, uint64_t stack,
                                          uint64_t argument,
                                          uint64_t return_address);

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) bytes[i] = 0;
}

static xaios_thread_record_t *find_thread_locked(uint64_t id) {
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

static xaios_status_t thread_create_on_cpu(
    xaios_thread_entry_t entry, void *context, uint32_t target_cpu,
    uint32_t owner_pid, uint32_t release_context, uint64_t *thread_id) {
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
  __atomic_store_n(&slot->state, XAIOS_THREAD_PENDING, __ATOMIC_RELEASE);
  *thread_id = id;
  xaios_spin_unlock(&g_thread_lock);
  __asm__ volatile("sev" ::: "memory");
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
  return thread_create_on_cpu(entry, context, target_cpu, 0U, 0U, thread_id);
}

static xaios_status_t select_user_cpu(uint32_t preferred_cpu,
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
  for (uint32_t offset = 0U; offset < online; ++offset) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at((start + offset) % online, &cpu_id) != XAIOS_OK ||
        cpu_id == current_cpu) {
      continue;
    }
    const xaios_cpu_state_t *cpu = smp_cpu_state(cpu_id);
    if (cpu != 0 && cpu->online != 0U &&
        cpu->role == XAIOS_CPU_ROLE_SCHEDULING && cpu->lease_owner_id == 0U) {
      *target_cpu = cpu_id;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_UNSUPPORTED;
}

static uint64_t user_thread_worker(void *opaque) {
  xaios_user_thread_context_t *context =
      (xaios_user_thread_context_t *)opaque;
  uint32_t cpu_id = smp_cpu_id();
  if (context == 0 || cpu_id >= g_current_user_thread_capacity ||
      user_bind_current_process(context->owner_pid) != XAIOS_OK) {
    return UINT64_MAX;
  }
  user_switch_address_space(context->owner_pid);
  g_current_user_thread_by_cpu[cpu_id] = context;
  uint64_t started_ns = timer_now_ns();
  user_thread_runtime_start(context->owner_pid, cpu_id, started_ns);
  uint64_t encoded = aarch64_enter_user_thread(
      context->entry, context->stack_top, context->argument,
      context->return_address);
  user_thread_runtime_stop(context->owner_pid, cpu_id, started_ns,
                           timer_now_ns());
  g_current_user_thread_by_cpu[cpu_id] = 0;
  user_clear_current_process();
  vmm_activate_kernel();
  if ((encoded & XAIOS_USER_EXIT_RETURN_MASK) != XAIOS_USER_EXIT_RETURN_MAGIC ||
      context->exited == 0U) {
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
  xaios_status_t status = select_user_cpu(preferred_cpu, &target_cpu);
  if (status != XAIOS_OK) return status;
  xaios_user_thread_context_t *context =
      (xaios_user_thread_context_t *)kheap_calloc(sizeof(*context), 16U);
  if (context == 0) return XAIOS_ERR_NO_MEMORY;
  context->entry = entry;
  context->argument = argument;
  context->stack_top = stack_top;
  context->return_address = return_address;
  context->owner_pid = owner_pid;
  status = thread_create_on_cpu(user_thread_worker, context, target_cpu,
                                owner_pid, 1U, thread_id);
  if (status != XAIOS_OK) kheap_free(context);
  return status;
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

  uint64_t result = claimed->entry(claimed->context);
  claimed->result = result;
  __atomic_store_n(&claimed->state, XAIOS_THREAD_COMPLETE, __ATOMIC_RELEASE);
  __asm__ volatile("sev" ::: "memory");
  return 1U;
}

static xaios_status_t thread_join_owned(uint64_t thread_id, uint64_t timeout_ns,
                                        uint64_t *result, uint32_t owner_pid,
                                        uint32_t enforce_owner) {
  if (thread_id == 0U || result == 0 || g_threads == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t start = timer_now_ns();
  uint32_t current_cpu = smp_cpu_id();
  for (;;) {
    xaios_spin_lock(&g_thread_lock);
    xaios_thread_record_t *thread = find_thread_locked(thread_id);
    if (thread == 0) {
      xaios_spin_unlock(&g_thread_lock);
      return XAIOS_ERR_NOT_FOUND;
    }
    if (enforce_owner != 0U && thread->owner_pid != owner_pid) {
      xaios_spin_unlock(&g_thread_lock);
      return XAIOS_ERR_INVALID;
    }
    xaios_thread_state_t state =
        __atomic_load_n(&thread->state, __ATOMIC_ACQUIRE);
    if (state == XAIOS_THREAD_COMPLETE || state == XAIOS_THREAD_CANCELLED) {
      uint64_t value = thread->result;
      void *context = thread->release_context != 0U ? thread->context : 0;
      bytes_zero(thread, sizeof(*thread));
      xaios_spin_unlock(&g_thread_lock);
      if (context != 0) kheap_free(context);
      *result = value;
      return state == XAIOS_THREAD_COMPLETE ? XAIOS_OK : XAIOS_ERR_BUSY;
    }
    xaios_spin_unlock(&g_thread_lock);

    if (current_cpu != UINT32_MAX) (void)xaios_thread_run_pending(current_cpu);
    if (timeout_ns != 0U && timer_now_ns() - start >= timeout_ns) {
      return XAIOS_ERR_BUSY;
    }
    __asm__ volatile("yield" ::: "memory");
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
  xaios_thread_record_t *thread = find_thread_locked(thread_id);
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
  __asm__ volatile("sev" ::: "memory");
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
        bytes_zero(thread, sizeof(*thread));
        break;
      }
    }
    xaios_spin_unlock(&g_thread_lock);
    if (context != 0) kheap_free(context);
    if (owned == 0U) return XAIOS_OK;
    if (timeout_ns != 0U && timer_now_ns() - started >= timeout_ns) {
      return XAIOS_ERR_BUSY;
    }
    __asm__ volatile("yield" ::: "memory");
  }
}

uint64_t xaios_user_thread_exit(uint64_t result) {
  uint32_t cpu_id = smp_cpu_id();
  if (cpu_id >= g_current_user_thread_capacity ||
      g_current_user_thread_by_cpu[cpu_id] == 0) {
    return UINT64_MAX;
  }
  xaios_user_thread_context_t *context = g_current_user_thread_by_cpu[cpu_id];
  context->exit_result = result;
  context->exited = 1U;
  return XAIOS_USER_EXIT_RETURN_MAGIC;
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

static uint64_t group_worker(void *opaque) {
  xaios_group_context_t *context = (xaios_group_context_t *)opaque;
  uint64_t tid = context->ordinal;
  uint32_t cpu = smp_cpu_id();
  context->actual_cpu = cpu;
  uint64_t local = (tid + 1U) * UINT64_C(0x100000001b3);
  for (uint64_t i = 0; i < context->iterations; ++i) {
    local ^= (i + 17U) + (tid << 8U) + cpu;
    local *= UINT64_C(0x9e3779b185ebca87);
    local = (local >> 11U) | (local << 53U);
  }
  return local + (tid << 32U);
}

static uint64_t cancel_test_blocker(void *opaque) {
  xaios_cancel_test_context_t *context =
      (xaios_cancel_test_context_t *)opaque;
  __atomic_store_n(&context->started, 1U, __ATOMIC_RELEASE);
  while (__atomic_load_n(&context->release, __ATOMIC_ACQUIRE) == 0U) {
    __asm__ volatile("yield" ::: "memory");
  }
  return UINT64_C(0xcace11ed);
}

static uint64_t cancel_test_queued(void *opaque) {
  (void)opaque;
  return UINT64_C(0xbad);
}

xaios_status_t xaios_thread_run_group(uint64_t requested_threads,
                                      uint64_t iterations,
                                      uint64_t *ran_threads,
                                      uint64_t *checksum) {
  if (requested_threads == 0U || iterations == 0U || ran_threads == 0 ||
      checksum == 0 || requested_threads > g_thread_capacity) {
    return XAIOS_ERR_INVALID;
  }
  if (iterations > UINT64_C(200000)) iterations = UINT64_C(200000);
  xaios_group_context_t *contexts = (xaios_group_context_t *)kheap_calloc(
      requested_threads * sizeof(*contexts), 16U);
  uint64_t *ids =
      (uint64_t *)kheap_calloc(requested_threads * sizeof(*ids), 16U);
  if (contexts == 0 || ids == 0) {
    if (contexts != 0) kheap_free(contexts);
    if (ids != 0) kheap_free(ids);
    return XAIOS_ERR_NO_MEMORY;
  }

  uint64_t created = 0U;
  for (; created < requested_threads; ++created) {
    uint32_t cpu = 0U;
    if (smp_cpu_id_at((uint32_t)(created % smp_online_count()), &cpu) !=
        XAIOS_OK) {
      break;
    }
    contexts[created].ordinal = created;
    contexts[created].iterations = iterations;
    contexts[created].expected_cpu = cpu;
    contexts[created].actual_cpu = UINT32_MAX;
    if (xaios_thread_create(group_worker, &contexts[created], cpu,
                            &ids[created]) != XAIOS_OK) {
      break;
    }
  }

  uint64_t total = 0U;
  uint64_t joined = 0U;
  for (; joined < created; ++joined) {
    uint64_t value = 0U;
    if (xaios_thread_join(ids[joined], XAIOS_THREAD_SELF_TEST_TIMEOUT_NS,
                          &value) != XAIOS_OK ||
        contexts[joined].actual_cpu != contexts[joined].expected_cpu) {
      break;
    }
    total ^= value;
  }
  for (uint64_t i = joined; i < created; ++i) {
    (void)xaios_thread_cancel(ids[i]);
    uint64_t ignored = 0U;
    (void)xaios_thread_join(ids[i], XAIOS_THREAD_SELF_TEST_TIMEOUT_NS, &ignored);
  }

  kheap_free(ids);
  kheap_free(contexts);
  *ran_threads = joined;
  *checksum = total;
  if (joined != requested_threads) return XAIOS_ERR_BUSY;
  klog("threads: concurrent group complete threads=%lu cpus=%u checksum=0x%lx\n",
       joined, smp_online_count(), total);
  return XAIOS_OK;
}

void xaios_thread_self_test(void) {
  uint64_t count = smp_online_count() + 2U;
  if (count > g_thread_capacity) count = g_thread_capacity;
  uint64_t ran = 0U;
  uint64_t checksum = 0U;
  kassert(xaios_thread_run_group(count, 128U, &ran, &checksum) == XAIOS_OK);
  kassert(ran == count);
  kassert(checksum != 0U);
  kassert(xaios_thread_active_count() == 0U);
  uint32_t target_cpu = UINT32_MAX;
  for (uint32_t i = 0U; i < smp_online_count(); ++i) {
    uint32_t candidate = UINT32_MAX;
    if (smp_cpu_id_at(i, &candidate) == XAIOS_OK &&
        candidate != smp_cpu_id()) {
      target_cpu = candidate;
      break;
    }
  }
  kassert(target_cpu != UINT32_MAX);
  xaios_cancel_test_context_t context = {0U, 0U};
  uint64_t blocker_id = 0U;
  uint64_t queued_id = 0U;
  kassert(xaios_thread_create(cancel_test_blocker, &context, target_cpu,
                              &blocker_id) == XAIOS_OK);
  uint64_t cancel_deadline =
      timer_now_ns() + XAIOS_THREAD_SELF_TEST_TIMEOUT_NS;
  while (__atomic_load_n(&context.started, __ATOMIC_ACQUIRE) == 0U) {
    kassert(timer_now_ns() < cancel_deadline);
    __asm__ volatile("yield" ::: "memory");
  }
  kassert(xaios_thread_create(cancel_test_queued, 0, target_cpu, &queued_id) ==
          XAIOS_OK);
  kassert(xaios_thread_cancel(queued_id) == XAIOS_OK);
  __atomic_store_n(&context.release, 1U, __ATOMIC_RELEASE);
  uint64_t result = 0U;
  kassert(xaios_thread_join(blocker_id, XAIOS_THREAD_SELF_TEST_TIMEOUT_NS,
                            &result) == XAIOS_OK);
  kassert(result == UINT64_C(0xcace11ed));
  kassert(xaios_thread_join(queued_id, XAIOS_THREAD_SELF_TEST_TIMEOUT_NS,
                            &result) == XAIOS_ERR_BUSY);
  kassert(xaios_thread_active_count() == 0U);
  klog("threads: concurrent scheduler self-test passed threads=%lu cpus=%u\n",
       ran, smp_online_count());
  klog("threads: pending cancellation self-test passed target_cpu=%u\n",
       target_cpu);
}
