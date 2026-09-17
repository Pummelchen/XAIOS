/* The thread runtime's group runner and its two self-tests.
 *
 * Split out of thread.c, which was 824 lines. The concurrent group runner and
 * the concurrent-scheduler and pending-cancellation self-tests live together
 * because the tests read exactly the counters and the per-CPU placement the
 * runner produces; the stalled-thread diagnostic under the join timeout reads
 * the table through thread_internal.h.
 *
 * The state itself stays in thread.c, so the order xaios_thread_runtime_init
 * establishes is unchanged, and xaios_thread_run_group still caps iterations
 * at 200000, joins every thread it created and cancels the rest.
 */

#include "thread_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>

#define XAIOS_THREAD_SELF_TEST_TIMEOUT_NS UINT64_C(30000000000)

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
    xaios_cpu_relax();
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
      klog("threads: group join timed out joined=%lu created=%lu id=%lu "
           "expected_cpu=%u actual_cpu=%u\n",
           joined, created, ids[joined], contexts[joined].expected_cpu,
           contexts[joined].actual_cpu);
      for (uint64_t i = joined; i < created; ++i) {
        xaios_spin_lock(&g_thread_lock);
        xaios_thread_record_t *thread = xaios_thread_find_locked(ids[i]);
        if (thread != 0) {
          klog("threads: stalled id=%lu state=%u target_cpu=%u "
               "running_cpu=%u actual_cpu=%u\n",
               ids[i], (uint32_t)thread->state, thread->target_cpu,
               thread->running_cpu, contexts[i].actual_cpu);
        }
        xaios_spin_unlock(&g_thread_lock);
      }
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
  uint64_t count = smp_online_count();
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
  if (target_cpu == UINT32_MAX) {
    klog("threads: pending cancellation self-test skipped on uniprocessor\n");
    klog("threads: concurrent scheduler self-test passed threads=%lu cpus=%u\n",
         ran, smp_online_count());
    return;
  }
  xaios_cancel_test_context_t context = {0U, 0U};
  uint64_t blocker_id = 0U;
  uint64_t queued_id = 0U;
  kassert(xaios_thread_create(cancel_test_blocker, &context, target_cpu,
                              &blocker_id) == XAIOS_OK);
  uint64_t cancel_deadline =
      timer_now_ns() + XAIOS_THREAD_SELF_TEST_TIMEOUT_NS;
  while (__atomic_load_n(&context.started, __ATOMIC_ACQUIRE) == 0U) {
    kassert(timer_now_ns() < cancel_deadline);
    xaios_cpu_relax();
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
