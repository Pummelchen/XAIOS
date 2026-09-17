/* Private interface shared by the three translation units of the scheduler.
 *
 * scheduler.c keeps the scheduler's state, its bring-up, the register and
 * process-state transitions, the tick, the yield and the per-CPU accessors.
 * sched_runqueue.c owns the per-CPU task tables and the run queues: the slot
 * bitmap, the lookup, the pick and the hierarchical steal that finds work for
 * a CPU whose own queue has run dry. sched_stats.c holds the load-average
 * accounting, the statistics surface and the self-tests.
 *
 * The state stays in scheduler.c and is named here; the helpers that cross a
 * translation unit carry the `sched_' prefix so two modules cannot collide at
 * link time. The run-queue pick order, the priority slices and the gates over
 * preemption are unchanged by the split -- every body moved verbatim.
 */
#ifndef XAIOS_KERNEL_SCHED_SCHEDULER_INTERNAL_H
#define XAIOS_KERNEL_SCHED_SCHEDULER_INTERNAL_H

#include <xaios/scheduler.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* Scheduler state, defined once in scheduler.c. */
extern xaios_cpu_task_table_t *g_cpu_tasks;
extern xaios_runqueue_t *g_runqueues;
extern xaios_sched_stats_t *g_sched_stats;
extern uint32_t g_cpu_capacity;
extern uint64_t g_tick_count;
extern uint64_t g_context_switch_count;
extern uint64_t g_yield_count;
extern uint64_t g_steal_count;
extern uint64_t g_load_average_q16[3];
extern uint64_t g_load_average_last_ns;
extern uint32_t g_load_average_guard;
extern uint32_t g_initialized;
extern uint32_t g_balance_counter;

/* Task tables, run queues and placement, defined in sched_runqueue.c. */
xaios_sched_task_t *sched_find_task_local(uint32_t cpu_id, uint32_t pid);
xaios_sched_task_t *sched_find_task_global(uint32_t pid, uint32_t *cpu_out);
xaios_sched_task_t *sched_alloc_task_slot(uint32_t cpu_id);
void sched_free_task_slot(uint32_t cpu_id, xaios_sched_task_t *task);
uint32_t sched_priority_slice(xaios_task_priority_t prio);
uint32_t sched_rq_index(const xaios_runqueue_t *rq, uint32_t pid);
void sched_rq_add(xaios_runqueue_t *rq, uint32_t pid);
void sched_rq_remove(xaios_runqueue_t *rq, uint32_t pid);
uint32_t sched_rq_pick_best(xaios_runqueue_t *rq, uint32_t cpu_id);
uint32_t sched_try_steal_hierarchical(uint32_t this_cpu);
uint32_t sched_find_least_loaded_cpu(void);
void sched_periodic_load_balance(uint32_t this_cpu);

/* Helpers and accounting that cross between scheduler.c and one of the two. */
void sched_bytes_zero(void *buffer, uint64_t size);
xaios_status_t sched_register_on_cpu(uint32_t pid,
                                     xaios_task_priority_t priority,
                                     uint32_t cpu);
void sched_load_average_update(uint64_t now_ns);

#endif
