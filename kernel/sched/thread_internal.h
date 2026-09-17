/* Private interface shared by the three translation units of the thread
 * runtime.
 *
 * thread.c keeps the thread table and the kernel-side lifecycle: the record
 * type, the table, the id counter, the placement rules (xaios_thread_create,
 * xaios_thread_create_off_current_cpu, xaios_thread_create_detached_off_
 * current_cpu), the pending check and the run that claims a pending record.
 * thread_user.c owns the user-thread path: the per-CPU context slot, the
 * worker that enters user mode, the join and cancel gates and the drain an
 * exiting process runs. thread_selftest.c holds the concurrent group runner
 * and the two self-tests that drive it.
 *
 * The table state stays in thread.c and is named here; the helpers that cross
 * a translation unit carry the `xaios_thread_' prefix so two modules cannot
 * collide at link time. Every body moved verbatim: the join and cancel gates,
 * the dispatch order and the release-context handoff are unchanged.
 */
#ifndef XAIOS_KERNEL_SCHED_THREAD_INTERNAL_H
#define XAIOS_KERNEL_SCHED_THREAD_INTERNAL_H

#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/thread.h>
#include <xaios/types.h>

typedef struct xaios_thread_record {
  uint64_t id;
  xaios_thread_entry_t entry;
  void *context;
  uint64_t result;
  uint32_t target_cpu;
  uint32_t running_cpu;
  uint32_t owner_pid;
  uint32_t release_context;
  uint32_t detached;
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
  /* Which CPU the thread was started on, and which one its exit syscall was
     serviced by. B-02 is a worker that returns the exit magic -- so the exit
     path ran and found *a* context -- while its own context is still not
     marked exited, which can only mean the exit marked a different one. The
     per-CPU slot is the only link between the two, so record both ends of it
     rather than inferring. */
  uint32_t entry_cpu;
  uint32_t exit_cpu;
} xaios_user_thread_context_t;

/* Thread-table state, defined once in thread.c. */
extern xaios_thread_record_t *g_threads;
extern uint32_t g_thread_capacity;
extern xaios_spinlock_t g_thread_lock;
extern xaios_user_thread_context_t **g_current_user_thread_by_cpu;
extern uint32_t g_current_user_thread_capacity;

/* Table helpers and placement, defined in thread.c. */
void xaios_thread_bytes_zero(void *buffer, uint64_t size);
xaios_thread_record_t *xaios_thread_find_locked(uint64_t id);
xaios_status_t xaios_thread_create_on_cpu(
    xaios_thread_entry_t entry, void *context, uint32_t target_cpu,
    uint32_t owner_pid, uint32_t release_context, uint32_t detached,
    uint64_t *thread_id);
xaios_status_t xaios_thread_select_user_cpu(uint32_t preferred_cpu,
                                            uint32_t *target_cpu);

#endif
