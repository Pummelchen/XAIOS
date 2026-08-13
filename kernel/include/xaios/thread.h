#ifndef XAIOS_THREAD_H
#define XAIOS_THREAD_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_THREAD_CPU_ANY UINT32_MAX

typedef uint64_t (*xaios_thread_entry_t)(void *context);

typedef enum xaios_thread_state {
  XAIOS_THREAD_UNUSED = 0,
  XAIOS_THREAD_PENDING = 1,
  XAIOS_THREAD_RUNNING = 2,
  XAIOS_THREAD_COMPLETE = 3,
  XAIOS_THREAD_CANCELLED = 4,
} xaios_thread_state_t;

void xaios_thread_runtime_init(void);
xaios_status_t xaios_thread_create(xaios_thread_entry_t entry, void *context,
                                   uint32_t preferred_cpu,
                                   uint64_t *thread_id);
xaios_status_t xaios_thread_create_off_current_cpu(
    xaios_thread_entry_t entry, void *context, uint64_t *thread_id);
xaios_status_t xaios_thread_create_detached_off_current_cpu(
    xaios_thread_entry_t entry, void *context);
xaios_status_t xaios_thread_join(uint64_t thread_id, uint64_t timeout_ns,
                                 uint64_t *result);
xaios_status_t xaios_thread_cancel(uint64_t thread_id);
xaios_status_t xaios_user_thread_create(uint64_t entry, uint64_t argument,
                                        uint64_t stack_top,
                                        uint64_t return_address,
                                        uint32_t preferred_cpu,
                                        uint32_t owner_pid,
                                        uint64_t *thread_id);
xaios_status_t xaios_user_thread_join(uint64_t thread_id, uint32_t owner_pid,
                                      uint64_t timeout_ns, uint64_t *result);
xaios_status_t xaios_user_thread_cancel(uint64_t thread_id,
                                        uint32_t owner_pid);
xaios_status_t xaios_user_thread_drain(uint32_t owner_pid,
                                       uint64_t timeout_ns);
uint64_t xaios_user_thread_exit(uint64_t result);
uint32_t xaios_thread_run_pending(uint32_t cpu_id);
uint32_t xaios_thread_capacity(void);
uint32_t xaios_thread_active_count(void);
xaios_status_t xaios_thread_run_group(uint64_t requested_threads,
                                      uint64_t iterations,
                                      uint64_t *ran_threads,
                                      uint64_t *checksum);
void xaios_thread_self_test(void);

#endif
