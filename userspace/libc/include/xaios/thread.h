#ifndef XAIOS_LIBC_THREAD_H
#define XAIOS_LIBC_THREAD_H

#include <stdint.h>

typedef uint64_t (*xaios_thread_entry_t)(void *argument);

#define XAIOS_THREAD_CPU_ANY UINT64_MAX

int xaios_thread_create(xaios_thread_entry_t entry, void *argument,
                        void *stack, uint64_t stack_size,
                        uint64_t preferred_cpu, uint64_t *thread_id);
int xaios_thread_join(uint64_t thread_id, uint64_t timeout_ns,
                      uint64_t *result);
int xaios_thread_cancel(uint64_t thread_id);

#endif /* XAIOS_LIBC_THREAD_H */
