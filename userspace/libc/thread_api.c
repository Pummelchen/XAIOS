#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <xaios/thread.h>

#define XAIOS_SYSCALL_THREAD_CREATE 42ULL
#define XAIOS_SYSCALL_THREAD_JOIN 43ULL
#define XAIOS_SYSCALL_THREAD_CANCEL 44ULL

typedef struct xaios_thread_create_request {
  uint64_t entry;
  uint64_t argument;
  uint64_t stack;
  uint64_t stack_size;
  uint64_t return_address;
  uint64_t preferred_cpu;
  uint64_t out_thread_id;
} xaios_thread_create_request_t;

typedef struct xaios_thread_join_request {
  uint64_t thread_id;
  uint64_t timeout_ns;
  uint64_t out_result;
} xaios_thread_join_request_t;

extern uint64_t __xaios_libc_syscall3(uint64_t number, uint64_t arg0,
                                      uint64_t arg1, uint64_t arg2);
extern void xaios_thread_return_trampoline(void);
extern int xaios_libc_thread_context_prepare(void *stack,
                                             uint64_t stack_size);
extern void xaios_libc_thread_context_assign(void *stack, uint64_t stack_size,
                                             uint64_t thread_id);
extern void xaios_libc_thread_context_release(uint64_t thread_id);

int xaios_thread_create(xaios_thread_entry_t entry, void *argument,
                        void *stack, uint64_t stack_size,
                        uint64_t preferred_cpu, uint64_t *thread_id) {
  xaios_thread_create_request_t request;
  uint64_t result;
  if (entry == NULL || stack == NULL || thread_id == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (xaios_libc_thread_context_prepare(stack, stack_size) != 0) return -1;
  request.entry = (uint64_t)(uintptr_t)entry;
  request.argument = (uint64_t)(uintptr_t)argument;
  request.stack = (uint64_t)(uintptr_t)stack;
  request.stack_size = stack_size;
  request.return_address = (uint64_t)(uintptr_t)xaios_thread_return_trampoline;
  request.preferred_cpu = preferred_cpu;
  request.out_thread_id = (uint64_t)(uintptr_t)thread_id;
  result = __xaios_libc_syscall3(XAIOS_SYSCALL_THREAD_CREATE,
                                 (uint64_t)(uintptr_t)&request,
                                 sizeof(request), 0U);
  if (result == UINT64_MAX) {
    errno = EAGAIN;
    return -1;
  }
  xaios_libc_thread_context_assign(stack, stack_size, *thread_id);
  return 0;
}

int xaios_thread_join(uint64_t thread_id, uint64_t timeout_ns,
                      uint64_t *result) {
  xaios_thread_join_request_t request;
  uint64_t syscall_result;
  if (thread_id == 0U || result == NULL) {
    errno = EINVAL;
    return -1;
  }
  request.thread_id = thread_id;
  request.timeout_ns = timeout_ns;
  request.out_result = (uint64_t)(uintptr_t)result;
  syscall_result = __xaios_libc_syscall3(XAIOS_SYSCALL_THREAD_JOIN,
                                         (uint64_t)(uintptr_t)&request,
                                         sizeof(request), 0U);
  if (syscall_result == UINT64_MAX) {
    errno = EBUSY;
    return -1;
  }
  xaios_libc_thread_context_release(thread_id);
  return 0;
}

int xaios_thread_cancel(uint64_t thread_id) {
  uint64_t result = __xaios_libc_syscall3(XAIOS_SYSCALL_THREAD_CANCEL,
                                          thread_id, 0U, 0U);
  if (result == UINT64_MAX) {
    errno = EBUSY;
    return -1;
  }
  return 0;
}
