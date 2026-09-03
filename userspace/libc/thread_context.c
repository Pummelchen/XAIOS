#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct xaios_libc_thread_context {
  uintptr_t stack_low;
  uintptr_t stack_high;
  uint64_t thread_id;
  int errno_value;
  struct xaios_libc_thread_context *next;
} xaios_libc_thread_context_t;

static xaios_libc_thread_context_t *contexts;
static volatile unsigned int context_lock;
static int main_errno;

static uintptr_t current_stack_pointer(void) {
  uintptr_t value;
#if defined(__aarch64__)
  __asm__ volatile("mov %0, sp" : "=r"(value));
#elif defined(__x86_64__)
  __asm__ volatile("mov %%rsp, %0" : "=r"(value));
#elif defined(__riscv)
  __asm__ volatile("mv %0, sp" : "=r"(value));
#else
#error "Unsupported XAIOS userspace architecture"
#endif
  return value;
}

static void lock_contexts(void) {
  while (__atomic_test_and_set(&context_lock, __ATOMIC_ACQUIRE)) {
#if defined(__aarch64__)
    __asm__ volatile("yield");
#elif defined(__x86_64__)
    __asm__ volatile("pause");
#elif defined(__riscv)
    __asm__ volatile("" ::: "memory");
#endif
  }
}

static void unlock_contexts(void) {
  __atomic_clear(&context_lock, __ATOMIC_RELEASE);
}

static xaios_libc_thread_context_t *context_for_stack(uintptr_t stack) {
  for (xaios_libc_thread_context_t *context = contexts; context != NULL;
       context = context->next) {
    if (stack >= context->stack_low && stack < context->stack_high) {
      return context;
    }
  }
  return NULL;
}

int *__xaios_libc_errno_location(void) {
  xaios_libc_thread_context_t *context;
  uintptr_t stack = current_stack_pointer();
  lock_contexts();
  context = context_for_stack(stack);
  unlock_contexts();
  return context == NULL ? &main_errno : &context->errno_value;
}

int xaios_libc_thread_context_prepare(void *stack, uint64_t stack_size) {
  uintptr_t low = (uintptr_t)stack;
  uintptr_t high = low + (uintptr_t)stack_size;
  xaios_libc_thread_context_t *context;

  if (stack == NULL || stack_size < 4096U || high <= low) {
    errno = EINVAL;
    return -1;
  }
  lock_contexts();
  if (context_for_stack(low) != NULL) {
    unlock_contexts();
    return 0;
  }
  unlock_contexts();
  context = (xaios_libc_thread_context_t *)calloc(1U, sizeof(*context));
  if (context == NULL) return -1;
  context->stack_low = low;
  context->stack_high = high;
  lock_contexts();
  if (context_for_stack(low) == NULL) {
    context->next = contexts;
    contexts = context;
    context = NULL;
  }
  unlock_contexts();
  free(context);
  return 0;
}

void xaios_libc_thread_context_assign(void *stack, uint64_t stack_size,
                                      uint64_t thread_id) {
  uintptr_t low = (uintptr_t)stack;
  uintptr_t high = low + (uintptr_t)stack_size;
  lock_contexts();
  for (xaios_libc_thread_context_t *context = contexts; context != NULL;
       context = context->next) {
    if (context->stack_low == low && context->stack_high == high) {
      context->thread_id = thread_id;
      break;
    }
  }
  unlock_contexts();
}

void xaios_libc_thread_context_release(uint64_t thread_id) {
  xaios_libc_thread_context_t *previous = NULL;
  xaios_libc_thread_context_t *context;
  if (thread_id == 0U) return;
  lock_contexts();
  for (context = contexts; context != NULL; context = context->next) {
    if (context->thread_id == thread_id) {
      if (previous == NULL) {
        contexts = context->next;
      } else {
        previous->next = context->next;
      }
      break;
    }
    previous = context;
  }
  unlock_contexts();
  free(context);
}
