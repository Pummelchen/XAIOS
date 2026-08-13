#include <stdint.h>
#include <stdlib.h>
#include <sys/lock.h>

struct __lock {
  volatile unsigned int held;
  const void *owner;
  unsigned int depth;
};

struct __lock __lock___libc_recursive_mutex;

extern int *__xaios_libc_errno_location(void);

static const void *current_owner(void) {
  return __xaios_libc_errno_location();
}

static void spin_lock(struct __lock *lock) {
  while (__atomic_test_and_set(&lock->held, __ATOMIC_ACQUIRE)) {
#if defined(__aarch64__)
    __asm__ volatile("yield");
#elif defined(__x86_64__)
    __asm__ volatile("pause");
#endif
  }
}

void __retarget_lock_init(_LOCK_T *lock) {
  struct __lock *value;
  if (lock == NULL || *lock != NULL) return;
  value = (struct __lock *)calloc(1U, sizeof(*value));
  if (value == NULL) return;
  _LOCK_T expected = NULL;
  if (!__atomic_compare_exchange_n(lock, &expected, value, 0,
                                   __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
    free(value);
  }
}

void __retarget_lock_init_recursive(_LOCK_T *lock) {
  __retarget_lock_init(lock);
}

void __retarget_lock_close(_LOCK_T lock) {
  free(lock);
}

void __retarget_lock_close_recursive(_LOCK_T lock) {
  __retarget_lock_close(lock);
}

void __retarget_lock_acquire(_LOCK_T lock) {
  if (lock != NULL) spin_lock(lock);
}

void __retarget_lock_release(_LOCK_T lock) {
  if (lock != NULL) __atomic_clear(&lock->held, __ATOMIC_RELEASE);
}

void __retarget_lock_acquire_recursive(_LOCK_T lock) {
  const void *owner = current_owner();
  if (lock == NULL) return;
  if (lock->owner == owner && lock->depth != 0U) {
    ++lock->depth;
    return;
  }
  spin_lock(lock);
  lock->owner = owner;
  lock->depth = 1U;
}

void __retarget_lock_release_recursive(_LOCK_T lock) {
  const void *owner = current_owner();
  if (lock == NULL || lock->owner != owner || lock->depth == 0U) return;
  if (--lock->depth == 0U) {
    lock->owner = NULL;
    __atomic_clear(&lock->held, __ATOMIC_RELEASE);
  }
}
