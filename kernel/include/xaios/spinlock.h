#ifndef XAIOS_SPINLOCK_H
#define XAIOS_SPINLOCK_H

#include <xaios/arch_cpu.h>
#include <xaios/types.h>

/*
 * Ticket spinlock — fair, FIFO ordering, SMP-safe.
 *
 * Uses GCC __sync builtins which compile to LSE/LL-SC atomics on AArch64.
 * On single-core systems, uses plain memory ops to avoid exclusive monitor
 * instructions (ldaxr) that may fault on some QEMU TCG versions after MMU
 * reconfiguration.
 */

/* Forward declaration — defined in smp.c */
extern uint32_t smp_online_count(void);

typedef struct xaios_spinlock {
  volatile uint32_t next_ticket;
  volatile uint32_t serve;
  volatile uint32_t guard; /* single-CPU recursion guard */
} xaios_spinlock_t;

#define XAIOS_SPINLOCK_INIT \
  { 0, 0, 0 }

static inline void xaios_spin_init(xaios_spinlock_t *lock) {
  lock->next_ticket = 0;
  lock->serve = 0;
  lock->guard = 0;
}

static inline void xaios_spin_lock(xaios_spinlock_t *lock) {
  if (smp_online_count() <= 1) {
    /* Single-core: use plain memory ops — no exclusive monitors needed */
    lock->guard = 1;
    xaios_cpu_memory_barrier();
    return;
  }
  uint32_t ticket = __sync_fetch_and_add(&lock->next_ticket, 1U);
  while (__atomic_load_n(&lock->serve, __ATOMIC_ACQUIRE) != ticket) {
    xaios_cpu_relax();
  }
  lock->guard = 1;
}

static inline void xaios_spin_unlock(xaios_spinlock_t *lock) {
  lock->guard = 0;
  uint32_t current = __atomic_load_n(&lock->serve, __ATOMIC_RELAXED);
  uint32_t next = __atomic_load_n(&lock->next_ticket, __ATOMIC_RELAXED);
  if (current == next) {
    xaios_cpu_memory_barrier();
    return;
  }
  __atomic_store_n(&lock->serve, current + 1U, __ATOMIC_RELEASE);
}

/* Non-blocking try-lock. Returns 1 on success, 0 if already held. */
static inline int xaios_spin_trylock(xaios_spinlock_t *lock) {
  if (smp_online_count() <= 1) {
    if (lock->guard != 0) {
      return 0;
    }
    lock->guard = 1;
    xaios_cpu_memory_barrier();
    return 1;
  }
  uint32_t current = __atomic_load_n(&lock->serve, __ATOMIC_ACQUIRE);
  uint32_t next = __atomic_load_n(&lock->next_ticket, __ATOMIC_RELAXED);
  if (current != next) {
    return 0; /* someone is queued or holding */
  }
  /* Attempt to claim the lock with a CAS */
  if (__sync_bool_compare_and_swap(&lock->next_ticket, current, current + 1U)) {
    lock->guard = 1;
    return 1;
  }
  return 0;
}

/* Single-CPU recursion guard (non-SMP path, no atomics) */
static inline int xaios_spin_trylock_guard(xaios_spinlock_t *lock) {
  if (lock->guard != 0) {
    return 0;
  }
  lock->guard = 1;
  return 1;
}

static inline void xaios_spin_unlock_guard(xaios_spinlock_t *lock) {
  lock->guard = 0;
}

static inline int xaios_spin_held(xaios_spinlock_t *lock) {
  if (smp_online_count() <= 1) {
    return __atomic_load_n(&lock->guard, __ATOMIC_RELAXED) != 0U;
  }
  return __atomic_load_n(&lock->serve, __ATOMIC_RELAXED) !=
         __atomic_load_n(&lock->next_ticket, __ATOMIC_RELAXED);
}

/*
 * Reentrant guard for a subsystem whose entry points call one another.
 *
 * Several subsystems here were written when one CPU ran the kernel, so their
 * shared tables are mutated in hundreds of places with no serialisation, and
 * their exported functions call each other freely. Both facts are now
 * problems: a syscall runs on whichever CPU the calling thread occupies, and
 * a plain spinlock taken at each entry point would deadlock on the nesting.
 *
 * This counts depth per CPU. The first acquisition on a CPU takes the lock and
 * nested ones only count, which serialises the subsystem without touching the
 * call graph or the writes inside it.
 *
 * Reading owner and depth outside the lock is safe in the only direction that
 * matters: a CPU can conclude it does *not* already hold the guard and fall
 * through to the real lock, which blocks correctly. It cannot conclude the
 * opposite, because a CPU writes its own id there only while holding the lock
 * and clears it before releasing.
 *
 * This is a coarse instrument. It is the right one while the question is
 * whether these subsystems are correct under parallelism at all; finer
 * locking belongs after that, with measurements to justify it.
 *
 * Never take this from interrupt context. The depth check identifies the
 * holder by CPU, so an interrupt that lands on a CPU already inside the guard
 * and calls a guarded function would be told it holds the lock and would walk
 * straight into the critical section it interrupted. Every subsystem using it
 * today is entered from syscalls and kernel threads only -- the timer path
 * reaches scheduler_tick, and the virtio handlers touch nothing but their own
 * driver state -- and that is a property to preserve rather than assume.
 */
typedef struct xaios_reentrant_lock {
  xaios_spinlock_t lock;
  volatile uint32_t owner;
  volatile uint32_t depth;
} xaios_reentrant_lock_t;

#define XAIOS_REENTRANT_LOCK_INIT \
  { XAIOS_SPINLOCK_INIT, 0xffffffffU, 0 }

static inline void xaios_reentrant_lock(xaios_reentrant_lock_t *guard,
                                        uint32_t cpu_id) {
  if (__atomic_load_n(&guard->depth, __ATOMIC_ACQUIRE) != 0U &&
      __atomic_load_n(&guard->owner, __ATOMIC_ACQUIRE) == cpu_id) {
    ++guard->depth;
    return;
  }
  xaios_spin_lock(&guard->lock);
  __atomic_store_n(&guard->owner, cpu_id, __ATOMIC_RELEASE);
  __atomic_store_n(&guard->depth, 1U, __ATOMIC_RELEASE);
}

static inline void xaios_reentrant_unlock(xaios_reentrant_lock_t *guard) {
  if (guard->depth == 0U) return;
  if (--guard->depth != 0U) return;
  __atomic_store_n(&guard->owner, 0xffffffffU, __ATOMIC_RELEASE);
  __atomic_store_n(&guard->depth, 0U, __ATOMIC_RELEASE);
  xaios_spin_unlock(&guard->lock);
}

#endif
