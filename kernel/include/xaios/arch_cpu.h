#ifndef XAIOS_ARCH_CPU_H
#define XAIOS_ARCH_CPU_H

#include <xaios/types.h>

uint32_t x86_64_platform_current_ordinal(void);
uint32_t x86_64_platform_cpu_apic_id(uint32_t ordinal);

static inline void xaios_cpu_memory_barrier(void) {
#if defined(__aarch64__)
  __asm__ volatile("dmb ish" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("mfence" ::: "memory");
#elif defined(__riscv)
  /* Read and write, both directions. RISC-V spells out which accesses are
     ordered against which, so the general barrier has to name all four. */
  __asm__ volatile("fence rw, rw" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_io_barrier(void) {
#if defined(__aarch64__)
  __asm__ volatile("dsb sy" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("mfence" ::: "memory");
#elif defined(__riscv)
  /* The io bits, not just the memory bits. A device-facing barrier that
     ordered only normal memory would let a doorbell write overtake the
     descriptor it announces -- which is a bug that looks like a device
     ignoring work. */
  __asm__ volatile("fence iorw, iorw" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_relax(void) {
#if defined(__aarch64__)
  __asm__ volatile("yield" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("pause" ::: "memory");
#elif defined(__riscv)
  /* Zihintpause's `pause` is encoded as a fence a hart without the extension
     ignores, so it is safe to emit unconditionally: a CPU that has the hint
     takes it, and one that does not executes a harmless fence. */
  __asm__ volatile(".insn i 0x0F, 0, x0, x0, 0x010" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_notify(void) {
#if defined(__aarch64__)
  __asm__ volatile("sev" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("" ::: "memory");
#elif defined(__riscv)
  /* No event-signalling instruction. A waiter here is woken by a real
     interrupt, so the only thing to do is order the write it will observe. */
  __asm__ volatile("fence w, w" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_wait(void) {
#if defined(__aarch64__)
  __asm__ volatile("wfe" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("hlt" ::: "memory");
#elif defined(__riscv)
  __asm__ volatile("wfi" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

/* Record what this CPU is waiting for, so a refusal on another CPU can name it
 * rather than asking which CPU was silent. `reason` is a string literal and `0`
 * clears it; the implementation lives with the architecture's per-CPU state
 * (see kernel/include/xaios/smp.h for the field it writes). */
void xaios_cpu_note_wait(const char *reason);

/* Interrupts, as a value that can be saved and put back.
 *
 * The kernel had no way to say "these few instructions must not be interrupted"
 * until OD-011 needed one. That decision is to poll the network from a timer,
 * and the reentrant lock is documented as never being taken from interrupt
 * context -- so the first thing the poll needs is a primitive that turns
 * interrupts off and, more importantly, puts them back exactly as they were. A
 * helper that always enables them on the way out would turn a nested disable
 * into a bug, which is why the state is saved rather than assumed.
 *
 * The saved value is architecture-defined and opaque: the caller holds it and
 * hands it back, and nothing else may look inside it. */
typedef unsigned long xaios_interrupt_state_t;

/* Turn interrupts off and report what they were. This is the only correct way
 * to enter a section that must not be interrupted: the restore below needs the
 * previous state, and a caller that assumed "they were on" is wrong inside
 * another such section. */
static inline xaios_interrupt_state_t xaios_interrupts_disable(void) {
#if defined(__aarch64__)
  xaios_interrupt_state_t state;
  __asm__ volatile("mrs %0, daif" : "=r"(state));
  /* daifset with bit 1 sets DAIF.I and leaves the other three masks alone. */
  __asm__ volatile("msr daifset, #2" ::: "memory");
  return state;
#elif defined(__x86_64__)
  xaios_interrupt_state_t state;
  __asm__ volatile("pushfq\n\tpopq %0\n\tcli" : "=r"(state) : : "memory");
  return state;
#elif defined(__riscv)
  xaios_interrupt_state_t state;
  /* One instruction, not a read and a write: an interrupt arriving between
     them would be masked by a value this function did not compute. */
  __asm__ volatile("csrrc %0, sstatus, %1"
                   : "=r"(state)
                   : "r"((unsigned long)(1UL << 1))
                   : "memory");
  return state;
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

/* Put back the state `xaios_interrupts_disable` reported. */
static inline void xaios_interrupts_restore(xaios_interrupt_state_t state) {
#if defined(__aarch64__)
  __asm__ volatile("msr daif, %0" ::"r"(state) : "memory");
#elif defined(__x86_64__)
  __asm__ volatile("pushq %0\n\tpopfq" ::"r"(state) : "memory");
#elif defined(__riscv)
  /* Only the enable bit is written back: sstatus carries other state, and this
     function was not asked to restore that. */
  if ((state & (1UL << 1)) != 0UL) {
    __asm__ volatile("csrrs zero, sstatus, %0" ::"r"((unsigned long)(1UL << 1))
                     : "memory");
  } else {
    __asm__ volatile("csrrc zero, sstatus, %0" ::"r"((unsigned long)(1UL << 1))
                     : "memory");
  }
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

/* Whether interrupts are enabled now. For assertions and self-tests: the pair
 * above is what correctness depends on, and this is how a test says so. */
static inline int xaios_interrupts_enabled(void) {
#if defined(__aarch64__)
  xaios_interrupt_state_t state;
  __asm__ volatile("mrs %0, daif" : "=r"(state));
  return (state & (1UL << 7)) == 0UL;
#elif defined(__x86_64__)
  xaios_interrupt_state_t state;
  __asm__ volatile("pushfq\n\tpopq %0" : "=r"(state));
  return (state & (1UL << 9)) != 0UL;
#elif defined(__riscv)
  xaios_interrupt_state_t state;
  __asm__ volatile("csrr %0, sstatus" : "=r"(state));
  return (state & (1UL << 1)) != 0UL;
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline uint64_t xaios_cpu_counter(void) {
  uint64_t counter;
#if defined(__aarch64__)
  __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(counter));
#elif defined(__x86_64__)
  uint32_t low;
  uint32_t high;
  __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
  counter = ((uint64_t)high << 32U) | low;
#elif defined(__riscv)
  __asm__ volatile("rdtime %0" : "=r"(counter));
#else
#error "Unsupported XAIOS kernel architecture"
#endif
  return counter;
}

static inline uint64_t xaios_cpu_stack_pointer(void) {
  uint64_t stack_pointer;
#if defined(__aarch64__)
  __asm__ volatile("mov %0, sp" : "=r"(stack_pointer));
#elif defined(__x86_64__)
  __asm__ volatile("mov %%rsp, %0" : "=r"(stack_pointer));
#elif defined(__riscv)
  __asm__ volatile("mv %0, sp" : "=r"(stack_pointer));
#else
#error "Unsupported XAIOS kernel architecture"
#endif
  return stack_pointer;
}

#endif
