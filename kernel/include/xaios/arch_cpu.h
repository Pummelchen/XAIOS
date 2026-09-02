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
