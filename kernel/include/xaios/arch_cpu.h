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
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_io_barrier(void) {
#if defined(__aarch64__)
  __asm__ volatile("dsb sy" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("mfence" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_relax(void) {
#if defined(__aarch64__)
  __asm__ volatile("yield" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("pause" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_notify(void) {
#if defined(__aarch64__)
  __asm__ volatile("sev" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("" ::: "memory");
#else
#error "Unsupported XAIOS kernel architecture"
#endif
}

static inline void xaios_cpu_wait(void) {
#if defined(__aarch64__)
  __asm__ volatile("wfe" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("hlt" ::: "memory");
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
#else
#error "Unsupported XAIOS kernel architecture"
#endif
  return stack_pointer;
}

#endif
