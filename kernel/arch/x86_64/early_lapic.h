#ifndef XAIOS_X86_64_EARLY_LAPIC_H
#define XAIOS_X86_64_EARLY_LAPIC_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_lapic.c. Both files include it and nothing in it is
 * visible outside those two translation units.
 *
 * The MSR/CR/TSC/CPUID primitives are the one thing the moved LAPIC and
 * CPU-identity code cannot carry away with it: early.c still reads CR3 while it
 * stages the AP trampoline, reads the APIC-base MSR around the LAPIC timer
 * self-test, counts TSC cycles in the AP startup delays and runs the AVX2
 * CPUID canary, so the six primitives are defined once here -- `static inline`,
 * so each side inlines them and no external symbol is introduced -- and
 * early.c's own definitions were removed rather than duplicated.
 *
 * The local-APIC register map and the RDTSCP-ordinal MSR move with the
 * accessors that spell them, because early.c's LAPIC timer self-test, its AP
 * entry and its AP startup report still name the same constants. They are
 * architectural constants, so both sides read them from here.
 *
 * The accessors are functions with external linkage, so only their declarations
 * live here; each is defined exactly once, in early_lapic.c. The names
 * early_module.h already declares -- xaios_x86_early_lapic_write, _lapic_send,
 * _lapic_id, _current_ordinal_fast, _rdmsr, _wrmsr, _read_cr3, _write_cr3,
 * _rdtsc and _cpuid -- keep those exact spellings because the other early files
 * call them by name, and early_module.h remains their single source of
 * prototypes. Only xaios_x86_early_lapic_read and
 * xaios_x86_early_prepare_tsc_aux are added here.
 * xaios_x86_early_lapic_ready, the one name of that family that stays, is
 * declared in early_module.h and defined in early.c beside the APIC-ready flag
 * its LAPIC timer self-test sets; neither crosses this seam.
 *
 * g_tsc_aux_ready stays defined in early.c, whose AP startup report prints it;
 * prepare_tsc_aux and the fast identity here write and read that same object,
 * never a pointer to it and never a copy. */

#include <xaios/types.h>

/* The local-APIC register map, in the byte offsets lapic_read/lapic_write take.
 * MSR_IA32_APIC_BASE, the MSR those windows sit behind, is declared once in
 * early_module.h, which both sides include. */
#define APIC_BASE_ENABLE UINT64_C(1 << 11)
#define APIC_BASE_X2APIC UINT64_C(1 << 10)
#define APIC_ID UINT32_C(0x020)
#define APIC_VERSION UINT32_C(0x030)
#define APIC_EOI UINT32_C(0x0b0)
#define APIC_SPURIOUS UINT32_C(0x0f0)
#define APIC_LVT_TIMER UINT32_C(0x320)
#define APIC_ICR_LOW UINT32_C(0x300)
#define APIC_ICR_HIGH UINT32_C(0x310)
#define APIC_TIMER_INITIAL UINT32_C(0x380)
#define APIC_TIMER_CURRENT UINT32_C(0x390)
#define APIC_TIMER_DIVIDE UINT32_C(0x3e0)
#define X2APIC_MSR_BASE UINT32_C(0x800)
#define X2APIC_ICR_MSR UINT32_C(0x830)

/* The value RDTSCP returns in ECX: this kernel puts the CPU's ordinal there so
 * a CPU can name itself without reading the APIC (see the fast identity in
 * early_lapic.c). */
#define MSR_IA32_TSC_AUX UINT32_C(0xc0000103)

static inline uint64_t read_cr3(void) {
  uint64_t value = 0;
  __asm__ volatile("mov %%cr3, %0" : "=r"(value));
  return value;
}

static inline void write_cr3(uint64_t value) {
  __asm__ volatile("mov %0, %%cr3" : : "r"(value) : "memory");
}

static inline uint64_t rdmsr(uint32_t msr) {
  uint32_t low = 0;
  uint32_t high = 0;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return ((uint64_t)high << 32) | low;
}

static inline uint64_t rdtsc(void) {
  uint32_t low = 0U;
  uint32_t high = 0U;
  __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
  return ((uint64_t)high << 32U) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
  __asm__ volatile("wrmsr" : : "c"(msr), "a"((uint32_t)value),
                   "d"((uint32_t)(value >> 32)) : "memory");
}

static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                         uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  __asm__ volatile("cpuid"
                   : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                   : "a"(leaf), "c"(subleaf));
}

/* Defined in early_lapic.c. */
uint32_t xaios_x86_early_lapic_read(uint32_t offset);
void xaios_x86_early_prepare_tsc_aux(uint32_t ordinal);

/* The one scalar early.c defines and this module reads or writes: the
 * RDTSCP-ordinal flag prepare_tsc_aux here sets and early.c's AP startup report
 * prints. It is the same object in both files -- the one shared scalar of this
 * seam, kept under the name early.c already spells it. */
extern uint32_t g_tsc_aux_ready;

#endif
