/* The x86-64 early LAPIC register access and CPU-identity primitives.
 *
 * Extracted verbatim from kernel/arch/x86_64/early.c. This is the access layer
 * under the whole early bring-up: the local-APIC register read and write, the
 * APIC id, the interprocessor interrupt, and the RDTSCP ordinal a CPU uses to
 * name itself without a host round trip. Every function here is a leaf that
 * touches one register or one early.c scalar; none chooses when it runs,
 * sends an IPI by itself, programs a timer, touches the IDT or patches the AP
 * trampoline, so the move reorders nothing. In particular the INIT-SIPI-SIPI
 * sequence stays in early.c's start_application_processors() with the delays it
 * always had, and reaches the interrupt transport through
 * xaios_x86_early_lapic_send() exactly as it reached the old static function.
 *
 * early.c keeps the raw MSR/CR/TSC/CPUID primitives as the `static inline`
 * copies in early_lapic.h, so its own call sites still inline them, and reaches
 * the accessors here through the aliases it defines where the old definitions
 * used to be. The one scalar this module shares with early.c --
 * g_tsc_aux_ready -- is still defined there, written by prepare_tsc_aux here
 * and printed by its AP startup report, and crosses as the same object. The
 * APIC-ready flag and its accessor do not cross at all; they stay in early.c
 * with the LAPIC timer self-test that sets the flag. */

#include "early_module.h"
#include "early_lapic.h"
#include "platform.h"

static uint32_t lapic_read(uint32_t offset) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_base & (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) ==
      (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) {
    return (uint32_t)rdmsr(X2APIC_MSR_BASE + (offset >> 4U));
  }
  volatile uint32_t *lapic = (volatile uint32_t *)(uintptr_t)(
      apic_base & UINT64_C(0xfffff000));
  return lapic[offset / sizeof(uint32_t)];
}

static void lapic_write(uint32_t offset, uint32_t value) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_base & (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) ==
      (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) {
    wrmsr(X2APIC_MSR_BASE + (offset >> 4U), value);
    return;
  }
  volatile uint32_t *lapic = (volatile uint32_t *)(uintptr_t)(
      apic_base & UINT64_C(0xfffff000));
  lapic[offset / sizeof(uint32_t)] = value;
  (void)lapic[APIC_ID / sizeof(uint32_t)];
}

static uint32_t lapic_id(void) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  uint32_t id = lapic_read(APIC_ID);
  return (apic_base & APIC_BASE_X2APIC) != 0U ? id : id >> 24U;
}

/* This CPU's ordinal without going to the APIC.
 *
 * `x86_64_platform_current_ordinal` reads the APIC id, which under emulation
 * is a host round trip -- too expensive to pay on every external interrupt, and
 * far too expensive to pay on every iteration of a spin loop. RDTSCP returns
 * the IA32_TSC_AUX value, bring-up puts this CPU's ordinal there, and reading
 * it costs a few cycles. A CPU whose CPUID has no RDTSCP keeps the APIC read,
 * and the ordinal is validated against the record table either way. The count
 * comes through early_module.h's accessor, which hands over early.c's
 * g_cpu_record_count by value; that table is filled once, before any CPU can
 * ask. */
static uint32_t current_ordinal_fast(void) {
  if (g_tsc_aux_ready == 0U) return x86_64_platform_current_ordinal();
  uint32_t low = 0U;
  uint32_t high = 0U;
  uint32_t aux = 0U;
  __asm__ volatile("rdtscp" : "=a"(low), "=d"(high), "=c"(aux) : : "memory");
  return aux < xaios_x86_early_cpu_record_count()
             ? aux
             : x86_64_platform_current_ordinal();
}

/* Whether this CPU can name itself with RDTSCP, and if so, teach it its own
 * ordinal. Called once per CPU, before that CPU can run anything that asks. */
static void prepare_tsc_aux(uint32_t ordinal) {
  uint32_t eax = 0U;
  uint32_t ebx = 0U;
  uint32_t ecx = 0U;
  uint32_t edx = 0U;
  cpuid(UINT32_C(0x80000000), 0U, &eax, &ebx, &ecx, &edx);
  if (eax < UINT32_C(0x80000001)) return;
  cpuid(UINT32_C(0x80000001), 0U, &eax, &ebx, &ecx, &edx);
  if ((edx & (UINT32_C(1) << 27U)) == 0U) return; /* no RDTSCP */
  wrmsr(MSR_IA32_TSC_AUX, ordinal);
  g_tsc_aux_ready = 1U;
}

static void lapic_send(uint32_t destination, uint32_t command) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_base & APIC_BASE_X2APIC) != 0U) {
    wrmsr(X2APIC_ICR_MSR, ((uint64_t)destination << 32U) | command);
    return;
  }
  while ((lapic_read(APIC_ICR_LOW) & UINT32_C(1 << 12)) != 0U) {
    __asm__ volatile("pause");
  }
  lapic_write(APIC_ICR_HIGH, destination << 24U);
  lapic_write(APIC_ICR_LOW, command);
  while ((lapic_read(APIC_ICR_LOW) & UINT32_C(1 << 12)) != 0U) {
    __asm__ volatile("pause");
  }
}

/* The accessors above and below, exported under the names early.c's aliases and
 * the other early files use. They are the same functions, not copies.
 * xaios_x86_early_lapic_ready is deliberately not here: the APIC-ready flag it
 * reports is set by early.c's own LAPIC timer self-test, so it stays in early.c
 * with that flag. */
void xaios_x86_early_lapic_send(uint32_t destination, uint32_t command) {
  lapic_send(destination, command);
}

uint32_t xaios_x86_early_current_ordinal_fast(void) {
  return current_ordinal_fast();
}

void xaios_x86_early_lapic_write(uint32_t offset, uint32_t value) {
  lapic_write(offset, value);
}

uint32_t xaios_x86_early_lapic_read(uint32_t offset) {
  return lapic_read(offset);
}

uint32_t xaios_x86_early_lapic_id(void) { return lapic_id(); }

void xaios_x86_early_prepare_tsc_aux(uint32_t ordinal) {
  prepare_tsc_aux(ordinal);
}

void xaios_x86_early_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                           uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  cpuid(leaf, subleaf, eax, ebx, ecx, edx);
}

uint64_t xaios_x86_early_rdmsr(uint32_t msr) { return rdmsr(msr); }

void xaios_x86_early_wrmsr(uint32_t msr, uint64_t value) { wrmsr(msr, value); }

uint64_t xaios_x86_early_read_cr3(void) { return read_cr3(); }

void xaios_x86_early_write_cr3(uint64_t value) { write_cr3(value); }

uint64_t xaios_x86_early_rdtsc(void) { return rdtsc(); }
