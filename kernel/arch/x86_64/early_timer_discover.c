/* x86-64 TSC calibration (B-122) and the APIC/timer capability report that
 * precedes the LAPIC timer self-test.
 *
 * Split out of kernel/arch/x86_64/early.c. Both functions moved verbatim; the
 * only edits are the aliases below and the fact that the frequency they measure
 * is still early.c's g_tsc_frequency, reached through the
 * xaios_x86_early_tsc_hz/_set_tsc_hz pair the platform hooks already use, at
 * the same points and in the same order as the direct stores this replaced.
 *
 * This runs at one well-defined point in x86_64_kmain: after the FPU/XSAVE
 * areas are prepared and before the LAPIC timer self-test. It programs no
 * interrupt, sends no IPI, patches no trampoline and starts no AP, so nothing
 * here can reorder the INIT-SIPI-SIPI path. The LAPIC timer interrupt itself --
 * the EOI path, the periodic tick and the interrupt self-test -- is still set
 * up and validated by validate_lapic_timer_interrupt in early.c.
 *
 * early_module.h is the shared seam; early_serial.h hands over the 8254 port
 * primitives the PIT measurement drives. Neither file owns anything else here. */

#include "early_module.h"
#include "early_serial.h"

/* early.c's primitives, under the names early_module.h declares. */
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64
#define cpuid xaios_x86_early_cpuid
#define rdmsr xaios_x86_early_rdmsr
#define rdtsc xaios_x86_early_rdtsc
#define tsc_hz xaios_x86_early_tsc_hz
#define set_tsc_hz xaios_x86_early_set_tsc_hz

/* The PIT's input frequency, by definition: 14.31818 MHz divided by twelve.
 * Nothing has to be discovered for it, which is the whole reason it is the
 * reference here. */
#define PIT_HZ UINT64_C(1193182)
#define PIT_CALIBRATION_COUNT UINT16_C(0xffff)

/* Measure the TSC in hertz against the PIT, which is the one clock on an x86
 * machine whose frequency is fixed by definition.
 *
 * B-122 is why this exists. CPUID leaf 0x15 gives the TSC frequency as a
 * crystal frequency and a ratio, and leaf 0x16 gives a base frequency in MHz --
 * but the CPU models this kernel is gated on report `ratio=0/0 crystal_hz=0`
 * and nothing in 0x16, so both branches were skipped and the frequency fell
 * through to a guess of 1 GHz. Every timeout, sleep and wall-clock reading in
 * the machine is then scaled by the ratio of the real TSC to that guess, which
 * on the CI runner is about 2.4 -- and the row for it has a measured sighting:
 * a thirty-second thread-join budget expiring after 12.3 seconds of wall clock.
 *
 * The measurement is the classic one: put PIT channel 2 in mode 0 with the gate
 * held low, program the full count, release the gate, and read the TSC across
 * the interval the counter takes to reach zero. It is measured twice so that
 * the two answers can be required to agree -- a single reading from a channel
 * that might be wired differently is exactly the kind of number this defect was
 * made of. Returns zero if the channel does not answer or the two readings
 * disagree by more than a twentieth. */
static uint64_t measure_tsc_with_pit(void) {
  uint64_t readings[2] = {0U, 0U};
  for (uint32_t pass = 0U; pass < 2U; ++pass) {
    uint8_t port61 = inb(0x61);
    outb(0x61, (uint8_t)((port61 & (uint8_t)~UINT8_C(0x01)) | UINT8_C(0x02)));
    outb(0x43, UINT8_C(0xb0)); /* channel 2, mode 0, binary */
    outb(0x42, (uint8_t)(PIT_CALIBRATION_COUNT & UINT16_C(0xff)));
    outb(0x42, (uint8_t)(PIT_CALIBRATION_COUNT >> 8U));
    uint64_t started = rdtsc();
    uint64_t budget = started + UINT64_C(4000000000);
    outb(0x61, (uint8_t)((port61 & (uint8_t)~UINT8_C(0x02)) | UINT8_C(0x01)));
    while ((inb(0x61) & UINT8_C(0x20)) == 0U) {
      if (rdtsc() - started > budget) {
        outb(0x61, port61);
        return 0U;
      }
    }
    uint64_t elapsed = rdtsc() - started;
    outb(0x61, port61);
    readings[pass] = (elapsed * PIT_HZ) / PIT_CALIBRATION_COUNT;
  }
  uint64_t first = readings[0];
  uint64_t second = readings[1];
  uint64_t larger = first > second ? first : second;
  uint64_t smaller = first > second ? second : first;
  if (smaller == 0U || larger - smaller > larger / 20U) return 0U;
  return (first + second) / 2U;
}

void xaios_x86_early_timer_discover(uint16_t serial_base) {
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
  cpuid(0, 0, &eax, &ebx, &ecx, &edx);
  uint32_t max_leaf = eax;
  cpuid(1, 0, &eax, &ebx, &ecx, &edx);
  uint32_t apic_supported = (edx & (UINT32_C(1) << 9)) != 0U;
  uint32_t tsc_supported = (edx & (UINT32_C(1) << 4)) != 0U;
  uint32_t deadline_supported = (ecx & (UINT32_C(1) << 24)) != 0U;
  uint64_t apic_base = apic_supported ? rdmsr(MSR_IA32_APIC_BASE) : 0;
  uint32_t tsc_denominator = 0;
  uint32_t tsc_numerator = 0;
  uint32_t crystal_hz = 0;
  if (max_leaf >= 0x15U) {
    cpuid(0x15U, 0, &tsc_denominator, &tsc_numerator, &crystal_hz, &edx);
  }
  const char *tsc_source = "cpuid-0x15";
  if (tsc_denominator != 0U && tsc_numerator != 0U && crystal_hz != 0U) {
    set_tsc_hz(((uint64_t)crystal_hz * tsc_numerator) / tsc_denominator);
  } else if (max_leaf >= 0x16U) {
    uint32_t base_mhz = 0U;
    cpuid(0x16U, 0U, &base_mhz, &ebx, &ecx, &edx);
    if (base_mhz != 0U) {
      set_tsc_hz((uint64_t)base_mhz * UINT64_C(1000000));
      tsc_source = "cpuid-0x16";
    }
  }
  if (tsc_hz() == 0U) {
    /* Neither leaf answered, which is the case on the CPU models this kernel
       is gated on. Measure it instead of guessing it: the PIT's 1.193182 MHz
       is fixed by definition, and a machine whose clock is wrong by a factor
       is worse than one that spends a tenth of a second of its boot finding
       out how fast it is (B-122). */
    set_tsc_hz(measure_tsc_with_pit());
    tsc_source = "pit";
  }
  if (tsc_hz() == 0U) {
    set_tsc_hz(UINT64_C(1000000000));
    tsc_source = "assumed";
  }

  serial_puts(serial_base, "x86_64: APIC discovery supported=");
  serial_dec(serial_base, apic_supported);
  serial_puts(serial_base, " base=");
  serial_hex64(serial_base, apic_base & UINT64_C(0xfffff000));
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: timer discovery tsc=");
  serial_dec(serial_base, tsc_supported);
  serial_puts(serial_base, " deadline=");
  serial_dec(serial_base, deadline_supported);
  serial_puts(serial_base, " ratio=");
  serial_dec(serial_base, tsc_numerator);
  serial_puts(serial_base, "/");
  serial_dec(serial_base, tsc_denominator);
  serial_puts(serial_base, " crystal_hz=");
  serial_dec(serial_base, crystal_hz);
  /* Which of the three sources the frequency came from, and what it came to.
     A machine that says `source=assumed` is a machine whose clock is a guess,
     and that is worth being able to read off the console. */
  serial_puts(serial_base, " source=");
  serial_puts(serial_base, tsc_source);
  serial_puts(serial_base, " tsc_hz=");
  serial_dec(serial_base, tsc_hz());
  serial_puts(serial_base, "\n");
}
