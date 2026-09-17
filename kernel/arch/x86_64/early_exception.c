/* The x86-64 exception entry entry.S calls, and the controlled INT3
 * round-trip that proves the installed IDT actually delivers.
 *
 * Extracted verbatim from kernel/arch/x86_64/early.c. This is the one part of
 * the trap path with a boot position of its own: x86_64_kmain calls
 * xaios_x86_early_exception_round_trip() immediately after install_idt() has
 * built and loaded the table and before parse_memory_map() runs, and the entry
 * itself runs whenever an ISR stub calls it. install_idt() and the IDT storage
 * it fills stay in early.c, which owns them, so no INIT-SIPI-SIPI,
 * AP-trampoline or timer ordering is touched.
 *
 * The trap frame and the serial/panic primitives come from early_module.h and
 * early_serial.h through early_exception.h; the aliases below keep the moved
 * body spelling them the way early.c did. read_cr2() and the two round-trip
 * scalars moved with it: the entry is their only reader and the round-trip
 * their only writer, exactly as before. */

#include "early_exception.h"
#include "early_serial.h"
#include "platform.h"

#include <xaios/user.h>

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

#define COM1_PORT UINT16_C(0x3f8)

/* early.c's primitives, under the names early_module.h and early_serial.h
 * declare. */
#define serial_init xaios_x86_early_serial_init
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64
#define panic_halt xaios_x86_early_panic_halt

/* Which vector the round-trip is waiting for and how many it has seen. Both
 * were file-scope in early.c and are file-scope here. */
static volatile uint32_t g_expected_exception_vector = UINT32_MAX;
static volatile uint64_t g_exception_test_count;

static inline uint64_t read_cr2(void) {
  uint64_t value = 0;
  __asm__ volatile("mov %%cr2, %0" : "=r"(value));
  return value;
}

uint64_t x86_64_exception_entry(const x86_64_exception_frame_t *frame) {
  uint16_t serial_base = COM1_PORT;
  serial_init(serial_base);
  if (frame != 0 && frame->vector == g_expected_exception_vector) {
    ++g_exception_test_count;
    g_expected_exception_vector = UINT32_MAX;
    return 0U;
  }
  serial_puts(serial_base, "\nEXCEPTION x86_64 vector=");
  serial_dec(serial_base, frame->vector);
  serial_puts(serial_base, " error=");
  serial_hex64(serial_base, frame->error_code);
  serial_puts(serial_base, " rip=");
  serial_hex64(serial_base, frame->rip);
  if (frame->vector == 14U) {
    serial_puts(serial_base, " cr2=");
    serial_hex64(serial_base, read_cr2());
  }
  serial_puts(serial_base, "\n");
#if XAIOS_X86_COMMON_RUNTIME
  if (frame != 0 && (frame->cs & 3U) == 3U) {
    uint64_t result = user_process_note_fault();
    x86_64_platform_set_user_return(result);
    return (uint64_t)(uintptr_t)x86_64_ring3_resume;
  }
#endif
  panic_halt(serial_base, "controlled x86_64 exception reported");
  return 0U;
}

void xaios_x86_early_exception_round_trip(uint16_t serial_base) {
  g_exception_test_count = 0U;
  g_expected_exception_vector = 3U;
  __asm__ volatile("int3" ::: "memory");
  if (g_exception_test_count != 1U ||
      g_expected_exception_vector != UINT32_MAX) {
    panic_halt(serial_base, "controlled INT3 exception failed");
  }
  serial_puts(serial_base,
              "x86_64: controlled INT3 exception round-trip passed count=1\n");
}
