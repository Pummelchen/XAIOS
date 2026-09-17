#ifndef XAIOS_X86_64_EARLY_SERIAL_H
#define XAIOS_X86_64_EARLY_SERIAL_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_serial.c. Both files include it and nothing in it
 * is visible outside those two translation units.
 *
 * Port I/O is the one thing the moved COM1 code cannot carry away with it:
 * early.c still drives the 8254 calibration ports and the PCI config ports
 * itself, so the four primitives are defined once here -- `static inline`, so
 * each side inlines them and no external symbol is introduced -- and early.c's
 * own definitions were removed rather than duplicated.
 *
 * The UART and panic entry points are functions with external linkage, so only
 * their declarations live here; they are defined exactly once, in
 * early_serial.c. The four names early_tlb.c and early_cpu.c call are already
 * declared in early_module.h, which this header includes so that file remains
 * the single source of those prototypes. */

#include <xaios/types.h>

#include "early_module.h"

static inline void outb(uint16_t port, uint8_t value) {
  __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline void outl(uint16_t port, uint32_t value) {
  __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value = 0;
  __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port) : "memory");
  return value;
}

static inline uint32_t inl(uint16_t port) {
  uint32_t value = 0;
  __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
  return value;
}

/* Defined in early_serial.c. The other four entry points this file needs --
 * xaios_x86_early_serial_puts, _serial_dec, _serial_hex64 and _panic_halt --
 * come from early_module.h above. */
void xaios_x86_early_serial_init(uint16_t base);
void xaios_x86_early_serial_putc(uint16_t base, char c);

#endif
