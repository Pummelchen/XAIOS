/* The x86_64 early debug output: the COM1 UART and the port-I/O primitives it
 * sits on, plus the panic halt.
 *
 * Extracted verbatim from kernel/arch/x86_64/early.c. This is the block with
 * the fewest ties to early.c's mutable state: nothing here reads the CPU
 * records, the page tables, the PMM cursor or the ACPI tables, so the only
 * thing it shares with early.c is the byte-level I/O path in early_serial.h.
 * The moved body keeps its short names; the exported wrappers at the bottom
 * are the names early_module.h and early_serial.h declare, and early.c reaches
 * them through the aliases it defines where the old definitions used to be.
 *
 * early.c keeps panic_at(), which is a public kernel entry point declared in
 * <xaios/panic.h> and has to keep the XAIOS_X86_COMMON_RUNTIME arm it had. */

#include "early_serial.h"

#define UART_DATA 0U
#define UART_INTERRUPT_ENABLE 1U
#define UART_FIFO_CONTROL 2U
#define UART_LINE_CONTROL 3U
#define UART_MODEM_CONTROL 4U
#define UART_LINE_STATUS 5U
#define UART_TRANSMIT_EMPTY 0x20U

static void serial_init(uint16_t base) {
  outb((uint16_t)(base + UART_INTERRUPT_ENABLE), 0x00);
  outb((uint16_t)(base + UART_LINE_CONTROL), 0x80);
  outb((uint16_t)(base + UART_DATA), 0x03);
  outb((uint16_t)(base + UART_INTERRUPT_ENABLE), 0x00);
  outb((uint16_t)(base + UART_LINE_CONTROL), 0x03);
  outb((uint16_t)(base + UART_FIFO_CONTROL), 0xc7);
  outb((uint16_t)(base + UART_MODEM_CONTROL), 0x0b);
}

static void serial_putc(uint16_t base, char c) {
  for (uint32_t spin = 0; spin < 100000U; ++spin) {
    if ((inb((uint16_t)(base + UART_LINE_STATUS)) & UART_TRANSMIT_EMPTY) != 0U) {
      break;
    }
  }
  outb((uint16_t)(base + UART_DATA), (uint8_t)c);
}

static void serial_puts(uint16_t base, const char *message) {
  while (*message != '\0') {
    if (*message == '\n') {
      serial_putc(base, '\r');
    }
    serial_putc(base, *message++);
  }
}

static void serial_hex64(uint16_t base, uint64_t value) {
  static const char digits[] = "0123456789abcdef";
  serial_puts(base, "0x");
  for (int shift = 60; shift >= 0; shift -= 4) {
    serial_putc(base, digits[(value >> (uint32_t)shift) & UINT64_C(0xf)]);
  }
}

static void serial_dec(uint16_t base, uint64_t value) {
  char buffer[21];
  uint32_t index = 0;
  if (value == 0) {
    serial_putc(base, '0');
    return;
  }
  while (value != 0 && index < sizeof(buffer)) {
    buffer[index++] = (char)('0' + (value % 10));
    value /= 10;
  }
  while (index != 0) {
    serial_putc(base, buffer[--index]);
  }
}

static void panic_halt(uint16_t serial_base, const char *message) {
  serial_puts(serial_base, "x86_64: panic: ");
  serial_puts(serial_base, message);
  serial_puts(serial_base, "\n");
  for (;;) {
    __asm__ volatile("hlt");
  }
}

/* The entry points above, exported under the names the two private headers
 * declare. They are the same functions, not copies. */
void xaios_x86_early_serial_init(uint16_t base) {
  serial_init(base);
}

void xaios_x86_early_serial_putc(uint16_t base, char c) {
  serial_putc(base, c);
}

void xaios_x86_early_serial_puts(uint16_t base, const char *message) {
  serial_puts(base, message);
}

void xaios_x86_early_serial_dec(uint16_t base, uint64_t value) {
  serial_dec(base, value);
}

void xaios_x86_early_serial_hex64(uint16_t base, uint64_t value) {
  serial_hex64(base, value);
}

void xaios_x86_early_panic_halt(uint16_t serial_base, const char *message) {
  panic_halt(serial_base, message);
}
