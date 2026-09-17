/* Console byte transport for the kernel log.
 *
 * The half of klog.c that talks to a console device: the PL011 and 16550
 * register offsets, the UART the boot info points at, the sink that stands in
 * for a platform with no UART at all, the line buffer the ring is fed from,
 * and the input side that reads the console the output side writes.
 *
 * The locking stays in klog.c. This file takes no lock; its byte writers are
 * called with the console lock already held, exactly as klog.c called the
 * functions they replace. Nothing here changed what is printed or when.
 */
#include <xaios/input.h>
#include <xaios/klog.h>
/* Whether this architecture reaches its console through memory.
 *
 * The guards here used to say __aarch64__, which was true and named the wrong
 * thing: what the code below actually depends on is a UART addressed through
 * memory rather than through port I/O. x86-64 uses ports; AArch64 and RISC-V
 * both use MMIO. Naming the capability instead of one architecture that has
 * it is what let RISC-V use this file unchanged -- and is the rule this
 * codebase claims to follow, applied to itself. */
#if defined(__aarch64__) || defined(__riscv)
#define XAIOS_KLOG_MMIO_UART 1
#else
#define XAIOS_KLOG_MMIO_UART 0
#endif

#if XAIOS_KLOG_MMIO_UART
#include <xaios/klog_ring.h>
#endif
#include <xaios/types.h>

#include "klog_internal.h"

#define PL011_UARTDR 0x00U
#define PL011_UARTFR 0x18U
#define PL011_UARTFR_TXFF UINT32_C(0x20)
#define PL011_UARTFR_RXFE UINT32_C(0x10)
#define UART_16550_THR UINT32_C(0)
#define UART_16550_RBR UINT32_C(0)
#define UART_16550_LSR UINT32_C(5)
#define UART_16550_LSR_THRE UINT8_C(0x20)
#define UART_16550_LSR_DR UINT8_C(0x01)

static volatile uint32_t *g_uart_base;
#if XAIOS_KLOG_MMIO_UART
/* Which UART, and how far apart its registers sit. Only the AArch64 console
   reaches a UART through memory -- the x86 one uses port I/O and never reads
   either of these -- so they are declared where they are used. Current Clang
   reports a global that is assigned and never read, and on x86 these were
   both. */
static uint32_t g_uart_kind;
static uint32_t g_uart_reg_shift;
#endif
static uint32_t g_log_output_enabled = 1U;

/* Line buffer for ring capture */
static char g_klog_line[XAIOS_KLOG_LINE_MAX];
static uint32_t g_klog_line_pos;

/* A platform may offer no UART at all. Virtualization.framework is one: it
   has no PL011, and its GOP is Blt-only, so a virtio console is the only way
   the kernel can be heard. Bytes are buffered to a line before being handed
   over, because each virtio transmission is a round trip to the device and
   one per character is far too slow to log a boot. */
static xaios_klog_sink_t g_console_sink;
static char g_sink_line[XAIOS_KLOG_LINE_MAX];
static uint32_t g_sink_pos;

static void sink_flush(void) {
  if (g_console_sink != 0 && g_sink_pos != 0U) {
    xaios_klog_sink_t sink = g_console_sink;
    uint32_t length = g_sink_pos;
    g_sink_pos = 0U;
    sink(g_sink_line, length);
    return;
  }
  g_sink_pos = 0U;
}

static void sink_putc(char c) {
  if (g_console_sink == 0) {
    return;
  }
  if (g_sink_pos < XAIOS_KLOG_LINE_MAX) {
    g_sink_line[g_sink_pos++] = c;
  }
  if (c == '\n' || g_sink_pos >= XAIOS_KLOG_LINE_MAX) {
    sink_flush();
  }
}

void klog_set_console_sink(xaios_klog_sink_t sink) {
  g_console_sink = sink;
}

/* A platform with no UART has nowhere to read from either, so the console it
   speaks through has to be the one it listens on. */
static xaios_klog_source_t g_console_source;

void klog_set_console_source(xaios_klog_source_t source) {
  g_console_source = source;
}

static xaios_klog_poll_t g_console_poll;

void klog_set_console_poll(xaios_klog_poll_t poll) {
  g_console_poll = poll;
}

/* One byte of the sink plus the raw device. This was uart_putc. */
void klog_console_putc_raw(char c) {
  sink_putc(c);
  if (g_uart_base == 0) {
    return;
  }

#if XAIOS_KLOG_MMIO_UART
  if (g_uart_kind == XAIOS_UART_PL011) {
    for (uint32_t spin = 0U; spin < UINT32_C(1000000); ++spin) {
      if ((g_uart_base[PL011_UARTFR / 4] & PL011_UARTFR_TXFF) == 0U) break;
    }
    g_uart_base[PL011_UARTDR / 4] = (uint32_t)c;
  } else if (g_uart_kind == XAIOS_UART_16550_MMIO) {
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)g_uart_base;
    uint32_t lsr_offset = UART_16550_LSR << g_uart_reg_shift;
    uint32_t thr_offset = UART_16550_THR << g_uart_reg_shift;
    for (uint32_t spin = 0U; spin < UINT32_C(1000000); ++spin) {
      if ((base[lsr_offset] & UART_16550_LSR_THRE) != 0U) break;
    }
    base[thr_offset] = (uint8_t)c;
  }
#elif defined(__x86_64__)
  uint16_t base = (uint16_t)(uintptr_t)g_uart_base;
  uint8_t ready;
  do {
    __asm__ volatile("inb %1, %0" : "=a"(ready) : "Nd"((uint16_t)(base + 5U)));
  } while ((ready & UINT8_C(0x20)) == 0U);
  __asm__ volatile("outb %0, %1" : : "a"((uint8_t)c), "Nd"(base));
#else
#error "Unsupported XAIOS logging architecture"
#endif
}

/* One byte of the ordinary path: '\r' before '\n', then the ring's line
   buffer. This was klog_char. */
void klog_console_emit(char c) {
  if (g_log_output_enabled != 0U) {
    if (c == '\n') {
      klog_console_putc_raw('\r');
    }
    klog_console_putc_raw(c);
  }

  /* Also capture to line buffer for ring */
  if (g_klog_line_pos < XAIOS_KLOG_LINE_MAX - 1U) {
    g_klog_line[g_klog_line_pos++] = c;
  }
}

/* This was klog_line_flush. */
void klog_console_line_flush(void) {
  if (g_klog_line_pos > 0) {
#if XAIOS_KLOG_MMIO_UART
    klog_ring_write(g_klog_line, g_klog_line_pos);
#endif
    g_klog_line_pos = 0;
  }
}

void klog_uart_bind(const xaios_boot_info_t *boot) {
  g_uart_base = (volatile uint32_t *)(uintptr_t)boot->uart_base;
#if XAIOS_KLOG_MMIO_UART
  g_uart_kind = boot->uart_kind;
  g_uart_reg_shift = boot->uart_reg_shift;
#endif
}

void klog_console_set_log_output(uint32_t enabled) {
  g_log_output_enabled = enabled != 0U ? 1U : 0U;
}

int klog_console_input_pending(void) {
  if (input_pending()) return 1;
  if (g_console_poll != 0 && g_console_poll() != 0) return 1;
  if (g_uart_base == 0) return 0;
#if XAIOS_KLOG_MMIO_UART
  if (g_uart_kind == XAIOS_UART_PL011) {
    return (g_uart_base[PL011_UARTFR / 4] & PL011_UARTFR_RXFE) == 0U;
  }
  if (g_uart_kind == XAIOS_UART_16550_MMIO) {
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)g_uart_base;
    uint32_t lsr_offset = UART_16550_LSR << g_uart_reg_shift;
    return (base[lsr_offset] & UART_16550_LSR_DR) != 0U;
  }
#elif defined(__x86_64__)
  uint16_t base = (uint16_t)(uintptr_t)g_uart_base;
  uint8_t status;
  __asm__ volatile("inb %1, %0" : "=a"(status)
                   : "Nd"((uint16_t)(base + UART_16550_LSR)));
  return (status & UART_16550_LSR_DR) != 0U;
#endif
  return 0;
}

int klog_console_read_char(uint8_t *value) {
  if (value == 0) return 0;
  if (input_read_char(value)) return 1;
  if (g_console_source != 0 && g_console_source(value) != 0) return 1;
  if (g_uart_base == 0) return 0;
#if XAIOS_KLOG_MMIO_UART
  if (g_uart_kind == XAIOS_UART_PL011) {
    if ((g_uart_base[PL011_UARTFR / 4] & PL011_UARTFR_RXFE) != 0U) return 0;
    *value = (uint8_t)g_uart_base[PL011_UARTDR / 4];
    return 1;
  }
  if (g_uart_kind == XAIOS_UART_16550_MMIO) {
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)g_uart_base;
    uint32_t lsr_offset = UART_16550_LSR << g_uart_reg_shift;
    if ((base[lsr_offset] & UART_16550_LSR_DR) == 0U) return 0;
    *value = base[UART_16550_RBR << g_uart_reg_shift];
    return 1;
  }
#elif defined(__x86_64__)
  uint16_t base = (uint16_t)(uintptr_t)g_uart_base;
  uint8_t status;
  __asm__ volatile("inb %1, %0" : "=a"(status)
                   : "Nd"((uint16_t)(base + UART_16550_LSR)));
  if ((status & UART_16550_LSR_DR) == 0U) return 0;
  __asm__ volatile("inb %1, %0" : "=a"(*value) : "Nd"(base));
  return 1;
#endif
  return 0;
}
