#include <stdarg.h>
#include <xaios/klog.h>
#include <xaios/input.h>
#include <xaios/boot_ui.h>
#if defined(__aarch64__)
#include <xaios/klog_ring.h>
#endif
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/types.h>

#define PL011_UARTDR 0x00U
#define PL011_UARTFR 0x18U
#define PL011_UARTFR_TXFF UINT32_C(0x20)
#define PL011_UARTFR_RXFE UINT32_C(0x10)
#define UART_16550_THR UINT32_C(0)
#define UART_16550_RBR UINT32_C(0)
#define UART_16550_LSR UINT32_C(5)
#define UART_16550_LSR_THRE UINT8_C(0x20)
#define UART_16550_LSR_DR UINT8_C(0x01)
#define XAIOS_CONSOLE_CAPTURE_DEPTH 8U

typedef struct xaios_console_capture {
  char *buffer;
  uint64_t capacity;
  uint64_t length;
} xaios_console_capture_t;

static volatile uint32_t *g_uart_base;
static uint32_t g_uart_kind;
static uint32_t g_uart_reg_shift;
static xaios_spinlock_t g_klog_lock;
static uint32_t g_log_output_enabled = 1U;
static xaios_console_capture_t
    g_console_captures[XAIOS_CONSOLE_CAPTURE_DEPTH];
static uint32_t g_console_capture_depth;

/* Line buffer for ring capture */
static char g_klog_line[XAIOS_KLOG_LINE_MAX];
static uint32_t g_klog_line_pos;

static void uart_putc(char c) {
  if (g_uart_base == 0) {
    return;
  }

#if defined(__aarch64__)
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

static void klog_char(char c) {
  if (g_log_output_enabled != 0U) {
    if (c == '\n') {
      uart_putc('\r');
    }
    uart_putc(c);
  }

  /* Also capture to line buffer for ring */
  if (g_klog_line_pos < XAIOS_KLOG_LINE_MAX - 1U) {
    g_klog_line[g_klog_line_pos++] = c;
  }
}

static void klog_line_flush(void) {
  if (g_klog_line_pos > 0) {
#if defined(__aarch64__)
    klog_ring_write(g_klog_line, g_klog_line_pos);
#endif
    g_klog_line_pos = 0;
  }
}

void klog_init(const xaios_boot_info_t *boot) {
  g_uart_base = (volatile uint32_t *)(uintptr_t)boot->uart_base;
  g_uart_kind = boot->uart_kind;
  g_uart_reg_shift = boot->uart_reg_shift;
  xaios_spin_init(&g_klog_lock);
  g_log_output_enabled = 1U;
}

void klog_console_set_log_output(uint32_t enabled) {
  g_log_output_enabled = enabled != 0U ? 1U : 0U;
}

void klog_console_write(const char *message, uint64_t length) {
  if (message == 0 || length == 0U) return;
  xaios_spin_lock(&g_klog_lock);
  /* Console output produced while a session is capturing belongs to that
     session: the capturing caller relays it to its own terminal exactly once.
     Echoing it to the UART as well printed every transient application's
     output twice on the local console, and published the output of remote
     SSH commands on the physical serial port. */
  int capturing = g_console_capture_depth != 0U;
  for (uint64_t i = 0U; i < length; ++i) {
    if (capturing) {
      xaios_console_capture_t *capture =
          &g_console_captures[g_console_capture_depth - 1U];
      if (capture->length < capture->capacity) {
        capture->buffer[capture->length++] = message[i];
      }
      continue;
    }
    if (message[i] == '\n') uart_putc('\r');
    uart_putc(message[i]);
  }
  xaios_spin_unlock(&g_klog_lock);
  /* The framebuffer terminal is a second console attached to the same stream,
     so it receives exactly what the UART receives: everything except bytes
     that belong to a capturing session. Written outside the klog lock because
     it paints pixels and must not hold the console lock while doing so. */
  if (!capturing) boot_ui_console_write(message, length);
}

int klog_console_capture_begin(char *buffer, uint64_t capacity) {
  if (buffer == 0 || capacity == 0U) return 0;
  xaios_spin_lock(&g_klog_lock);
  if (g_console_capture_depth == XAIOS_CONSOLE_CAPTURE_DEPTH) {
    xaios_spin_unlock(&g_klog_lock);
    return 0;
  }
  xaios_console_capture_t *capture =
      &g_console_captures[g_console_capture_depth++];
  capture->buffer = buffer;
  capture->capacity = capacity;
  capture->length = 0U;
  xaios_spin_unlock(&g_klog_lock);
  return 1;
}

uint64_t klog_console_capture_end(void) {
  uint64_t length = 0U;
  xaios_spin_lock(&g_klog_lock);
  if (g_console_capture_depth != 0U) {
    xaios_console_capture_t *capture =
        &g_console_captures[--g_console_capture_depth];
    length = capture->length;
    capture->buffer = 0;
    capture->capacity = 0U;
    capture->length = 0U;
  }
  xaios_spin_unlock(&g_klog_lock);
  return length;
}

int klog_console_read_char(uint8_t *value) {
  if (value == 0) return 0;
  if (input_read_char(value)) return 1;
  if (g_uart_base == 0) return 0;
#if defined(__aarch64__)
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

void klog_puts(const char *message) {
  while (*message != '\0') {
    klog_char(*message++);
  }
}

void klog_write(const char *message, uint64_t length) {
  for (uint64_t i = 0; i < length; ++i) {
    klog_char(message[i]);
  }
}

void klog_write_atomic(const char *message, uint64_t length) {
  if (message == 0 || length == 0U) return;
  xaios_spin_lock(&g_klog_lock);
  klog_write(message, length);
  klog_line_flush();
  xaios_spin_unlock(&g_klog_lock);
}

static void klog_u64_width(uint64_t value, unsigned base, unsigned width,
                           char padding) {
  char buffer[32];
  unsigned index = 0;

  if (value == 0) {
    while (width > 1U) {
      klog_char(padding);
      --width;
    }
    klog_char('0');
    return;
  }

  while (value != 0 && index < sizeof(buffer)) {
    unsigned digit = (unsigned)(value % base);
    buffer[index++] = (char)(digit < 10 ? '0' + digit : 'a' + (digit - 10));
    value /= base;
  }

  while (width > index) {
    klog_char(padding);
    --width;
  }
  while (index != 0) {
    klog_char(buffer[--index]);
  }
}

static void klog_u64(uint64_t value, unsigned base) {
  klog_u64_width(value, base, 0, ' ');
}

static void klog_i64(int64_t value, unsigned width, char padding) {
  uint64_t magnitude = (uint64_t)value;
  if (value < 0) {
    klog_char('-');
    magnitude = (uint64_t)(-(value + 1)) + 1U;
    if (width > 0U) {
      --width;
    }
  }
  klog_u64_width(magnitude, 10, width, padding);
}

static void klog_vformat(const char *fmt, va_list args) {
  for (const char *p = fmt; *p != '\0'; ++p) {
    if (*p != '%') {
      klog_char(*p);
      continue;
    }

    ++p;
    if (*p == '\0') {
      break;
    }

    char padding = ' ';
    unsigned width = 0;
    if (*p == '0') {
      padding = '0';
      ++p;
    }
    while (*p >= '0' && *p <= '9') {
      width = (width * 10U) + (unsigned)(*p - '0');
      ++p;
    }

    if (*p == 's') {
      const char *s = va_arg(args, const char *);
      klog_puts(s == 0 ? "(null)" : s);
    } else if (*p == 'u') {
      klog_u64_width((uint64_t)va_arg(args, unsigned), 10, width, padding);
    } else if (*p == 'x') {
      klog_u64_width((uint64_t)va_arg(args, unsigned), 16, width, padding);
    } else if (*p == 'd') {
      klog_i64((int64_t)va_arg(args, int), width, padding);
    } else if (*p == 'p') {
      klog_puts("0x");
      klog_u64((uint64_t)(uintptr_t)va_arg(args, void *), 16);
    } else if (*p == 'l' && p[1] == 'u') {
      ++p;
      klog_u64(va_arg(args, uint64_t), 10);
    } else if (*p == 'l' && p[1] == 'x') {
      ++p;
      klog_u64(va_arg(args, uint64_t), 16);
    } else if (*p == '%') {
      klog_char('%');
    } else {
      klog_char('%');
      klog_char(*p);
    }
  }
}

void klog(const char *fmt, ...) {
  if (!xaios_spin_trylock(&g_klog_lock)) {
    return;
  }

  va_list args;
  va_start(args, fmt);
  klog_vformat(fmt, args);
  klog_line_flush();
  va_end(args);
  xaios_spin_unlock(&g_klog_lock);
}

static const char *log_level_str(xaios_log_level_t level) {
  switch (level) {
  case XAIOS_LOG_DEBUG:
    return "DEBUG";
  case XAIOS_LOG_INFO:
    return "INFO";
  case XAIOS_LOG_WARN:
    return "WARN";
  case XAIOS_LOG_ERROR:
    return "ERROR";
  case XAIOS_LOG_PANIC:
    return "PANIC";
  }
  return "?";
}

void klog_level(xaios_log_level_t level, const char *fmt, ...) {
  if (level == XAIOS_LOG_PANIC || level == XAIOS_LOG_ERROR) {
    klog_console_set_log_output(1U);
  }
  uint64_t wall_ns = wall_time_now_ns();
  uint64_t sec = wall_ns / UINT64_C(1000000000);
  uint64_t nsec = wall_ns % UINT64_C(1000000000);
  klog("[%lu.%lu] [%s] ", sec, nsec, log_level_str(level));

  va_list args;
  va_start(args, fmt);
  klog_vformat(fmt, args);
  klog_line_flush();
  va_end(args);

  /* Flush ring immediately on panic */
  if (level == XAIOS_LOG_PANIC) {
#if defined(__aarch64__)
    klog_flush();
#endif
  }
}
