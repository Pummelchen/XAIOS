#include <stdarg.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/types.h>

#define PL011_UARTDR 0x00U

static volatile uint32_t *g_uart_base;
static xaios_spinlock_t g_klog_lock;

/* Line buffer for ring capture */
static char g_klog_line[XAIOS_KLOG_LINE_MAX];
static uint32_t g_klog_line_pos;

static void uart_putc(char c) {
  if (g_uart_base == 0) {
    return;
  }

  g_uart_base[PL011_UARTDR / 4] = (uint32_t)c;
}

static void klog_char(char c) {
  if (c == '\n') {
    uart_putc('\r');
  }
  uart_putc(c);

  /* Also capture to line buffer for ring */
  if (g_klog_line_pos < XAIOS_KLOG_LINE_MAX - 1U) {
    g_klog_line[g_klog_line_pos++] = c;
  }
}

static void klog_line_flush(void) {
  if (g_klog_line_pos > 0) {
    klog_ring_write(g_klog_line, g_klog_line_pos);
    g_klog_line_pos = 0;
  }
}

void klog_init(const xaios_boot_info_t *boot) {
  g_uart_base = (volatile uint32_t *)(uintptr_t)boot->uart_base;
  xaios_spin_init(&g_klog_lock);
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
    klog_flush();
  }
}
