#include <stdarg.h>
#include <xaios/klog.h>
#include <xaios/input.h>
#include <xaios/boot_ui.h>
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
#if XAIOS_KLOG_MMIO_UART
/* Which UART, and how far apart its registers sit. Only the AArch64 console
   reaches a UART through memory -- the x86 one uses port I/O and never reads
   either of these -- so they are declared where they are used. Current Clang
   reports a global that is assigned and never read, and on x86 these were
   both. */
static uint32_t g_uart_kind;
static uint32_t g_uart_reg_shift;
#endif
static xaios_spinlock_t g_klog_lock;
static uint32_t g_log_output_enabled = 1U;
/* Set by the hart that is panicking; see klog_console_panic_claim below.
   Plain integers touched only through the atomics, because several harts
   reach them at once and the numbers are reported. */
static uint32_t g_panic_active;
static uint64_t g_panic_dropped;
static uint64_t g_panic_other;

/* Lines `klog` has thrown away because another CPU held the console lock.
 *
 * `klog` takes that lock with a try, on purpose: it is called from contexts
 * that must not block, so a contended line is dropped rather than waited for.
 * What was wrong is that it was dropped *silently*. Gates assert on lines, so a
 * dropped line is indistinguishable from behaviour that did not happen -- and
 * that is the shape of a class of intermittent failures: a marker missing under
 * load with the machine otherwise perfect, and neither the success message nor
 * the failure message present in the console. Counted here and reported by the
 * next line that does get through, because an absence has to be visible to be
 * read correctly. */
static uint64_t g_klog_contended_drops;

/* One place that says "the console is not ours right now". */
static int klog_suppressed_by_panic(void) {
  if (__atomic_load_n(&g_panic_active, __ATOMIC_ACQUIRE) == 0U) return 0;
  (void)__atomic_add_fetch(&g_panic_dropped, 1U, __ATOMIC_RELAXED);
  return 1;
}
static xaios_console_capture_t
    g_console_captures[XAIOS_CONSOLE_CAPTURE_DEPTH];
static uint32_t g_console_capture_depth;

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

static void uart_putc(char c) {
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
#if XAIOS_KLOG_MMIO_UART
    klog_ring_write(g_klog_line, g_klog_line_pos);
#endif
    g_klog_line_pos = 0;
  }
}

void klog_init(const xaios_boot_info_t *boot) {
  g_uart_base = (volatile uint32_t *)(uintptr_t)boot->uart_base;
#if XAIOS_KLOG_MMIO_UART
  g_uart_kind = boot->uart_kind;
  g_uart_reg_shift = boot->uart_reg_shift;
#endif
  xaios_spin_init(&g_klog_lock);
  g_log_output_enabled = 1U;
}

void klog_console_set_log_output(uint32_t enabled) {
  g_log_output_enabled = enabled != 0U ? 1U : 0U;
}

/* Set once, by the hart that is panicking, and never cleared.
 *
 * The panic path writes around `g_klog_lock` deliberately: it cannot take a
 * lock a dying machine may already hold, and a panic that deadlocks on its own
 * console is worse than one that prints in a strange order. What that cost was
 * legibility. Every other hart kept logging through the locked paths, and the
 * two streams interleaved byte for byte -- so a panic dump arrived shredded
 * through the middle of other lines, and `System halted` came out inside a
 * `user: rejected syscall=11` line.
 *
 * That is not a cosmetic complaint about one boot. The panic dump is the only
 * evidence a halted machine leaves, and on the first RISC-V boot failure that
 * got far enough to panic from a running system, the cause was not readable at
 * all. So the panicking hart claims the console, the ordinary paths drop what
 * they were asked to print, and the dump reports how much it dropped -- the
 * suppression is disclosed rather than silent. */
int klog_console_panic_claim(void) {
  uint32_t expected = 0U;
  if (__atomic_compare_exchange_n(&g_panic_active, &expected, 1U, 0,
                                  __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    return 1;
  }
  /* Someone else already owns the console. The count is kept so the winning
     dump can say so; see the header. */
  (void)__atomic_add_fetch(&g_panic_other, 1U, __ATOMIC_RELAXED);
  return 0;
}

uint64_t klog_console_panic_dropped(void) {
  return __atomic_load_n(&g_panic_dropped, __ATOMIC_RELAXED);
}

uint64_t klog_console_panic_other(void) {
  return __atomic_load_n(&g_panic_other, __ATOMIC_RELAXED);
}

void klog_console_write(const char *message, uint64_t length) {
  if (message == 0 || length == 0U) return;
  if (klog_suppressed_by_panic()) return;
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
  if (klog_suppressed_by_panic()) return;
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
    } else if (*p == 'c') {
      /* A single character, which this understood nowhere until a diagnostic
         needed it. initramfs prints the four magic bytes it found when a
         volume header does not validate, and without %c that line reported
         the literal text %c%c%c%c -- the one message whose whole job was to
         say what was actually on the disk said nothing at all. A format this
         does not implement is not a missing feature, it is a diagnostic that
         lies at exactly the moment it is read.
         Promoted to int by the default argument promotions, so read as int. */
      char c = (char)va_arg(args, int);
      klog_char(c);
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
  if (klog_suppressed_by_panic()) return;
  if (!xaios_spin_trylock(&g_klog_lock)) {
    (void)__atomic_add_fetch(&g_klog_contended_drops, 1U, __ATOMIC_RELAXED);
    return;
  }

  /* Said before the line that got through, while the lock is held, so a reader
     of the console knows the log is lossy and by how much. */
  uint64_t lost = __atomic_exchange_n(&g_klog_contended_drops, 0U,
                                      __ATOMIC_RELAXED);
  if (lost != 0U) {
    klog_puts("klog: ");
    klog_u64(lost, 10U);
    klog_puts(" log lines dropped, the console lock was held\n");
    klog_line_flush();
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
  /* Suppressed whole, not just its prefix: klog_level prints its prefix through
     klog() and its message through klog_vformat directly, so guarding one and
     not the other would shred the dump with the other half of every line. */
  if (klog_suppressed_by_panic()) return;
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
#if XAIOS_KLOG_MMIO_UART
    klog_flush();
#endif
  }
}
