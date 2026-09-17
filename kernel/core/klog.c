#include <stdarg.h>
#include <xaios/klog.h>
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

#include "klog_internal.h"

#define XAIOS_CONSOLE_CAPTURE_DEPTH 8U

typedef struct xaios_console_capture {
  char *buffer;
  uint64_t capacity;
  uint64_t length;
} xaios_console_capture_t;

static xaios_spinlock_t g_klog_lock;
/* Set by the hart that is panicking; see klog_console_panic_claim below.
   Plain integers touched only through the atomics, because several harts
   reach them at once and the numbers are reported. */
static uint32_t g_panic_active;
static uint64_t g_panic_dropped;
/* Contended drops, counted by the context that lost the line: a drop inside a
 * handler is the short wait working as designed, and one outside a handler is
 * the budget still being wrong (B-119). */
static uint64_t g_klog_drops_in_handler;
static uint64_t g_klog_drops_masked;
static uint64_t g_panic_other;

/* How long a contended line waits for the console lock before it is dropped.
 *
 * Measured, not guessed: a bound of 200 microseconds changed nothing on the
 * x86-64 smoke -- two to four lines were still lost per boot -- because the
 * holder is not finishing a word, it is writing a whole line to a console that
 * traps per character under emulation, and a long line takes milliseconds.
 *
 * So the wait depends on what the caller is. A line printed from a thread may
 * wait as long as a line takes, because that is what the lock is for and the
 * thread has nothing it must return to. A line printed from an interrupt
 * handler may not: the holder can be the very thread this handler interrupted,
 * which cannot run again until the handler returns, so waiting there is waiting
 * for something that cannot happen and the line is dropped after a short try.
 * The console lock is a leaf -- nothing takes it and then another lock, and the
 * ring it feeds is only ever taken underneath it -- so the long wait cannot
 * deadlock against anything. */
#define KLOG_LOCK_WAIT_NS UINT64_C(5000000)     /* thread context: 5 ms */
#define KLOG_LOCK_IRQ_WAIT_NS UINT64_C(200000)  /* interrupt context: 200 us */
#define KLOG_LOCK_MAX_ATTEMPTS UINT32_C(10000000)

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

void klog_init(const xaios_boot_info_t *boot) {
  klog_uart_bind(boot);
  xaios_spin_init(&g_klog_lock);
  klog_console_set_log_output(1U);
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
    if (message[i] == '\n') klog_console_putc_raw('\r');
    klog_console_putc_raw(message[i]);
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

void klog_puts(const char *message) {
  while (*message != '\0') {
    klog_console_emit(*message++);
  }
}

void klog_write(const char *message, uint64_t length) {
  for (uint64_t i = 0; i < length; ++i) {
    klog_console_emit(message[i]);
  }
}

void klog_write_atomic(const char *message, uint64_t length) {
  if (message == 0 || length == 0U) return;
  if (klog_suppressed_by_panic()) return;
  xaios_spin_lock(&g_klog_lock);
  klog_write(message, length);
  klog_console_line_flush();
  xaios_spin_unlock(&g_klog_lock);
}

void klog(const char *fmt, ...) {
  if (klog_suppressed_by_panic()) return;
  /* A contended line waits for the lock before it is dropped.
   *
   * Dropping on the first try was too eager, and B-119 is the measurement: a
   * console under load lost the one line a gate was asserting on -- the
   * x86-64 secondary-worker barrier, printed once, gone -- while the rest of
   * the boot was perfect, and the gate failed a guest that had done the work.
   * The lock is still not blocked for: the wait is bounded by
   * KLOG_LOCK_WAIT_NS, so a context that must not block waits at most that
   * long, and a line that loses the race even then is still dropped and still
   * counted. What the bound is not is zero, because the holder is usually
   * finishing a line rather than a report, and that is a wait worth taking. */
  int locked = xaios_spin_trylock(&g_klog_lock);
  if (!locked) {
    uint64_t started = timer_now_ns();
    uint32_t attempts = 0U;
    /* The question is whether this CPU is inside a handler, not whether
     * interrupts are masked. A thread that holds a kernel spinlock is masked
     * too, and its lock is held by another CPU, which will release -- so
     * shortening the wait there loses lines that had time to get through. The
     * barrier line B-119's first fix was written for is exactly that case: it
     * is printed from inside the scheduler guard, with interrupts masked and
     * no handler anywhere near it, and the runner dropped it anyway. Only a
     * CPU inside a handler may be waiting for a lock its own interrupted
     * context holds, and only there is the wait shortened. */
    uint64_t budget = xaios_cpu_in_interrupt() != 0 ? KLOG_LOCK_IRQ_WAIT_NS
                                                    : KLOG_LOCK_WAIT_NS;
    /* Bounded twice: by the elapsed time, which is what the bound means, and
       by an attempt count, because the first lines of a boot can be printed
       before the time source is worth reading and a zero-length elapsed time
       would otherwise make the wait unbounded. */
    while (timer_now_ns() - started < budget &&
           ++attempts < KLOG_LOCK_MAX_ATTEMPTS) {
      if (xaios_spin_trylock(&g_klog_lock)) {
        locked = 1;
        break;
      }
      xaios_cpu_relax();
    }
  }
  if (!locked) {
    /* Counted apart, because which context loses a line is the whole question
       the next sighting has to answer: a handler drop is the shortened wait
       working as designed, and a non-handler drop is this budget still being
       wrong. */
    (void)__atomic_add_fetch(&g_klog_contended_drops, 1U, __ATOMIC_RELAXED);
    if (xaios_cpu_in_interrupt() != 0) {
      (void)__atomic_add_fetch(&g_klog_drops_in_handler, 1U, __ATOMIC_RELAXED);
    }
    (void)__atomic_add_fetch(
        &g_klog_drops_masked,
        xaios_interrupts_enabled() == 0 ? 1U : 0U, __ATOMIC_RELAXED);
    return;
  }

  /* Said before the line that got through, while the lock is held, so a reader
     of the console knows the log is lossy and by how much. */
  uint64_t lost = __atomic_exchange_n(&g_klog_contended_drops, 0U,
                                      __ATOMIC_RELAXED);
  if (lost != 0U) {
    uint64_t in_handler = __atomic_exchange_n(&g_klog_drops_in_handler, 0U,
                                              __ATOMIC_RELAXED);
    uint64_t masked = __atomic_exchange_n(&g_klog_drops_masked, 0U,
                                          __ATOMIC_RELAXED);
    klog_puts("klog: ");
    klog_format_u64(lost, 10U);
    klog_puts(" log lines dropped, the console lock was held in_handler=");
    klog_format_u64(in_handler, 10U);
    klog_puts(" masked=");
    klog_format_u64(masked, 10U);
    klog_puts("\n");
    klog_console_line_flush();
  }

  va_list args;
  va_start(args, fmt);
  klog_format_v(fmt, args);
  klog_console_line_flush();
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
  klog_format_v(fmt, args);
  klog_console_line_flush();
  va_end(args);

  /* Flush ring immediately on panic */
  if (level == XAIOS_LOG_PANIC) {
#if XAIOS_KLOG_MMIO_UART
    klog_flush();
#endif
  }
}
