/* Time on RISC-V: one counter, and firmware to schedule against it.
 *
 * The counter is `time`, readable from supervisor mode with rdtime, running
 * at a frequency the device tree declares -- 10 MHz on QEMU's virt board and
 * not a constant anywhere else. Reading the frequency rather than assuming it
 * is the difference between a kernel that keeps time on one machine and a
 * kernel that keeps time.
 *
 * Scheduling an interrupt against it is not something supervisor mode can do
 * directly: the comparator lives in machine mode. SBI's TIME extension exists
 * precisely for that, and asking firmware is the supported path rather than a
 * workaround.
 */
#include <xaios/exception.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/status.h>
#include <xaios/timer.h>

void klog(const char *fmt, ...);
void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn));
#define timer_panic(...) panic_at(__FILE__, __LINE__, __VA_ARGS__)

#define SBI_TIME_SET_TIMER UINT64_C(0)
#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)
/* Only used if the device tree omits the frequency, which would be a
   malformed tree; kept so a missing property degrades to a wrong rate rather
   than a division by zero. */
#define FALLBACK_FREQUENCY_HZ UINT64_C(10000000)

static uint64_t g_frequency_hz = FALLBACK_FREQUENCY_HZ;
static int g_have_stimecmp;
static uint64_t g_boot_counter;
static uint64_t g_period_ticks;
static const void *g_device_tree;

void riscv64_timer_set_device_tree(const void *blob) { g_device_tree = blob; }
const void *riscv64_device_tree(void) { return g_device_tree; }
int riscv64_timer_has_stimecmp(void) { return g_have_stimecmp; }

typedef struct frequency_search {
  uint64_t hz;
  int found;
} frequency_search_t;

static int property_is(const char *name, const char *wanted) {
  while (*wanted != '\0' && *name == *wanted) {
    ++name;
    ++wanted;
  }
  return *name == '\0' && *wanted == '\0';
}

static void find_frequency(const fdt_property_t *property, void *context) {
  frequency_search_t *search = (frequency_search_t *)context;
  if (search->found != 0) return;
  if (!property_is(property->name, "timebase-frequency")) return;
  if (property->length < 4U) return;
  const uint8_t *value = property->value;
  search->hz = ((uint64_t)value[0] << 24) | ((uint64_t)value[1] << 16) |
               ((uint64_t)value[2] << 8) | (uint64_t)value[3];
  search->found = 1;
}

uint64_t timer_counter(void) {
  uint64_t value = 0U;
  __asm__ volatile("rdtime %0" : "=r"(value));
  return value;
}

uint64_t timer_frequency_hz(void) { return g_frequency_hz; }

/* Where the next timer interrupt is scheduled, and by which of the two
 * mechanisms this machine actually has.
 *
 * Sstc gives supervisor mode its own comparator, `stimecmp`, and the pending
 * bit is then derived from it directly: writing it is both the way to arm the
 * timer and the only way to acknowledge one. SBI's TIME extension is the
 * older route, and asks firmware to do the same thing one privilege level up.
 *
 * Preferring stimecmp is not only about the ecall it saves on every tick. On
 * a machine where firmware has enabled Sstc, the pending bit follows
 * stimecmp and an SBI call that programs the machine-mode comparator instead
 * moves a register nothing is looking at -- so the interrupt is never
 * acknowledged, fires again the instant it returns, and the kernel makes
 * about one instruction of progress per tick. That is not hypothetical: it is
 * what booting under EDK2 did, and it presented as a kernel frozen inside a
 * memset with no fault and a healthy-looking timer.
 */

#define CSR_STIMECMP 0x14D

static void set_timer(uint64_t absolute_ticks) {
  /* Both, when both exist.
   *
   * Whether stimecmp drives the pending bit depends on menvcfg.STCE, which is
   * a machine-mode bit a supervisor cannot read: the CSR is present and
   * writable either way, so "does this register exist" is not the same
   * question as "does writing it acknowledge the interrupt". Programming both
   * costs one ecall on a machine that did not need it and is correct on both
   * kinds; programming only the one that turns out to be inert is a timer
   * that never stops firing. */
  if (g_have_stimecmp != 0) {
    __asm__ volatile("csrw 0x14d, %0" : : "r"(absolute_ticks) : "memory");
  }
  register uint64_t a0 __asm__("a0") = absolute_ticks;
  register uint64_t a6 __asm__("a6") = SBI_TIME_SET_TIMER;
  register uint64_t a7 __asm__("a7") = SBI_EXT_TIME;
  __asm__ volatile("ecall" : "+r"(a0) : "r"(a6), "r"(a7) : "memory");
}

/* Whether this hart has stimecmp, asked rather than assumed. Reading a CSR
   the hardware does not implement raises an illegal instruction, which the
   probe turns into an answer instead of a panic. */
static int detect_stimecmp(void) {
  uint64_t value = 0U;
  exception_mmio_probe_begin();
  __asm__ volatile("csrr %0, 0x14d" : "=r"(value) : : "memory");
  exception_mmio_probe_end();
  (void)value;
  return exception_mmio_probe_faulted() == 0;
}

void timer_init(void) {
  frequency_search_t search = {0U, 0};
  if (g_device_tree != 0) fdt_walk(g_device_tree, find_frequency, &search);
  if (search.found != 0 && search.hz != 0U) {
    g_frequency_hz = search.hz;
  } else {
    klog("timer: the device tree declares no timebase-frequency; assuming "
         "%lu Hz, which will keep the wrong time if that is not this "
         "machine's rate\n", FALLBACK_FREQUENCY_HZ);
  }
  g_boot_counter = timer_counter();
  g_have_stimecmp = detect_stimecmp();
  klog("timer: riscv64 rdtime frequency=%lu Hz sbi_time=%d stimecmp=%d\n",
       g_frequency_hz, sbi_probe_extension(SBI_EXT_TIME), g_have_stimecmp);
}

uint64_t timer_now_ns(void) {
  uint64_t elapsed = timer_counter() - g_boot_counter;
  /* Scaled in two steps so a 10 MHz counter does not overflow on the way to
     nanoseconds. Multiplying first would wrap after about eighteen minutes of
     uptime at this frequency, and the result would look like time running
     backwards rather than like an overflow. */
  uint64_t seconds = elapsed / g_frequency_hz;
  uint64_t remainder = elapsed % g_frequency_hz;
  return seconds * NANOSECONDS_PER_SECOND +
         (remainder * NANOSECONDS_PER_SECOND) / g_frequency_hz;
}

void timer_enable_periodic(uint32_t hz) {
  if (hz == 0U) return;
  g_period_ticks = g_frequency_hz / hz;
  if (g_period_ticks == 0U) g_period_ticks = 1U;
  timer_rearm();
}

/* RISC-V has no periodic mode: the comparator fires once and has to be set
   again. Rearming from the deadline that just passed rather than from "now"
   keeps the period from drifting by however long the handler took. */
void timer_rearm(void) {
  /* Always reprogram, even with no period set.
     RISC-V has no way to acknowledge a timer interrupt: the pending bit is
     cleared by writing a new comparator and by nothing else. Returning early
     when no period is configured therefore left the interrupt pending, and
     the moment sstatus.SIE was set the hart trapped, returned, and trapped
     again forever. The symptom was a kernel that stopped between two log
     lines with no fault, which is the least informative way a livelock can
     present. */
  if (g_period_ticks == 0U) {
    set_timer(UINT64_MAX);
    return;
  }
  set_timer(timer_counter() + g_period_ticks);
}

void timer_mask_local(void) {
  /* Clear the supervisor timer interrupt enable. Masking rather than
     cancelling, so a rearm does not have to know it was ever masked. */
  __asm__ volatile("csrc sie, %0" : : "r"(UINT64_C(1) << 5));
}

void timer_disable(void) {
  g_period_ticks = 0U;
  timer_mask_local();
  /* Push the comparator past any plausible uptime so a pending interrupt
     does not arrive after the caller believes the timer is off. */
  set_timer(UINT64_MAX);
}

/* Counter ticks for a duration, rounded up so a wait never ends early. */
static uint64_t duration_ticks(uint64_t duration_ns) {
  uint64_t seconds = duration_ns / NANOSECONDS_PER_SECOND;
  uint64_t remainder = duration_ns % NANOSECONDS_PER_SECOND;
  if (seconds > UINT64_MAX / g_frequency_hz) return UINT64_MAX;
  uint64_t ticks = seconds * g_frequency_hz;
  uint64_t fractional =
      (remainder * g_frequency_hz + (NANOSECONDS_PER_SECOND - 1U)) /
      NANOSECONDS_PER_SECOND;
  return ticks > UINT64_MAX - fractional ? UINT64_MAX : ticks + fractional;
}

/* Wait for a deadline with the hart asleep, on any hart.
 *
 * This used to be `wfi` in a loop and nothing else, which waits for whatever
 * interrupt happens to come. On the boot hart the periodic tick comes; on a
 * worker hart the local timer is masked by design -- kernel workers are
 * event-driven -- and nothing comes. A syscall that asked to idle from a
 * worker hart therefore slept for ever, and the first program to ask was
 * the process monitor: its first request is a quarter-second wait, and the
 * machine went silent the moment it entered user mode.
 *
 * The same shape as AArch64: arm a one-shot comparator at the deadline,
 * enable the timer interrupt around the wait so a pending timer is what wakes
 * the hart, and put the mask and the periodic schedule back afterwards. The
 * global interrupt enable is left as the caller had it, so a wait from inside
 * a syscall wakes without taking the trap. */
void timer_idle_until(uint64_t deadline_ns) {
  uint64_t sie = 0U;
  __asm__ volatile("csrr %0, sie" : "=r"(sie));
  for (;;) {
    uint64_t now_ns = timer_now_ns();
    if (now_ns >= deadline_ns) break;
    uint64_t ticks = duration_ticks(deadline_ns - now_ns);
    uint64_t counter = timer_counter();
    uint64_t compare = ticks > UINT64_MAX - counter
                           ? UINT64_MAX
                           : counter + (ticks == 0U ? 1U : ticks);
    set_timer(compare);
    __asm__ volatile("csrs sie, %0" : : "r"(UINT64_C(1) << 5) : "memory");
    __asm__ volatile("wfi" ::: "memory");
  }
  if ((sie & (UINT64_C(1) << 5)) == 0U) timer_mask_local();
  /* Back to the periodic schedule, or to nothing; either write clears the
     pending bit the one-shot left behind. */
  timer_rearm();
}

void timer_self_test(void) {
  uint64_t first = timer_now_ns();
  /* Busy rather than idle: wfi with no interrupt armed would wait forever,
     and a self-test that hangs when the timer is broken has reported nothing
     about the timer. */
  for (volatile uint32_t spin = 0U; spin < 100000U; ++spin) {
  }
  uint64_t second = timer_now_ns();
  if (second <= first) {
    timer_panic("timer did not advance: %lu then %lu", first, second);
  }
  /* The counter and the nanosecond clock have to agree about direction. They
     are separate reads of the same hardware through different arithmetic, and
     a scaling bug shows up here rather than as a slightly wrong uptime. */
  uint64_t ticks_before = timer_counter();
  for (volatile uint32_t spin = 0U; spin < 100000U; ++spin) {
  }
  if (timer_counter() <= ticks_before) {
    timer_panic("the raw counter did not advance while the clock did");
  }
  klog("timer: self-test passed advance=%lu ns frequency=%lu Hz\n",
       second - first, g_frequency_hz);
}

/* Wall time.
 *
 * The virt board has a Goldfish RTC, but reading it needs a driver this port
 * does not have yet, so wall time is anchored at zero and advances with the
 * monotonic clock. That is honest rather than convenient: it means the epoch
 * is unknown, which callers can see, instead of a plausible-looking date that
 * is wrong by decades. */
static uint64_t g_wall_epoch_ns;
static uint32_t g_wall_source;

void wall_time_calibrate(void) {
  g_wall_epoch_ns = 0U;
  g_wall_source = 0U;
  klog("wall-time: riscv64 has no clock source yet; the epoch is unknown and "
       "uptime is what advances\n");
}

uint64_t wall_time_now_ns(void) { return g_wall_epoch_ns + timer_now_ns(); }

xaios_status_t wall_time_set_ns(uint64_t epoch_ns, uint32_t source) {
  g_wall_epoch_ns = epoch_ns > timer_now_ns() ? epoch_ns - timer_now_ns() : 0U;
  g_wall_source = source;
  return XAIOS_OK;
}

xaios_status_t wall_time_discipline_ns(uint64_t epoch_ns, uint32_t source,
                                       uint32_t maximum_ppm) {
  (void)maximum_ppm;
  return wall_time_set_ns(epoch_ns, source);
}

int64_t wall_time_slew_remaining_ns(void) { return 0; }

uint32_t wall_time_source(void) { return g_wall_source; }
