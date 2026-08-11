#include <xaios/assert.h>
#include <xaios/arch_power.h>
#include <xaios/klog.h>
#include <xaios/mutable_fs.h>
#include <xaios/timer.h>
#include <xaios/watchdog.h>

static uint64_t g_watchdog_deadline_ns;
static uint32_t g_watchdog_active;

void watchdog_init(void) {
  g_watchdog_deadline_ns =
      timer_now_ns() +
      (uint64_t)XAIOS_WATCHDOG_TIMEOUT_SECONDS * UINT64_C(1000000000);
  g_watchdog_active = 1;
  klog("watchdog: initialized timeout=%u s deadline=%lu ns\n",
       XAIOS_WATCHDOG_TIMEOUT_SECONDS, g_watchdog_deadline_ns);
}

void watchdog_kick(void) {
  if (g_watchdog_active == 0) {
    return;
  }
  g_watchdog_deadline_ns =
      timer_now_ns() +
      (uint64_t)XAIOS_WATCHDOG_TIMEOUT_SECONDS * UINT64_C(1000000000);
}

void watchdog_trigger_reset(void) {
  g_watchdog_active = 0;
  klog("watchdog: triggering PSCI system reset\n");

  arch_reboot();
}

uint32_t watchdog_is_active(void) {
  return g_watchdog_active;
}

void watchdog_self_test(void) {
  kassert(g_watchdog_active != 0);

  uint64_t deadline_before = g_watchdog_deadline_ns;
  /* Spin briefly then kick */
  for (volatile uint64_t spin = 0; spin < UINT64_C(10000); ++spin) {
  }
  watchdog_kick();
  kassert(g_watchdog_deadline_ns >= deadline_before);

  klog("watchdog: self-test passed active=%u deadline=%lu\n",
       g_watchdog_active, g_watchdog_deadline_ns);
}

/* ---- Boot counter (persisted to mutable_fs) ---- */

static uint32_t parse_u32_simple(const char *buf, uint64_t size) {
  uint32_t value = 0;
  for (uint64_t i = 0; i < size; ++i) {
    char ch = buf[i];
    if (ch < '0' || ch > '9') {
      break;
    }
    value = value * 10U + (uint32_t)(ch - '0');
  }
  return value;
}

static void format_u32(uint32_t value, char *buf, uint64_t *out_len) {
  char tmp[12];
  uint32_t idx = 0;
  if (value == 0) {
    buf[0] = '0';
    *out_len = 1;
    return;
  }
  while (value != 0 && idx < sizeof(tmp)) {
    tmp[idx++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  /* Reverse */
  for (uint32_t i = 0; i < idx; ++i) {
    buf[i] = tmp[idx - 1U - i];
  }
  *out_len = idx;
}

uint32_t boot_counter_read(void) {
  char buf[16];
  uint64_t read_size = 0;
  for (uint64_t i = 0; i < sizeof(buf); ++i) {
    buf[i] = 0;
  }
  xaios_status_t status =
      mutable_fs_read(XAIOS_BOOT_COUNTER_PATH, buf, sizeof(buf) - 1U, &read_size);
  if (status != XAIOS_OK || read_size == 0) {
    return 0;
  }
  return parse_u32_simple(buf, read_size);
}

void boot_counter_increment(void) {
  uint32_t count = boot_counter_read() + 1U;
  char buf[16];
  uint64_t len = 0;
  for (uint64_t i = 0; i < sizeof(buf); ++i) {
    buf[i] = 0;
  }
  format_u32(count, buf, &len);
  mutable_fs_write(XAIOS_BOOT_COUNTER_PATH, buf, len);
  klog("boot: counter incremented count=%u\n", count);
}

void boot_counter_reset(void) {
  char buf[2] = {'0', 0};
  mutable_fs_write(XAIOS_BOOT_COUNTER_PATH, buf, 1);
  klog("boot: counter reset\n");
}

uint32_t boot_in_recovery_mode(void) {
  uint32_t count = boot_counter_read();
  return count > XAIOS_BOOT_THRESHOLD ? 1U : 0U;
}
