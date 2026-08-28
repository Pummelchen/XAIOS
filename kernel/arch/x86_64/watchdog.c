#include <xaios/assert.h>
#include <xaios/arch_power.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/timer.h>
#include <xaios/watchdog.h>

static uint64_t g_watchdog_deadline_ns;
static uint32_t g_watchdog_active;

void watchdog_init(void) {
  g_watchdog_deadline_ns =
      timer_now_ns() +
      (uint64_t)XAIOS_WATCHDOG_TIMEOUT_SECONDS * UINT64_C(1000000000);
  g_watchdog_active = 1U;
  klog("watchdog: initialized timeout=%u s deadline=%lu ns\n",
       XAIOS_WATCHDOG_TIMEOUT_SECONDS, g_watchdog_deadline_ns);
}

void watchdog_kick(void) {
  if (g_watchdog_active == 0U) return;
  g_watchdog_deadline_ns =
      timer_now_ns() +
      (uint64_t)XAIOS_WATCHDOG_TIMEOUT_SECONDS * UINT64_C(1000000000);
}

void watchdog_trigger_reset(void) {
  g_watchdog_active = 0U;
  klog("watchdog: triggering architecture reset\n");
  arch_reboot();
}

uint32_t watchdog_is_active(void) { return g_watchdog_active; }

void watchdog_self_test(void) {
  kassert(g_watchdog_active != 0U);
  uint64_t before = g_watchdog_deadline_ns;
  watchdog_kick();
  kassert(g_watchdog_deadline_ns >= before);
  klog("watchdog: self-test passed active=%u deadline=%lu\n",
       g_watchdog_active, g_watchdog_deadline_ns);
}

static uint32_t parse_u32(const char *buffer, uint64_t size) {
  uint32_t value = 0U;
  for (uint64_t index = 0U; index < size; ++index) {
    if (buffer[index] < '0' || buffer[index] > '9') break;
    value = value * 10U + (uint32_t)(buffer[index] - '0');
  }
  return value;
}

static uint64_t format_u32(uint32_t value, char *buffer) {
  char reverse[12];
  uint64_t count = 0U;
  if (value == 0U) {
    buffer[0] = '0';
    return 1U;
  }
  while (value != 0U && count < sizeof(reverse)) {
    reverse[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  for (uint64_t index = 0U; index < count; ++index) {
    buffer[index] = reverse[count - index - 1U];
  }
  return count;
}

uint32_t boot_counter_read(void) {
  char buffer[16] = {0};
  uint64_t size = 0U;
  if (xaiboot_fs_read(XAIOS_BOOT_COUNTER_PATH, buffer, sizeof(buffer) - 1U,
                      &size) != XAIOS_OK) {
    return 0U;
  }
  return parse_u32(buffer, size);
}

void boot_counter_increment(void) {
  char buffer[16] = {0};
  uint32_t value = boot_counter_read() + 1U;
  uint64_t size = format_u32(value, buffer);
  (void)xaiboot_fs_write(XAIOS_BOOT_COUNTER_PATH, buffer, size);
  klog("boot: counter incremented count=%u\n", value);
}

void boot_counter_reset(void) {
  (void)xaiboot_fs_write(XAIOS_BOOT_COUNTER_PATH, "0", 1U);
  klog("boot: counter reset\n");
}

uint32_t boot_in_recovery_mode(void) {
  return boot_counter_read() > XAIOS_BOOT_THRESHOLD ? 1U : 0U;
}
