#include <xaios/arch_power.h>
#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/operations.h>
#include <xaios/timer.h>
#include <xaios/xaiboot_fs.h>

#include "operations_internal.h"

#define OPERATIONS_POWER_DELAY_NS UINT64_C(500000000)

uint32_t ops_state_persistent;
uint32_t ops_state_boot_ready;
uint32_t ops_state_rescue;
uint32_t ops_state_unclean_boots;
uint64_t ops_state_boots;
operations_power_action_t ops_state_power_action;

static uint32_t g_durable;
static uint64_t g_power_deadline_ns;

static uint32_t record_running(const char *record) {
  return record != 0 && ops_str_starts(record, "state=running\n");
}

static xaios_status_t persist_lifecycle(const char *state) {
  char record[160];
  uint64_t flushed = 0U;
  uint64_t unsupported = 0U;
  uint64_t failed = 0U;
  uint64_t used = 0U;
  xaios_status_t status = XAIOS_OK;
  record[0] = '\0';
  ops_append(record, sizeof(record), &used, "state=");
  ops_append(record, sizeof(record), &used, state);
  ops_append(record, sizeof(record), &used, "\nunclean=");
  ops_append_u64(record, sizeof(record), &used, ops_state_unclean_boots);
  ops_append(record, sizeof(record), &used, "\nboots=");
  ops_append_u64(record, sizeof(record), &used, ops_state_boots);
  ops_append(record, sizeof(record), &used, "\n");
  if (ops_state_persistent == 0U) return XAIOS_ERR_UNSUPPORTED;
  status = xaiboot_fs_write(OPERATIONS_RECORD_PATH, record, used);
  if (status == XAIOS_OK) status = xaiboot_fs_commit("lifecycle");
  if (status == XAIOS_OK) {
    /* A running marker must survive host-side power loss before SSH starts. */
    status = block_flush_all(&flushed, &unsupported, &failed);
  }
  if (status != XAIOS_OK) {
    klog("operations: lifecycle persist failed state=%s status=%d flushed=%lu unsupported=%lu failed=%lu\n",
         state, (int)status, flushed, unsupported, failed);
  }
  return status;
}

/* Say on the console, once per boot, what became of this boot's lifecycle
   record.

   The operations gate kills the first guest and asks the second what it
   inherited. Waiting for SSH before killing is not the same as waiting for
   the record the second boot reads: a guest whose state volume never mounted
   reaches SSH exactly as fast, writes its record into memory, and leaves the
   second boot with nothing to find -- which the gate then reports as a missed
   unclean boot, blaming the second guest for what the first one never wrote.
   So the machine says it itself, and says which of the two happened.

   Written through the console writer rather than klog because a release build
   turns klog's console output off at boot_ui_begin, and this line has to exist
   in the image the gate actually runs. The wordings are deliberately disjoint:
   "record durable" is the only one that means the record is on a disk, and no
   other verdict contains it. */
static void report_lifecycle(xaios_status_t status) {
  char line[160];
  uint64_t used = 0U;
  const char *verdict;
  const char *storage;
  line[0] = '\0';
  if (ops_state_persistent == 0U) {
    verdict = "absent";
    storage = "none";
  } else if (status != XAIOS_OK) {
    verdict = "unwritten";
    storage = g_durable != 0U ? "disk" : "memory";
  } else if (g_durable == 0U) {
    verdict = "volatile";
    storage = "memory";
  } else {
    verdict = "durable";
    storage = "disk";
  }
  ops_append(line, sizeof(line), &used, "lifecycle: record ");
  ops_append(line, sizeof(line), &used, verdict);
  ops_append(line, sizeof(line), &used, " state=running boots=");
  ops_append_u64(line, sizeof(line), &used, ops_state_boots);
  ops_append(line, sizeof(line), &used, " unclean=");
  ops_append_u64(line, sizeof(line), &used, ops_state_unclean_boots);
  ops_append(line, sizeof(line), &used, " storage=");
  ops_append(line, sizeof(line), &used, storage);
  ops_append(line, sizeof(line), &used, " status=");
  ops_append_status(line, sizeof(line), &used, status);
  ops_append(line, sizeof(line), &used, "\n");
  klog_console_write(line, used);
}

void operations_init(uint32_t persistent_available, uint32_t durable_storage) {
  char record[160];
  uint64_t bytes = 0U;
  xaios_xbfs_stat_t rescue;
  ops_state_persistent = persistent_available != 0U;
  g_durable = ops_state_persistent != 0U && durable_storage != 0U;
  ops_state_boot_ready = 0U;
  ops_state_rescue = 0U;
  ops_state_unclean_boots = 0U;
  ops_state_boots = 1U;
  ops_state_power_action = OPERATIONS_POWER_NONE;
  g_power_deadline_ns = 0U;
  if (ops_state_persistent != 0U) {
    (void)xaiboot_fs_mkdir("/state");
    (void)xaiboot_fs_mkdir("/state/lifecycle");
    if (xaiboot_fs_read(OPERATIONS_RECORD_PATH, record, sizeof(record) - 1U,
                        &bytes) == XAIOS_OK) {
      record[bytes] = '\0';
      ops_state_unclean_boots = (uint32_t)ops_find_decimal(record, "unclean=");
      ops_state_boots = ops_find_decimal(record, "boots=") + 1U;
      if (record_running(record) != 0U) ++ops_state_unclean_boots;
      else ops_state_unclean_boots = 0U;
    }
    if (xaiboot_fs_stat(OPERATIONS_RESCUE_PATH, &rescue) == XAIOS_OK)
      ops_state_rescue = 1U;
  }
  if (ops_state_unclean_boots >= 3U) ops_state_rescue = 1U;
  report_lifecycle(persist_lifecycle("running"));
  klog("operations: lifecycle initialized boots=%lu unclean=%u rescue=%u durable=%u\n",
       ops_state_boots, ops_state_unclean_boots, ops_state_rescue, g_durable);
}

void operations_mark_boot_ready(void) {
  ops_state_boot_ready = 1U;
  (void)persist_lifecycle("running");
}

uint32_t operations_rescue_mode(void) { return ops_state_rescue; }

void ops_request_power(operations_power_action_t action) {
  if (ops_state_power_action != OPERATIONS_POWER_NONE) return;
  ops_state_power_action = action;
  g_power_deadline_ns = timer_now_ns() + OPERATIONS_POWER_DELAY_NS;
  klog("operations: power action scheduled action=%u\n", (unsigned)action);
}

void operations_tick(void) {
  uint64_t flushed = 0U, unsupported = 0U, failed = 0U;
  if (ops_state_power_action == OPERATIONS_POWER_NONE ||
      timer_now_ns() < g_power_deadline_ns) return;
  (void)persist_lifecycle(ops_state_power_action == OPERATIONS_POWER_REBOOT
                              ? "reboot" : "clean");
  (void)klog_flush();
  xaios_status_t flush_status =
      block_flush_all(&flushed, &unsupported, &failed);
  klog("operations: storage quiesced flushed=%lu unsupported=%lu failed=%lu\n",
       flushed, unsupported, failed);
  if (flush_status != XAIOS_OK) {
    (void)persist_lifecycle("flush-failed");
    (void)klog_flush();
    ops_state_power_action = OPERATIONS_POWER_NONE;
    g_power_deadline_ns = 0U;
    klog("operations: power action cancelled because storage flush failed\n");
    return;
  }
  (void)klog_flush();
  if (ops_state_power_action == OPERATIONS_POWER_REBOOT) arch_reboot();
  arch_power_off();
}

uint32_t operations_is_command(const char *command) {
  static const char *names[] = {"shutdown", "reboot", "power", "service",
      "kill", "ifconfig", "route", "arp", "ndp", "netstat", "ping",
      "nslookup", "date", "ntp", "limits", "recovery", "update",
      "config", "support"};
  char token[24];
  const char *cursor = command;
  if (!ops_next_token(&cursor, token, sizeof(token))) return 0U;
  for (uint32_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i)
    if (ops_str_equal(token, names[i])) return 1U;
  return 0U;
}

uint32_t operations_command_allowed_in_rescue(const char *command) {
  static const char *allowed[] = {
      "help", "pwd", "ls", "cat", "less", "stat", "df", "du", "cp",
      "mv", "rm", "mkdir", "nano", "recovery", "power", "shutdown",
      "reboot", "support", "ifconfig", "netstat", "limits", "date", "ntp"};
  char name[24], action[24];
  const char *cursor = command;
  if (!ops_next_token(&cursor, name, sizeof(name))) return 0U;
  for (uint32_t i = 0U; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
    if (ops_str_equal(name, allowed[i])) return 1U;
  }
  if (!ops_str_equal(name, "update")) return 0U;
  if (!ops_next_token(&cursor, action, sizeof(action))) return 1U;
  return ops_str_equal(action, "status") && *ops_skip_spaces(cursor) == '\0';
}

void operations_self_test(void) {
  kassert(ops_str_equal(ops_pressure_name(100U, 100U, 1U), "normal"));
  kassert(ops_str_equal(ops_pressure_name(10U, 100U, 1U), "warning"));
  kassert(ops_str_equal(ops_pressure_name(4U, 100U, 1U), "critical"));
  uint32_t ip = 0U;
  kassert(ops_parse_ipv4("10.0.2.15", &ip) == XAIOS_OK);
  kassert(ip == UINT32_C(0x0a00020f));
  kassert(ops_parse_ipv4("10.0.2.999", &ip) == XAIOS_ERR_INVALID);
  kassert(record_running("state=running\nunclean=2\n") != 0U);
  kassert(operations_command_allowed_in_rescue("ls /state") != 0U);
  kassert(operations_command_allowed_in_rescue("update status") != 0U);
  kassert(operations_command_allowed_in_rescue("update rollback") == 0U);
  kassert(operations_command_allowed_in_rescue("lstm-xor") == 0U);
  klog("operations: self-test passed\n");
}
