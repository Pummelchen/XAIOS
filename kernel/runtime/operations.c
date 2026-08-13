#include <xaios/admin_control.h>
#include <xaios/arch_power.h>
#include <xaios/arp.h>
#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/dns.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/mutable_fs.h>
#include <xaios/ndp.h>
#include <xaios/network_stack.h>
#include <xaios/ntp.h>
#include <xaios/operations.h>
#include <xaios/pmm.h>
#include <xaios/routing.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/update.h>
#include <xaios/user.h>

#define OPERATIONS_RECORD_PATH "/state/lifecycle/record"
#define OPERATIONS_RESCUE_PATH "/state/lifecycle/rescue"
#define OPERATIONS_POWER_DELAY_NS UINT64_C(500000000)

#ifndef XAIOS_BUILD_IDENTIFIER
#define XAIOS_BUILD_IDENTIFIER "xaios-admin-control-dirty"
#endif
#ifndef XAIOS_BUILD_REVISION
#define XAIOS_BUILD_REVISION "unknown"
#endif
#ifndef XAIOS_BUILD_MODE
#define XAIOS_BUILD_MODE "unknown"
#endif

typedef enum operations_power_action {
  OPERATIONS_POWER_NONE = 0,
  OPERATIONS_POWER_OFF = 1,
  OPERATIONS_POWER_REBOOT = 2,
} operations_power_action_t;

static uint32_t g_persistent;
static uint32_t g_boot_ready;
static uint32_t g_rescue;
static uint32_t g_unclean_boots;
static uint64_t g_boots;
static operations_power_action_t g_power_action;
static uint64_t g_power_deadline_ns;

static uint64_t str_len(const char *value) {
  uint64_t length = 0U;
  if (value == 0) return 0U;
  while (value[length] != '\0') ++length;
  return length;
}

static uint32_t str_equal(const char *left, const char *right) {
  uint64_t i = 0U;
  if (left == 0 || right == 0) return 0U;
  while (left[i] != '\0' && right[i] != '\0' && left[i] == right[i]) ++i;
  return left[i] == '\0' && right[i] == '\0';
}

static uint32_t str_starts(const char *value, const char *prefix) {
  uint64_t i = 0U;
  if (value == 0 || prefix == 0) return 0U;
  while (prefix[i] != '\0' && value[i] == prefix[i]) ++i;
  return prefix[i] == '\0';
}

static const char *skip_spaces(const char *value) {
  while (*value == ' ' || *value == '\t') ++value;
  return value;
}

static uint32_t next_token(const char **cursor, char *token,
                           uint64_t capacity) {
  uint64_t i = 0U;
  const char *value = skip_spaces(*cursor);
  if (*value == '\0' || capacity == 0U) return 0U;
  while (*value != '\0' && *value != ' ' && *value != '\t') {
    if (i + 1U >= capacity) return 0U;
    token[i++] = *value++;
  }
  token[i] = '\0';
  *cursor = value;
  return 1U;
}

static void append(char *output, uint64_t capacity, uint64_t *used,
                   const char *value) {
  if (output == 0 || used == 0 || capacity == 0U || value == 0) return;
  while (*value != '\0' && *used + 1U < capacity) {
    output[*used] = *value++;
    ++*used;
  }
  output[*used] = '\0';
}

static void append_u64(char *output, uint64_t capacity, uint64_t *used,
                       uint64_t value) {
  char digits[21];
  uint32_t count = 0U;
  if (value == 0U) {
    append(output, capacity, used, "0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  while (count != 0U) {
    char text[2] = {digits[--count], '\0'};
    append(output, capacity, used, text);
  }
}

static void append_status(char *output, uint64_t capacity, uint64_t *used,
                          xaios_status_t status) {
  if (status == XAIOS_OK) append(output, capacity, used, "ok");
  else {
    append(output, capacity, used, "error(");
    append_u64(output, capacity, used, (uint64_t)(uint32_t)(-status));
    append(output, capacity, used, ")");
  }
}

static void append_ipv4(char *output, uint64_t capacity, uint64_t *used,
                        uint32_t ip) {
  append_u64(output, capacity, used, ip >> 24U);
  append(output, capacity, used, ".");
  append_u64(output, capacity, used, (ip >> 16U) & 0xffU);
  append(output, capacity, used, ".");
  append_u64(output, capacity, used, (ip >> 8U) & 0xffU);
  append(output, capacity, used, ".");
  append_u64(output, capacity, used, ip & 0xffU);
}

static void append_hex16(char *output, uint64_t capacity, uint64_t *used,
                         uint16_t value) {
  static const char digits[] = "0123456789abcdef";
  char text[5];
  uint32_t position = 0U;
  uint32_t started = 0U;
  for (int32_t shift = 12; shift >= 0; shift -= 4) {
    uint8_t digit = (uint8_t)((value >> (uint32_t)shift) & 0x0fU);
    if (digit != 0U || started != 0U || shift == 0) {
      text[position++] = digits[digit];
      started = 1U;
    }
  }
  text[position] = '\0';
  append(output, capacity, used, text);
}

static void append_ipv6(char *output, uint64_t capacity, uint64_t *used,
                        const xaios_ip_addr_t *address) {
  for (uint32_t group = 0U; group < 8U; ++group) {
    if (group != 0U) append(output, capacity, used, ":");
    append_hex16(output, capacity, used,
                 (uint16_t)(((uint16_t)address->addr[group * 2U] << 8U) |
                            address->addr[group * 2U + 1U]));
  }
}

static xaios_status_t parse_u64(const char *text, uint64_t *value) {
  uint64_t result = 0U;
  if (text == 0 || *text == '\0' || value == 0) return XAIOS_ERR_INVALID;
  while (*text != '\0') {
    if (*text < '0' || *text > '9' ||
        result > (UINT64_MAX - (uint64_t)(*text - '0')) / 10U)
      return XAIOS_ERR_INVALID;
    result = result * 10U + (uint64_t)(*text++ - '0');
  }
  *value = result;
  return XAIOS_OK;
}

static xaios_status_t parse_ipv4(const char *text, uint32_t *ip) {
  uint32_t result = 0U;
  if (text == 0 || ip == 0) return XAIOS_ERR_INVALID;
  for (uint32_t part = 0U; part < 4U; ++part) {
    uint32_t value = 0U;
    uint32_t digits = 0U;
    while (*text >= '0' && *text <= '9') {
      value = value * 10U + (uint32_t)(*text++ - '0');
      if (++digits > 3U || value > 255U) return XAIOS_ERR_INVALID;
    }
    if (digits == 0U || (part < 3U && *text++ != '.') ||
        (part == 3U && *text != '\0')) return XAIOS_ERR_INVALID;
    result = (result << 8U) | value;
  }
  *ip = result;
  return XAIOS_OK;
}

static uint64_t find_decimal(const char *text, const char *key) {
  uint64_t key_len = str_len(key);
  if (text == 0) return 0U;
  for (uint64_t i = 0U; text[i] != '\0'; ++i) {
    uint64_t j = 0U;
    while (j < key_len && text[i + j] == key[j]) ++j;
    if (j == key_len) {
      uint64_t value = 0U;
      const char *cursor = text + i + key_len;
      while (*cursor >= '0' && *cursor <= '9')
        value = value * 10U + (uint64_t)(*cursor++ - '0');
      return value;
    }
  }
  return 0U;
}

static uint32_t record_running(const char *record) {
  return record != 0 && str_starts(record, "state=running\n");
}

static void persist_lifecycle(const char *state) {
  char record[160];
  uint64_t used = 0U;
  record[0] = '\0';
  append(record, sizeof(record), &used, "state=");
  append(record, sizeof(record), &used, state);
  append(record, sizeof(record), &used, "\nunclean=");
  append_u64(record, sizeof(record), &used, g_unclean_boots);
  append(record, sizeof(record), &used, "\nboots=");
  append_u64(record, sizeof(record), &used, g_boots);
  append(record, sizeof(record), &used, "\n");
  if (g_persistent != 0U) {
    (void)mutable_fs_write(OPERATIONS_RECORD_PATH, record, used);
    (void)mutable_fs_commit("lifecycle");
  }
}

void operations_init(uint32_t persistent_available) {
  char record[160];
  uint64_t bytes = 0U;
  xaios_mfs_stat_t rescue;
  g_persistent = persistent_available != 0U;
  g_boot_ready = 0U;
  g_rescue = 0U;
  g_unclean_boots = 0U;
  g_boots = 1U;
  g_power_action = OPERATIONS_POWER_NONE;
  g_power_deadline_ns = 0U;
  if (g_persistent != 0U) {
    (void)mutable_fs_mkdir("/state");
    (void)mutable_fs_mkdir("/state/lifecycle");
    if (mutable_fs_read(OPERATIONS_RECORD_PATH, record, sizeof(record) - 1U,
                        &bytes) == XAIOS_OK) {
      record[bytes] = '\0';
      g_unclean_boots = (uint32_t)find_decimal(record, "unclean=");
      g_boots = find_decimal(record, "boots=") + 1U;
      if (record_running(record) != 0U) ++g_unclean_boots;
      else g_unclean_boots = 0U;
    }
    if (mutable_fs_stat(OPERATIONS_RESCUE_PATH, &rescue) == XAIOS_OK)
      g_rescue = 1U;
  }
  if (g_unclean_boots >= 3U) g_rescue = 1U;
  persist_lifecycle("running");
  klog("operations: lifecycle initialized boots=%lu unclean=%u rescue=%u\n",
       g_boots, g_unclean_boots, g_rescue);
}

void operations_mark_boot_ready(void) {
  g_boot_ready = 1U;
  persist_lifecycle("running");
}

uint32_t operations_rescue_mode(void) { return g_rescue; }

static void request_power(operations_power_action_t action) {
  if (g_power_action != OPERATIONS_POWER_NONE) return;
  g_power_action = action;
  g_power_deadline_ns = timer_now_ns() + OPERATIONS_POWER_DELAY_NS;
  klog("operations: power action scheduled action=%u\n", (unsigned)action);
}

void operations_tick(void) {
  uint64_t flushed = 0U, unsupported = 0U, failed = 0U;
  if (g_power_action == OPERATIONS_POWER_NONE ||
      timer_now_ns() < g_power_deadline_ns) return;
  persist_lifecycle(g_power_action == OPERATIONS_POWER_REBOOT
                        ? "reboot" : "clean");
  (void)klog_flush();
  xaios_status_t flush_status =
      block_flush_all(&flushed, &unsupported, &failed);
  klog("operations: storage quiesced flushed=%lu unsupported=%lu failed=%lu\n",
       flushed, unsupported, failed);
  if (flush_status != XAIOS_OK) {
    persist_lifecycle("flush-failed");
    (void)klog_flush();
    g_power_action = OPERATIONS_POWER_NONE;
    g_power_deadline_ns = 0U;
    klog("operations: power action cancelled because storage flush failed\n");
    return;
  }
  (void)klog_flush();
  if (g_power_action == OPERATIONS_POWER_REBOOT) arch_reboot();
  arch_power_off();
}

static const char *service_state(uint32_t state) {
  switch (state) {
    case XAIOS_SERVICE_STOPPED: return "stopped";
    case XAIOS_SERVICE_STARTING: return "starting";
    case XAIOS_SERVICE_RUNNING: return "running";
    case XAIOS_SERVICE_EXITED: return "exited";
    case XAIOS_SERVICE_FAILED: return "failed";
    default: return "unknown";
  }
}

static const char *ntp_state(uint32_t state) {
  switch (state) {
    case XAIOS_NTP_IDLE: return "idle";
    case XAIOS_NTP_PENDING: return "pending";
    case XAIOS_NTP_SYNCED: return "synced";
    case XAIOS_NTP_TIMEOUT: return "timeout";
    case XAIOS_NTP_FAILED: return "failed";
    default: return "unknown";
  }
}

static const char *pressure_name(uint64_t free_pages, uint64_t total_pages,
                                 uint64_t active_processes) {
  if (total_pages == 0U || free_pages * 100U < total_pages * 5U ||
      active_processes * 100U >= XAIOS_MAX_USER_PROCESSES * 95U)
    return "critical";
  if (free_pages * 100U < total_pages * 15U ||
      active_processes * 100U >= XAIOS_MAX_USER_PROCESSES * 80U)
    return "warning";
  return "normal";
}

static xaios_status_t handle_service(const char *args, char *output,
                                     uint64_t capacity, uint64_t *used) {
  char action[24], name[64];
  const char *cursor = args;
  if (!next_token(&cursor, action, sizeof(action)) || str_equal(action, "list")) {
    for (uint32_t i = 0U; i < service_count(); ++i) {
      xaios_service_t item;
      if (service_snapshot_at(i, &item) != XAIOS_OK) continue;
      append(output, capacity, used, item.name);
      append(output, capacity, used, " state=");
      append(output, capacity, used, service_state(item.state));
      append(output, capacity, used, " starts=");
      append_u64(output, capacity, used, item.starts);
      append(output, capacity, used, " restarts=");
      append_u64(output, capacity, used, item.restart_attempts);
      append(output, capacity, used, "\n");
    }
    return XAIOS_OK;
  }
  if (!next_token(&cursor, name, sizeof(name)) || *skip_spaces(cursor) != '\0')
    return XAIOS_ERR_INVALID;
  if (str_equal(action, "status")) {
    xaios_service_t item;
    xaios_status_t status = service_snapshot(name, &item);
    if (status != XAIOS_OK) return status;
    append(output, capacity, used, name);
    append(output, capacity, used, " state=");
    append(output, capacity, used, service_state(item.state));
    append(output, capacity, used, "\n");
    return XAIOS_OK;
  }
  xaios_status_t status = str_equal(action, "start") ? service_start(name) :
      str_equal(action, "stop") ? service_stop(name) :
      str_equal(action, "restart") ? service_restart(name) : XAIOS_ERR_INVALID;
  append(output, capacity, used, "service ");
  append(output, capacity, used, action);
  append(output, capacity, used, " ");
  append(output, capacity, used, name);
  append(output, capacity, used, ": ");
  append_status(output, capacity, used, status);
  append(output, capacity, used, "\n");
  return status;
}

static void append_network_status(char *output, uint64_t capacity,
                                  uint64_t *used) {
  append(output, capacity, used, "rx_packets=");
  append_u64(output, capacity, used, network_stack_rx_packet_count());
  append(output, capacity, used, " tx_packets=");
  append_u64(output, capacity, used, network_stack_tx_packet_count());
  append(output, capacity, used, " drops=");
  append_u64(output, capacity, used, network_stack_packet_drop_count());
  append(output, capacity, used, " tcp_established=");
  append_u64(output, capacity, used, network_stack_tcp_established_count());
  append(output, capacity, used, " tcp_resets=");
  append_u64(output, capacity, used, network_stack_tcp_reset_count());
  append(output, capacity, used, " udp_rx=");
  append_u64(output, capacity, used, network_stack_udp_rx_count());
  append(output, capacity, used, " udp_drops=");
  append_u64(output, capacity, used, network_stack_udp_dropped_count());
  append(output, capacity, used, " dns_pending=");
  append_u64(output, capacity, used, dns_pending_count());
  append(output, capacity, used, "\n");
}

static void append_resource_status(char *output, uint64_t capacity,
                                   uint64_t *used) {
  uint64_t total = pmm_managed_pages();
  uint64_t free = pmm_free_pages();
  uint64_t active = user_process_active_count();
  append(output, capacity, used, "pressure=");
  append(output, capacity, used, pressure_name(free, total, active));
  append(output, capacity, used, " memory_pages_free=");
  append_u64(output, capacity, used, free);
  append(output, capacity, used, " memory_pages_total=");
  append_u64(output, capacity, used, total);
  append(output, capacity, used, " heap_bytes=");
  append_u64(output, capacity, used, kheap_bytes_allocated());
  append(output, capacity, used, " processes_active=");
  append_u64(output, capacity, used, active);
  append(output, capacity, used, " processes_max=");
  append_u64(output, capacity, used, XAIOS_MAX_USER_PROCESSES);
  append(output, capacity, used, " files=");
  append_u64(output, capacity, used, mutable_fs_file_count());
  append(output, capacity, used, " cpus=");
  append_u64(output, capacity, used, smp_online_count());
  append(output, capacity, used, "\n");
}

uint32_t operations_is_command(const char *command) {
  static const char *names[] = {"shutdown", "reboot", "power", "service",
      "kill", "ifconfig", "route", "arp", "ndp", "netstat", "ping",
      "nslookup", "date", "ntp", "limits", "recovery", "update",
      "config", "support"};
  char token[24];
  const char *cursor = command;
  if (!next_token(&cursor, token, sizeof(token))) return 0U;
  for (uint32_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i)
    if (str_equal(token, names[i])) return 1U;
  return 0U;
}

uint32_t operations_command_allowed_in_rescue(const char *command) {
  static const char *allowed[] = {
      "help", "pwd", "ls", "cat", "less", "stat", "df", "du", "cp",
      "mv", "rm", "mkdir", "nano", "recovery", "power", "shutdown",
      "reboot", "support", "ifconfig", "netstat", "limits", "date", "ntp"};
  char name[24], action[24];
  const char *cursor = command;
  if (!next_token(&cursor, name, sizeof(name))) return 0U;
  for (uint32_t i = 0U; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
    if (str_equal(name, allowed[i])) return 1U;
  }
  if (!str_equal(name, "update")) return 0U;
  if (!next_token(&cursor, action, sizeof(action))) return 1U;
  return str_equal(action, "status") && *skip_spaces(cursor) == '\0';
}

xaios_status_t operations_execute(const char *command, char *output,
                                  uint64_t capacity, uint64_t *output_bytes) {
  char name[24], arg1[80], arg2[256];
  const char *cursor = command;
  uint64_t used = 0U;
  xaios_status_t status = XAIOS_OK;
  if (output == 0 || output_bytes == 0 || capacity < 2U ||
      !next_token(&cursor, name, sizeof(name))) return XAIOS_ERR_INVALID;
  output[0] = '\0';
  arg1[0] = '\0'; arg2[0] = '\0';
  (void)next_token(&cursor, arg1, sizeof(arg1));
  (void)next_token(&cursor, arg2, sizeof(arg2));
  uint32_t has_extra = *skip_spaces(cursor) != '\0';

  if (str_equal(name, "shutdown") || str_equal(name, "reboot")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    else {
      request_power(str_equal(name, "reboot") ? OPERATIONS_POWER_REBOOT
                                               : OPERATIONS_POWER_OFF);
      append(output, capacity, &used, name);
      append(output, capacity, &used, ": scheduled after storage flush\n");
    }
  } else if (str_equal(name, "power")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "power_state=");
    append(output, capacity, &used, g_power_action == OPERATIONS_POWER_NONE
                                      ? "running" : "quiescing");
    append(output, capacity, &used, " boot_ready=");
    append_u64(output, capacity, &used, g_boot_ready);
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "service")) {
    status = handle_service(skip_spaces(command + str_len(name)), output,
                            capacity, &used);
  } else if (str_equal(name, "kill")) {
    uint64_t pid = 0U;
    status = parse_u64(arg1, &pid);
    if (status == XAIOS_OK && (arg2[0] != '\0' || pid > UINT32_MAX))
      status = XAIOS_ERR_INVALID;
    if (status == XAIOS_OK)
      status = user_process_terminate((uint32_t)pid, 143);
    append(output, capacity, &used, "kill: ");
    append_status(output, capacity, &used, status);
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "ifconfig")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    uint8_t mac[6];
    append(output, capacity, &used, "vtnet0: flags=UP,RUNNING mtu 1500\n  inet ");
    append_ipv4(output, capacity, &used, network_stack_local_ipv4());
    append(output, capacity, &used, " netmask ");
    append_ipv4(output, capacity, &used, UINT32_C(0xffffff00));
    if (network_stack_local_mac(mac) == XAIOS_OK) {
      static const char hex[] = "0123456789abcdef";
      append(output, capacity, &used, "\n  ether ");
      for (uint32_t i = 0U; i < 6U; ++i) {
        char octet[3] = {hex[mac[i] >> 4U], hex[mac[i] & 0xfU], '\0'};
        append(output, capacity, &used, octet);
        if (i != 5U) append(output, capacity, &used, ":");
      }
    }
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "route")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "Destination Gateway Netmask\n");
    for (uint32_t i = 0U; i < routing_count(); ++i) {
      routing_entry_t route;
      if (routing_snapshot(i, &route) != XAIOS_OK) continue;
      append_ipv4(output, capacity, &used, route.dest_network);
      append(output, capacity, &used, " ");
      append_ipv4(output, capacity, &used, route.gateway);
      append(output, capacity, &used, " ");
      append_ipv4(output, capacity, &used, route.netmask);
      append(output, capacity, &used, "\n");
    }
  } else if (str_equal(name, "arp")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    for (uint32_t i = 0U; i < arp_cache_count(); ++i) {
      xaios_arp_entry_t entry;
      if (arp_cache_snapshot(i, &entry) != XAIOS_OK) continue;
      append_ipv4(output, capacity, &used, entry.ip);
      append(output, capacity, &used, " age_ns=");
      append_u64(output, capacity, &used, entry.age_ns);
      append(output, capacity, &used, "\n");
    }
  } else if (str_equal(name, "ndp")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "ndp_entries=");
    append_u64(output, capacity, &used, ndp_cache_count());
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "netstat")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append_network_status(output, capacity, &used);
  } else if (str_equal(name, "ping")) {
    if (str_equal(arg1, "status")) {
      xaios_network_ping_status_t ping = network_stack_ping_status();
      append(output, capacity, &used, "ping_state=");
      append_u64(output, capacity, &used, ping.state);
      append(output, capacity, &used, " target=");
      append_ipv4(output, capacity, &used, ping.target_ip);
      append(output, capacity, &used, " rtt_ns=");
      append_u64(output, capacity, &used, ping.round_trip_ns);
      append(output, capacity, &used, "\n");
    } else {
      uint32_t ip = 0U;
      status = parse_ipv4(arg1, &ip);
      if (status == XAIOS_OK) status = network_stack_ping_start(ip);
      if (status == XAIOS_ERR_BUSY) status = XAIOS_OK;
      append(output, capacity, &used, "ping: request sent; use ping status\n");
    }
  } else if (str_equal(name, "nslookup")) {
    uint8_t family = XAIOS_IP_FAMILY_V4;
    const char *hostname = arg1;
    if (str_equal(arg1, "-6")) {
      family = XAIOS_IP_FAMILY_V6;
      hostname = arg2;
    } else if (arg2[0] != '\0') {
      status = XAIOS_ERR_INVALID;
    }
    if (has_extra != 0U || hostname[0] == '\0') status = XAIOS_ERR_INVALID;
    xaios_ip_addr_t address;
    xaios_ip_addr_zero(&address);
    if (status == XAIOS_OK)
      status = dns_resolve_address(hostname, family, &address);
    append(output, capacity, &used, hostname);
    append(output, capacity, &used, ": ");
    if (status == XAIOS_OK && family == XAIOS_IP_FAMILY_V4)
      append_ipv4(output, capacity, &used,
                  xaios_ip_addr_to_ipv4(&address));
    else if (status == XAIOS_OK)
      append_ipv6(output, capacity, &used, &address);
    else if (status == XAIOS_ERR_BUSY) append(output, capacity, &used, "pending");
    else append_status(output, capacity, &used, status);
    append(output, capacity, &used, "\n");
    if (status == XAIOS_ERR_BUSY) status = XAIOS_OK;
  } else if (str_equal(name, "date")) {
    if (str_equal(arg1, "-s")) {
      uint64_t epoch = 0U;
      status = parse_u64(arg2, &epoch);
      if (status == XAIOS_OK && epoch <= UINT64_MAX / UINT64_C(1000000000))
        status = wall_time_set_ns(epoch * UINT64_C(1000000000), 3U);
      else status = XAIOS_ERR_INVALID;
    } else if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    if (has_extra != 0U) status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "epoch_seconds=");
    append_u64(output, capacity, &used,
               wall_time_now_ns() / UINT64_C(1000000000));
    append(output, capacity, &used, " source=");
    append(output, capacity, &used, wall_time_source() == 2U ? "ntp" :
        wall_time_source() == 3U ? "manual" : "rtc");
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "ntp")) {
    if (str_equal(arg1, "sync")) {
      uint32_t ip = 0U;
      if (arg2[0] != '\0') status = parse_ipv4(arg2, &ip);
      if (status == XAIOS_OK) status = ntp_sync(ip);
      if (status == XAIOS_ERR_BUSY) status = XAIOS_OK;
    } else if (arg1[0] != '\0' && !str_equal(arg1, "status"))
      status = XAIOS_ERR_INVALID;
    if (has_extra != 0U) status = XAIOS_ERR_INVALID;
    xaios_ntp_status_t current = ntp_status();
    append(output, capacity, &used, "ntp_state=");
    append(output, capacity, &used, ntp_state(current.state));
    append(output, capacity, &used, " server=");
    append_ipv4(output, capacity, &used, current.server_ip);
    append(output, capacity, &used, " attempts=");
    append_u64(output, capacity, &used, current.attempts);
    append(output, capacity, &used, " rtt_ns=");
    append_u64(output, capacity, &used, current.round_trip_ns);
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "limits")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append_resource_status(output, capacity, &used);
  } else if (str_equal(name, "recovery")) {
    if (str_equal(arg1, "enter")) {
      if (g_persistent == 0U) status = XAIOS_ERR_UNSUPPORTED;
      else {
        status = mutable_fs_write(OPERATIONS_RESCUE_PATH, "enabled\n", 8U);
        if (status == XAIOS_OK) (void)mutable_fs_commit("rescue-enter");
        if (status == XAIOS_OK) { g_rescue = 1U; request_power(OPERATIONS_POWER_REBOOT); }
      }
    } else if (str_equal(arg1, "clear")) {
      status = mutable_fs_delete(OPERATIONS_RESCUE_PATH);
      if (status == XAIOS_ERR_NOT_FOUND) status = XAIOS_OK;
      if (status == XAIOS_OK) (void)mutable_fs_commit("rescue-clear");
      if (status == XAIOS_OK) { g_rescue = 0U; g_unclean_boots = 0U; }
    } else if (arg1[0] != '\0' && !str_equal(arg1, "status"))
      status = XAIOS_ERR_INVALID;
    if (arg2[0] != '\0') status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "rescue=");
    append_u64(output, capacity, &used, g_rescue);
    append(output, capacity, &used, " unclean_boots=");
    append_u64(output, capacity, &used, g_unclean_boots);
    append(output, capacity, &used, " boots=");
    append_u64(output, capacity, &used, g_boots);
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "update")) {
    if (str_equal(arg1, "rollback")) status = update_rollback();
    else if (arg1[0] != '\0' && !str_equal(arg1, "status"))
      status = XAIOS_ERR_INVALID;
    if (arg2[0] != '\0') status = XAIOS_ERR_INVALID;
    xaios_update_status_t update = update_status_snapshot();
    append(output, capacity, &used, "update_active=");
    append_u64(output, capacity, &used, update.active);
    append(output, capacity, &used, " state=");
    append_u64(output, capacity, &used, update.state);
    append(output, capacity, &used, " generation=");
    append_u64(output, capacity, &used, update.generation);
    append(output, capacity, &used, " target=");
    append(output, capacity, &used, update.target[0] != '\0' ? update.target : "none");
    append(output, capacity, &used, " bytes=");
    append_u64(output, capacity, &used, update.delivery.bytes_received);
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "config")) {
    xaios_admin_config_t config;
    uint32_t changes = 0U;
    if (str_equal(arg1, "export") && arg2[0] != '\0') {
      if (admin_control_config_get(&config) != XAIOS_ADMIN_RESULT_OK)
        status = XAIOS_ERR_IO;
      else {
        char text[320];
        uint64_t text_bytes = 0U;
        text[0] = '\0';
        append(text, sizeof(text), &text_bytes, "schema=xaios.config.v1\n");
        append(text, sizeof(text), &text_bytes, "ssh.max_connections=");
        append_u64(text, sizeof(text), &text_bytes, config.max_connections);
        append(text, sizeof(text), &text_bytes,
               "\nssh.max_channels_per_connection=");
        append_u64(text, sizeof(text), &text_bytes,
                   config.max_channels_per_connection);
        append(text, sizeof(text), &text_bytes, "\nssh.max_auth_attempts=");
        append_u64(text, sizeof(text), &text_bytes,
                   config.max_auth_attempts);
        append(text, sizeof(text), &text_bytes,
               "\nssh.command_rate_per_minute=");
        append_u64(text, sizeof(text), &text_bytes,
                   config.command_rate_per_minute);
        append(text, sizeof(text), &text_bytes, "\nssh.password_auth=");
        append(text, sizeof(text), &text_bytes,
               config.password_auth == XAIOS_ADMIN_PASSWORD_DEVELOPMENT
                   ? "development\n" : "disabled\n");
        status = mutable_fs_write(arg2, text, text_bytes);
      }
    } else if (str_equal(arg1, "import") && arg2[0] != '\0') {
      status = admin_control_config_apply(arg2, "ssh-admin",
          3U, timer_now_ns(), &config, &changes) ==
          XAIOS_ADMIN_RESULT_OK ? XAIOS_OK : XAIOS_ERR_INVALID;
    } else status = XAIOS_ERR_INVALID;
    if (has_extra != 0U) status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "config ");
    append(output, capacity, &used, arg1);
    append(output, capacity, &used, ": ");
    append_status(output, capacity, &used, status);
    append(output, capacity, &used, " changes=");
    append_u64(output, capacity, &used, changes);
    append(output, capacity, &used, "\n");
  } else if (str_equal(name, "support")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append(output, capacity, &used, "XAIOS support bundle (redacted)\n");
    append(output, capacity, &used, "build=");
    append(output, capacity, &used, XAIOS_BUILD_IDENTIFIER);
    append(output, capacity, &used, " revision=");
    append(output, capacity, &used, XAIOS_BUILD_REVISION);
    append(output, capacity, &used, " mode=");
    append(output, capacity, &used, XAIOS_BUILD_MODE);
    append(output, capacity, &used, "\nboot_ready=");
    append_u64(output, capacity, &used, g_boot_ready);
    append(output, capacity, &used, " rescue=");
    append_u64(output, capacity, &used, g_rescue);
    append(output, capacity, &used, " unclean_boots=");
    append_u64(output, capacity, &used, g_unclean_boots);
    append(output, capacity, &used, " timer_hz=");
    append_u64(output, capacity, &used, timer_frequency_hz());
    append(output, capacity, &used, " thermal=unavailable pmu=unavailable\n");
    append_resource_status(output, capacity, &used);
    append_network_status(output, capacity, &used);
    append(output, capacity, &used, "log_bytes=");
    append_u64(output, capacity, &used, klog_ring_count());
    append(output, capacity, &used, " log_overflows=");
    append_u64(output, capacity, &used, klog_ring_overflow_count());
    append(output, capacity, &used, "\nsecrets=redacted\n");
  } else status = XAIOS_ERR_NOT_FOUND;

  if (status != XAIOS_OK && used == 0U) {
    append(output, capacity, &used, name);
    append(output, capacity, &used, ": ");
    append_status(output, capacity, &used, status);
    append(output, capacity, &used, "\n");
  }
  *output_bytes = used;
  return status;
}

void operations_self_test(void) {
  kassert(str_equal(pressure_name(100U, 100U, 1U), "normal"));
  kassert(str_equal(pressure_name(10U, 100U, 1U), "warning"));
  kassert(str_equal(pressure_name(4U, 100U, 1U), "critical"));
  uint32_t ip = 0U;
  kassert(parse_ipv4("10.0.2.15", &ip) == XAIOS_OK);
  kassert(ip == UINT32_C(0x0a00020f));
  kassert(parse_ipv4("10.0.2.999", &ip) == XAIOS_ERR_INVALID);
  kassert(record_running("state=running\nunclean=2\n") != 0U);
  kassert(operations_command_allowed_in_rescue("ls /state") != 0U);
  kassert(operations_command_allowed_in_rescue("update status") != 0U);
  kassert(operations_command_allowed_in_rescue("update rollback") == 0U);
  kassert(operations_command_allowed_in_rescue("lstm-xor") == 0U);
  klog("operations: self-test passed\n");
}
