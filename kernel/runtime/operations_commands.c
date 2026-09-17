#include "operations_internal.h"

#include <xaios/admin_control.h>
#include <xaios/arp.h>
#include <xaios/dns.h>
#include <xaios/kheap.h>
#include <xaios/klog_ring.h>
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
#include <xaios/xaiboot_fs.h>

#ifndef XAIOS_BUILD_IDENTIFIER
#define XAIOS_BUILD_IDENTIFIER "xaios-admin-control-dirty"
#endif
#ifndef XAIOS_BUILD_REVISION
#define XAIOS_BUILD_REVISION "unknown"
#endif
#ifndef XAIOS_BUILD_MODE
#define XAIOS_BUILD_MODE "unknown"
#endif

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

const char *ops_pressure_name(uint64_t free_pages, uint64_t total_pages,
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
  if (!ops_next_token(&cursor, action, sizeof(action)) ||
      ops_str_equal(action, "list")) {
    for (uint32_t i = 0U; i < service_count(); ++i) {
      xaios_service_t item;
      if (service_snapshot_at(i, &item) != XAIOS_OK) continue;
      ops_append(output, capacity, used, item.name);
      ops_append(output, capacity, used, " state=");
      ops_append(output, capacity, used, service_state(item.state));
      ops_append(output, capacity, used, " starts=");
      ops_append_u64(output, capacity, used, item.starts);
      ops_append(output, capacity, used, " restarts=");
      ops_append_u64(output, capacity, used, item.restart_attempts);
      ops_append(output, capacity, used, "\n");
    }
    return XAIOS_OK;
  }
  if (!ops_next_token(&cursor, name, sizeof(name)) ||
      *ops_skip_spaces(cursor) != '\0')
    return XAIOS_ERR_INVALID;
  if (ops_str_equal(action, "status")) {
    xaios_service_t item;
    xaios_status_t status = service_snapshot(name, &item);
    if (status != XAIOS_OK) return status;
    ops_append(output, capacity, used, name);
    ops_append(output, capacity, used, " state=");
    ops_append(output, capacity, used, service_state(item.state));
    ops_append(output, capacity, used, "\n");
    return XAIOS_OK;
  }
  xaios_status_t status = ops_str_equal(action, "start") ? service_start(name) :
      ops_str_equal(action, "stop") ? service_stop(name) :
      ops_str_equal(action, "restart") ? service_restart(name)
                                       : XAIOS_ERR_INVALID;
  ops_append(output, capacity, used, "service ");
  ops_append(output, capacity, used, action);
  ops_append(output, capacity, used, " ");
  ops_append(output, capacity, used, name);
  ops_append(output, capacity, used, ": ");
  ops_append_status(output, capacity, used, status);
  ops_append(output, capacity, used, "\n");
  return status;
}

static void append_network_status(char *output, uint64_t capacity,
                                  uint64_t *used) {
  ops_append(output, capacity, used, "rx_packets=");
  ops_append_u64(output, capacity, used, network_stack_rx_packet_count());
  ops_append(output, capacity, used, " tx_packets=");
  ops_append_u64(output, capacity, used, network_stack_tx_packet_count());
  ops_append(output, capacity, used, " drops=");
  ops_append_u64(output, capacity, used, network_stack_packet_drop_count());
  ops_append(output, capacity, used, " tcp_established=");
  ops_append_u64(output, capacity, used, network_stack_tcp_established_count());
  ops_append(output, capacity, used, " tcp_resets=");
  ops_append_u64(output, capacity, used, network_stack_tcp_reset_count());
  ops_append(output, capacity, used, " udp_rx=");
  ops_append_u64(output, capacity, used, network_stack_udp_rx_count());
  ops_append(output, capacity, used, " udp_drops=");
  ops_append_u64(output, capacity, used, network_stack_udp_dropped_count());
  ops_append(output, capacity, used, " dns_pending=");
  ops_append_u64(output, capacity, used, dns_pending_count());
  ops_append(output, capacity, used, "\n");
}

static void append_resource_status(char *output, uint64_t capacity,
                                   uint64_t *used) {
  uint64_t total = pmm_managed_pages();
  uint64_t free = pmm_free_pages();
  uint64_t active = user_process_active_count();
  ops_append(output, capacity, used, "pressure=");
  ops_append(output, capacity, used, ops_pressure_name(free, total, active));
  ops_append(output, capacity, used, " memory_pages_free=");
  ops_append_u64(output, capacity, used, free);
  ops_append(output, capacity, used, " memory_pages_total=");
  ops_append_u64(output, capacity, used, total);
  ops_append(output, capacity, used, " heap_bytes=");
  ops_append_u64(output, capacity, used, kheap_bytes_allocated());
  ops_append(output, capacity, used, " processes_active=");
  ops_append_u64(output, capacity, used, active);
  ops_append(output, capacity, used, " processes_max=");
  ops_append_u64(output, capacity, used, XAIOS_MAX_USER_PROCESSES);
  ops_append(output, capacity, used, " files=");
  ops_append_u64(output, capacity, used, xaiboot_fs_file_count());
  ops_append(output, capacity, used, " cpus=");
  ops_append_u64(output, capacity, used, smp_online_count());
  ops_append(output, capacity, used, "\n");
}

xaios_status_t operations_execute(const char *command, char *output,
                                  uint64_t capacity, uint64_t *output_bytes) {
  char name[24], arg1[80], arg2[256];
  const char *cursor = command;
  uint64_t used = 0U;
  xaios_status_t status = XAIOS_OK;
  if (output == 0 || output_bytes == 0 || capacity < 2U ||
      !ops_next_token(&cursor, name, sizeof(name))) return XAIOS_ERR_INVALID;
  output[0] = '\0';
  arg1[0] = '\0'; arg2[0] = '\0';
  (void)ops_next_token(&cursor, arg1, sizeof(arg1));
  (void)ops_next_token(&cursor, arg2, sizeof(arg2));
  uint32_t has_extra = *ops_skip_spaces(cursor) != '\0';

  if (ops_str_equal(name, "shutdown") || ops_str_equal(name, "reboot")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    else {
      ops_request_power(ops_str_equal(name, "reboot") ? OPERATIONS_POWER_REBOOT
                                                      : OPERATIONS_POWER_OFF);
      ops_append(output, capacity, &used, name);
      ops_append(output, capacity, &used, ": scheduled after storage flush\n");
    }
  } else if (ops_str_equal(name, "power")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "power_state=");
    ops_append(output, capacity, &used,
               ops_state_power_action == OPERATIONS_POWER_NONE
                   ? "running" : "quiescing");
    ops_append(output, capacity, &used, " boot_ready=");
    ops_append_u64(output, capacity, &used, ops_state_boot_ready);
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "service")) {
    status = handle_service(ops_skip_spaces(command + ops_str_len(name)), output,
                            capacity, &used);
  } else if (ops_str_equal(name, "kill")) {
    uint64_t pid = 0U;
    status = ops_parse_u64(arg1, &pid);
    if (status == XAIOS_OK && (arg2[0] != '\0' || pid > UINT32_MAX))
      status = XAIOS_ERR_INVALID;
    if (status == XAIOS_OK)
      status = user_process_terminate((uint32_t)pid, 143);
    ops_append(output, capacity, &used, "kill: ");
    ops_append_status(output, capacity, &used, status);
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "ifconfig")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    uint8_t mac[6];
    ops_append(output, capacity, &used,
               "vtnet0: flags=UP,RUNNING mtu 1500\n  inet ");
    ops_append_ipv4(output, capacity, &used, network_stack_local_ipv4());
    ops_append(output, capacity, &used, " netmask ");
    ops_append_ipv4(output, capacity, &used, UINT32_C(0xffffff00));
    if (network_stack_local_mac(mac) == XAIOS_OK) {
      static const char hex[] = "0123456789abcdef";
      ops_append(output, capacity, &used, "\n  ether ");
      for (uint32_t i = 0U; i < 6U; ++i) {
        char octet[3] = {hex[mac[i] >> 4U], hex[mac[i] & 0xfU], '\0'};
        ops_append(output, capacity, &used, octet);
        if (i != 5U) ops_append(output, capacity, &used, ":");
      }
    }
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "route")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "Destination Gateway Netmask\n");
    for (uint32_t i = 0U; i < routing_count(); ++i) {
      routing_entry_t route;
      if (routing_snapshot(i, &route) != XAIOS_OK) continue;
      ops_append_ipv4(output, capacity, &used, route.dest_network);
      ops_append(output, capacity, &used, " ");
      ops_append_ipv4(output, capacity, &used, route.gateway);
      ops_append(output, capacity, &used, " ");
      ops_append_ipv4(output, capacity, &used, route.netmask);
      ops_append(output, capacity, &used, "\n");
    }
  } else if (ops_str_equal(name, "arp")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    for (uint32_t i = 0U; i < arp_cache_count(); ++i) {
      xaios_arp_entry_t entry;
      if (arp_cache_snapshot(i, &entry) != XAIOS_OK) continue;
      ops_append_ipv4(output, capacity, &used, entry.ip);
      ops_append(output, capacity, &used, " age_ns=");
      ops_append_u64(output, capacity, &used, entry.age_ns);
      ops_append(output, capacity, &used, "\n");
    }
  } else if (ops_str_equal(name, "ndp")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "ndp_entries=");
    ops_append_u64(output, capacity, &used, ndp_cache_count());
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "netstat")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append_network_status(output, capacity, &used);
  } else if (ops_str_equal(name, "ping")) {
    if (ops_str_equal(arg1, "status")) {
      xaios_network_ping_status_t ping = network_stack_ping_status();
      ops_append(output, capacity, &used, "ping_state=");
      ops_append_u64(output, capacity, &used, ping.state);
      ops_append(output, capacity, &used, " target=");
      ops_append_ipv4(output, capacity, &used, ping.target_ip);
      ops_append(output, capacity, &used, " rtt_ns=");
      ops_append_u64(output, capacity, &used, ping.round_trip_ns);
      ops_append(output, capacity, &used, "\n");
    } else {
      uint32_t ip = 0U;
      status = ops_parse_ipv4(arg1, &ip);
      if (status == XAIOS_OK) status = network_stack_ping_start(ip);
      if (status == XAIOS_ERR_BUSY) status = XAIOS_OK;
      ops_append(output, capacity, &used,
                 "ping: request sent; use ping status\n");
    }
  } else if (ops_str_equal(name, "nslookup")) {
    /* B-36. "dnssec-unverified" is a verdict about a name: the chain was
       walked and refused. It used to also be what this printed when the
       command itself was wrong -- an extra argument, a missing hostname, a
       bare -6 -- because both arrived as XAIOS_ERR_INVALID and the last one
       to set it won. A reader could not tell a typo from a fail-closed
       resolver, and neither could a gate.

       So the command's own arguments are checked here, before the resolver is
       asked anything, and a bad one is reported as a bad argument. That
       includes the length: the resolver rejects an over-long hostname with
       the same XAIOS_ERR_INVALID it uses for a refused chain, so the shell
       has to catch it first rather than translate it afterwards. What is left
       reaching the resolver is a syntactically valid request, and every
       status it returns is then a statement about the name. */
    uint8_t family = XAIOS_IP_FAMILY_V4;
    const char *hostname = arg1;
    uint32_t bad_arguments = 0U;
    if (ops_str_equal(arg1, "-6")) {
      family = XAIOS_IP_FAMILY_V6;
      hostname = arg2;
    } else if (arg2[0] != '\0') {
      bad_arguments = 1U;
    }
    if (has_extra != 0U || hostname[0] == '\0' ||
        ops_str_len(hostname) >= XAIOS_DNS_MAX_HOSTNAME) {
      bad_arguments = 1U;
    }
    if (bad_arguments != 0U) {
      ops_append(output, capacity, &used,
                 "nslookup: invalid-argument; usage: nslookup [-6] <hostname>\n");
      status = XAIOS_ERR_INVALID;
    } else {
      xaios_ip_addr_t address;
      xaios_ip_addr_zero(&address);
      status = dns_resolve_address(hostname, family, &address);
      ops_append(output, capacity, &used, hostname);
      ops_append(output, capacity, &used, ": ");
      if (status == XAIOS_OK && family == XAIOS_IP_FAMILY_V4)
        ops_append_ipv4(output, capacity, &used,
                        xaios_ip_addr_to_ipv4(&address));
      else if (status == XAIOS_OK)
        ops_append_ipv6(output, capacity, &used, &address);
      else if (status == XAIOS_ERR_BUSY)
        ops_append(output, capacity, &used, "pending");
      else if (status == XAIOS_ERR_INVALID)
        ops_append(output, capacity, &used, "dnssec-unverified");
      /* B-35's other half. A resolution that ran out of budget reached no
         verdict at all, which is not the same claim as refusing one, and
         used to surface as the bare "error(7)" of XAIOS_ERR_CANCELLED. */
      else if (status == XAIOS_ERR_CANCELLED)
        ops_append(output, capacity, &used, "dnssec-timeout");
      else if (status == XAIOS_ERR_NOT_FOUND)
        ops_append(output, capacity, &used, "not-found");
      else ops_append_status(output, capacity, &used, status);
      ops_append(output, capacity, &used, "\n");
      if (status == XAIOS_ERR_BUSY) status = XAIOS_OK;
    }
  } else if (ops_str_equal(name, "date")) {
    if (ops_str_equal(arg1, "-s")) {
      uint64_t epoch = 0U;
      status = ops_parse_u64(arg2, &epoch);
      if (status == XAIOS_OK && epoch <= UINT64_MAX / UINT64_C(1000000000))
        status = wall_time_set_ns(epoch * UINT64_C(1000000000), 3U);
      else status = XAIOS_ERR_INVALID;
    } else if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    if (has_extra != 0U) status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "epoch_seconds=");
    ops_append_u64(output, capacity, &used,
                   wall_time_now_ns() / UINT64_C(1000000000));
    ops_append(output, capacity, &used, " source=");
    ops_append(output, capacity, &used,
               wall_time_source() == 2U ? "ntp" :
               wall_time_source() == 3U ? "manual" : "rtc");
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "ntp")) {
    if (ops_str_equal(arg1, "sync")) {
      uint32_t ip = 0U;
      if (arg2[0] != '\0') status = ops_parse_ipv4(arg2, &ip);
      if (status == XAIOS_OK) status = ntp_sync(ip);
      if (status == XAIOS_ERR_BUSY) status = XAIOS_OK;
    } else if (arg1[0] != '\0' && !ops_str_equal(arg1, "status"))
      status = XAIOS_ERR_INVALID;
    if (has_extra != 0U) status = XAIOS_ERR_INVALID;
    xaios_ntp_status_t current = ntp_status();
    ops_append(output, capacity, &used, "ntp_state=");
    ops_append(output, capacity, &used, ntp_state(current.state));
    ops_append(output, capacity, &used, " server=");
    ops_append_ipv4(output, capacity, &used, current.server_ip);
    ops_append(output, capacity, &used, " attempts=");
    ops_append_u64(output, capacity, &used, current.attempts);
    ops_append(output, capacity, &used, " rtt_ns=");
    ops_append_u64(output, capacity, &used, current.round_trip_ns);
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "limits")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    append_resource_status(output, capacity, &used);
  } else if (ops_str_equal(name, "recovery")) {
    if (ops_str_equal(arg1, "enter")) {
      if (ops_state_persistent == 0U) status = XAIOS_ERR_UNSUPPORTED;
      else {
        status = xaiboot_fs_write(OPERATIONS_RESCUE_PATH, "enabled\n", 8U);
        if (status == XAIOS_OK) (void)xaiboot_fs_commit("rescue-enter");
        if (status == XAIOS_OK) {
          ops_state_rescue = 1U;
          ops_request_power(OPERATIONS_POWER_REBOOT);
        }
      }
    } else if (ops_str_equal(arg1, "clear")) {
      status = xaiboot_fs_delete(OPERATIONS_RESCUE_PATH);
      if (status == XAIOS_ERR_NOT_FOUND) status = XAIOS_OK;
      if (status == XAIOS_OK) (void)xaiboot_fs_commit("rescue-clear");
      if (status == XAIOS_OK) {
        ops_state_rescue = 0U;
        ops_state_unclean_boots = 0U;
      }
    } else if (arg1[0] != '\0' && !ops_str_equal(arg1, "status"))
      status = XAIOS_ERR_INVALID;
    if (arg2[0] != '\0') status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "rescue=");
    ops_append_u64(output, capacity, &used, ops_state_rescue);
    ops_append(output, capacity, &used, " unclean_boots=");
    ops_append_u64(output, capacity, &used, ops_state_unclean_boots);
    ops_append(output, capacity, &used, " boots=");
    ops_append_u64(output, capacity, &used, ops_state_boots);
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "update")) {
    if (ops_str_equal(arg1, "rollback")) status = update_rollback();
    else if (arg1[0] != '\0' && !ops_str_equal(arg1, "status"))
      status = XAIOS_ERR_INVALID;
    if (arg2[0] != '\0') status = XAIOS_ERR_INVALID;
    xaios_update_status_t update = update_status_snapshot();
    ops_append(output, capacity, &used, "update_active=");
    ops_append_u64(output, capacity, &used, update.active);
    ops_append(output, capacity, &used, " state=");
    ops_append_u64(output, capacity, &used, update.state);
    ops_append(output, capacity, &used, " generation=");
    ops_append_u64(output, capacity, &used, update.generation);
    ops_append(output, capacity, &used, " target=");
    ops_append(output, capacity, &used,
               update.target[0] != '\0' ? update.target : "none");
    ops_append(output, capacity, &used, " bytes=");
    ops_append_u64(output, capacity, &used, update.delivery.bytes_received);
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "config")) {
    xaios_admin_config_t config;
    uint32_t changes = 0U;
    if (ops_str_equal(arg1, "export") && arg2[0] != '\0') {
      if (admin_control_config_get(&config) != XAIOS_ADMIN_RESULT_OK)
        status = XAIOS_ERR_IO;
      else {
        char text[320];
        uint64_t text_bytes = 0U;
        text[0] = '\0';
        ops_append(text, sizeof(text), &text_bytes, "schema=xaios.config.v1\n");
        ops_append(text, sizeof(text), &text_bytes, "ssh.max_connections=");
        ops_append_u64(text, sizeof(text), &text_bytes, config.max_connections);
        ops_append(text, sizeof(text), &text_bytes,
                   "\nssh.max_channels_per_connection=");
        ops_append_u64(text, sizeof(text), &text_bytes,
                       config.max_channels_per_connection);
        ops_append(text, sizeof(text), &text_bytes, "\nssh.max_auth_attempts=");
        ops_append_u64(text, sizeof(text), &text_bytes,
                       config.max_auth_attempts);
        ops_append(text, sizeof(text), &text_bytes,
                   "\nssh.command_rate_per_minute=");
        ops_append_u64(text, sizeof(text), &text_bytes,
                       config.command_rate_per_minute);
        ops_append(text, sizeof(text), &text_bytes, "\nssh.password_auth=");
        ops_append(text, sizeof(text), &text_bytes,
                   config.password_auth == XAIOS_ADMIN_PASSWORD_DEVELOPMENT
                       ? "development\n" : "disabled\n");
        status = xaiboot_fs_write(arg2, text, text_bytes);
      }
    } else if (ops_str_equal(arg1, "import") && arg2[0] != '\0') {
      status = admin_control_config_apply(arg2, "ssh-admin",
          3U, timer_now_ns(), &config, &changes) ==
          XAIOS_ADMIN_RESULT_OK ? XAIOS_OK : XAIOS_ERR_INVALID;
    } else status = XAIOS_ERR_INVALID;
    if (has_extra != 0U) status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "config ");
    ops_append(output, capacity, &used, arg1);
    ops_append(output, capacity, &used, ": ");
    ops_append_status(output, capacity, &used, status);
    ops_append(output, capacity, &used, " changes=");
    ops_append_u64(output, capacity, &used, changes);
    ops_append(output, capacity, &used, "\n");
  } else if (ops_str_equal(name, "support")) {
    if (arg1[0] != '\0') status = XAIOS_ERR_INVALID;
    ops_append(output, capacity, &used, "XAIOS support bundle (redacted)\n");
    ops_append(output, capacity, &used, "build=");
    ops_append(output, capacity, &used, XAIOS_BUILD_IDENTIFIER);
    ops_append(output, capacity, &used, " revision=");
    ops_append(output, capacity, &used, XAIOS_BUILD_REVISION);
    ops_append(output, capacity, &used, " mode=");
    ops_append(output, capacity, &used, XAIOS_BUILD_MODE);
    ops_append(output, capacity, &used, "\nboot_ready=");
    ops_append_u64(output, capacity, &used, ops_state_boot_ready);
    ops_append(output, capacity, &used, " rescue=");
    ops_append_u64(output, capacity, &used, ops_state_rescue);
    ops_append(output, capacity, &used, " unclean_boots=");
    ops_append_u64(output, capacity, &used, ops_state_unclean_boots);
    ops_append(output, capacity, &used, " timer_hz=");
    ops_append_u64(output, capacity, &used, timer_frequency_hz());
    ops_append(output, capacity, &used,
               " thermal=unavailable pmu=unavailable\n");
    append_resource_status(output, capacity, &used);
    append_network_status(output, capacity, &used);
    ops_append(output, capacity, &used, "log_bytes=");
    ops_append_u64(output, capacity, &used, klog_ring_count());
    ops_append(output, capacity, &used, " log_overflows=");
    ops_append_u64(output, capacity, &used, klog_ring_overflow_count());
    ops_append(output, capacity, &used, "\nsecrets=redacted\n");
  } else status = XAIOS_ERR_NOT_FOUND;

  if (status != XAIOS_OK && used == 0U) {
    ops_append(output, capacity, &used, name);
    ops_append(output, capacity, &used, ": ");
    ops_append_status(output, capacity, &used, status);
    ops_append(output, capacity, &used, "\n");
  }
  *output_bytes = used;
  return status;
}
