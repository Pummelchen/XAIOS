/*
 * sshd's per-address rate limiting.
 *
 * One table, keyed on the peer address, bounds unauthenticated connection
 * attempts and authentication failures, and bans an address that fails too
 * often. The table lives here rather than in sshd.c so the accept path and the
 * auth path share one implementation; see sshd_internal.h for the operations
 * sshd.c calls.
 */

#include "sshd_internal.h"

#include "ssh_utils.h"

static sshd_rate_limit_entry_t g_rate_limits[SSHD_RATE_LIMIT_MAX_ENTRIES];
static uint32_t g_rate_limit_count = 0;

static int ip_addr_equal(const xaios_ip_addr_user_t *a,
                         const xaios_ip_addr_user_t *b) {
  if (a->family != b->family) return 0;
  uint32_t len = (a->family == 4) ? 4U : 16U;
  for (uint32_t i = 0; i < len; ++i) {
    if (a->addr[i] != b->addr[i]) return 0;
  }
  return 1;
}

/* ---- Rate Limiting ---- */
static sshd_rate_limit_entry_t *find_rate_limit_entry(
    const xaios_ip_addr_user_t *ip) {
  for (uint32_t i = 0; i < g_rate_limit_count; ++i) {
    if (ip_addr_equal(&g_rate_limits[i].ip_address, ip)) {
      return &g_rate_limits[i];
    }
  }
  return 0;
}

static sshd_rate_limit_entry_t *allocate_rate_limit_entry(
    const xaios_ip_addr_user_t *client_addr, uint64_t now) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry != 0) return entry;
  if (g_rate_limit_count < SSHD_RATE_LIMIT_MAX_ENTRIES) {
    entry = &g_rate_limits[g_rate_limit_count++];
  } else {
    uint32_t oldest = 0U;
    for (uint32_t i = 1U; i < g_rate_limit_count; ++i) {
      if (g_rate_limits[i].ban_until <= now &&
          (g_rate_limits[oldest].ban_until > now ||
           g_rate_limits[i].last_attempt_time <
               g_rate_limits[oldest].last_attempt_time)) {
        oldest = i;
      }
    }
    if (g_rate_limits[oldest].ban_until <= now) {
      entry = &g_rate_limits[oldest];
    }
  }
  if (entry != 0) {
    ssh_mem_zero(entry, sizeof(*entry));
    entry->ip_address = *client_addr;
  }
  return entry;
}

int record_connection_attempt(
    const xaios_ip_addr_user_t *client_addr) {
  uint64_t now = xaios_clock_nanos();
  sshd_rate_limit_entry_t *entry =
      allocate_rate_limit_entry(client_addr, now);
  if (entry == 0) return -1;
  if (entry->connection_window_start == 0U ||
      now - entry->connection_window_start >= SSHD_CONNECTION_RATE_WINDOW) {
    entry->connection_window_start = now;
    entry->connection_count = 0U;
  }
  if (entry->connection_count >= SSHD_CONNECTION_RATE_LIMIT) return -1;
  ++entry->connection_count;
  entry->last_attempt_time = now;
  return 0;
}

int check_rate_limit(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry == 0) return 0;
  uint64_t now = xaios_clock_nanos();
  if (entry->ban_until > now) return -1;
  if (entry->ban_until > 0 && entry->ban_until <= now) {
    entry->failure_count = 0;
    entry->ban_until = 0;
  }
  return 0;
}

void record_auth_failure(const xaios_ip_addr_user_t *client_addr) {
  uint64_t now = xaios_clock_nanos();
  sshd_rate_limit_entry_t *entry =
      allocate_rate_limit_entry(client_addr, now);
  if (entry != 0) {
    entry->last_attempt_time = now;
    entry->failure_count++;
    if (entry->failure_count >= SSHD_RATE_LIMIT_MAX_FAILURES) {
      entry->ban_until = now + SSHD_RATE_LIMIT_BAN_DURATION;
    }
  }
}

void record_auth_success(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry == 0) return;
  entry->failure_count = 0;
  entry->ban_until = 0;
  /* Credit the connection back to the accept-rate window.
   *
   * That window exists to bound a flood from a peer that has proved nothing.
   * A peer that has just completed authentication has proved it holds a
   * credential this machine accepts, and counting it against a flood limit
   * protects nothing while breaking the workload this machine is for: an
   * administrator moving files over SFTP opens a connection per transfer.
   *
   * B-28 was exactly that, and it took two years to name because the refusal
   * was silent. The limit is 120 accepts per minute per address; a soak round
   * opens two connections -- the transfer and the status probe after it -- so
   * the 61st round carried the 121st connection and was closed before a byte
   * of SSH was spoken. From the far end that is `Connection closed`, with no
   * banner and nothing in the guest's console to attribute it to.
   *
   * Unauthenticated connections still count and still trip the limit, which is
   * the property the limiter exists for. Authenticated peers remain bounded by
   * max_connections and by the session table above it. */
  if (entry->connection_count != 0U) --entry->connection_count;
}
