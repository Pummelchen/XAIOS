/*
 * The small per-connection support that sshd.c's state machine and service
 * loop share, split out of sshd.c. The declarations both sides use are in
 * sshd_connection_support.h; nothing here is a hub and no code in this file
 * was rewritten, only moved and renamed across the module boundary.
 */

#include "sshd_connection_support.h"

#include <xaios_user.h>

#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sshd_config.h"
#include "sshd_internal.h"

/* The reason the connection currently being serviced is giving up.
 *
 * sshd is one thread and process_connection runs for one connection at a
 * time; the walk reads this immediately after the call that set it, so one
 * slot is the whole requirement. Cleared at the top of every connection's
 * turn, so a reason can never be attributed to the wrong close. */
static const char *g_close_reason;

void sshd_close_reason_set(const char *reason) {
  g_close_reason = reason;
}

const char *sshd_close_reason(void) {
  return g_close_reason;
}

int sshd_close_because(const char *reason) {
  g_close_reason = reason;
  return -1;
}

/* ---- Timer ---- */
uint64_t sshd_timer_now(void) {
  return xaios_clock_nanos();
}

int sshd_verify_ipv4_ready(void) {
  /* The kernel reaches this service only after NIC selection and IPv4 setup.
   * Keep SSH availability independent of a third-party DNS/TCP endpoint. */
  u32 address = xaios_net_local_ipv4();
  return address != 0U && address != UINT32_MAX ? 0 : -1;
}

int sshd_bytes_have_zero(const uint8_t *data, uint32_t size) {
  for (uint32_t i = 0; i < size; ++i) {
    if (data[i] == 0U) return 1;
  }
  return 0;
}

int sshd_valid_client_version(const uint8_t *version, uint32_t length) {
  static const uint8_t prefix[] = "SSH-2.0-";
  if (version == 0 || length < sizeof(prefix) || version[length - 1U] != '\n') {
    return 0;
  }
  uint32_t text_length = length - 1U;
  if (text_length != 0U && version[text_length - 1U] == '\r') --text_length;
  if (text_length < sizeof(prefix) ||
      !sshd_bytes_equal(version, prefix, sizeof(prefix) - 1U)) {
    return 0;
  }
  for (uint32_t i = 0; i < text_length; ++i) {
    if (version[i] < 32U || version[i] > 126U) return 0;
  }
  return 1;
}

int sshd_send_auth_failure(ssh_connection_t *conn) {
  uint8_t reject[64];
  const char *methods = g_password_auth_enabled == 0U ? "publickey" :
                                                        "publickey,password";
  uint32_t methods_len = ssh_str_len(methods);
  reject[0] = SSH_MSG_USERAUTH_FAILURE;
  ssh_write_u32_be(reject + 1U, methods_len);
  ssh_mem_copy(reject + 5U, methods, methods_len);
  reject[5U + methods_len] = 0U;
  return conn_packet_write_encrypted(conn, reject, 6U + methods_len);
}
