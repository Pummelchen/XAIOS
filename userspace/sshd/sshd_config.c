#include "sshd_config.h"
#include "sshd.h"
#include "sshd_auth.h"
#include "ssh_channel.h"
#include "ssh_connection.h"
#include "ssh_host_key.h"
#include "ssh_utils.h"
#include <xaios_user.h>

static int config_record_valid(const xaios_admin_config_user_t *config) {
  uint64_t checksum_offset =
      (uint64_t)((const uint8_t *)&config->checksum -
                 (const uint8_t *)config);
  return config->magic == XAIOS_ADMIN_CONFIG_MAGIC &&
         config->version == XAIOS_ADMIN_SCHEMA_VERSION &&
         config->size == sizeof(*config) && config->generation != 0U &&
         config->max_connections >= 1U &&
         config->max_connections <= SSH_MAX_CONNECTIONS &&
         config->max_channels_per_connection >= 1U &&
         config->max_channels_per_connection <= SSH_CHANNELS_PER_CONNECTION &&
         config->max_auth_attempts >= 1U &&
         config->max_auth_attempts <= SSHD_MAX_AUTH_ATTEMPTS &&
         config->command_rate_per_minute >= 1U &&
         config->command_rate_per_minute <= 120U &&
         config->password_auth <= XAIOS_ADMIN_PASSWORD_DEVELOPMENT &&
         (config->password_auth == XAIOS_ADMIN_PASSWORD_DISABLED ||
          XAIOS_PASSWORD_AUTH_AVAILABLE != 0) &&
         config->reserved == 0U &&
         config->checksum ==
             sshd_fnv1a64_zero_range(config, sizeof(*config), checksum_offset,
                                     sizeof(config->checksum));
}

int load_runtime_config(void) {
  xaios_admin_config_user_t config;
  if (sshd_read_exact_file(XAIOS_ADMIN_CONFIG_PATH, &config,
                           sizeof(config)) != 0 ||
      !config_record_valid(&config)) {
    ssh_mem_zero(&config, sizeof(config));
    return -1;
  }
  g_runtime_config = config;
  g_password_auth_enabled =
      XAIOS_PASSWORD_AUTH_AVAILABLE != 0 &&
      config.password_auth == XAIOS_ADMIN_PASSWORD_DEVELOPMENT;
  return 0;
}

uint32_t sshd_max_channels_per_connection(void) {
  return g_runtime_config.max_channels_per_connection;
}

uint32_t sshd_command_rate_per_minute(void) {
  return g_runtime_config.command_rate_per_minute;
}

/* Which background services this machine was told to start.

   One list, one name per line, written by setup. A machine that has never
   been set up has no file and everything starts, which is what every image
   did before this.

   Only the network listener is selectable today. The console is not a service
   in this sense -- it is how a person reaches a machine that has no network,
   and a switch that could turn it off is a switch that can strand a machine
   nobody can reach. */
#define SSHD_SERVICES_PATH "/etc/xaios_services"

int service_enabled(const char *name) {
  char list[256];
  int length = xaios_read_file(SSHD_SERVICES_PATH, list, sizeof(list) - 1U);
  if (length <= 0) return 1; /* never configured: start everything */
  list[length] = '\0';
  uint32_t start = 0U;
  for (uint32_t i = 0U; i <= (uint32_t)length; ++i) {
    if (i != (uint32_t)length && list[i] != '\n' && list[i] != ',') continue;
    uint32_t end = i;
    while (end > start && (list[end - 1U] == '\r' || list[end - 1U] == ' ')) {
      --end;
    }
    uint32_t j = 0U;
    while (start + j < end && name[j] != '\0' && list[start + j] == name[j]) {
      ++j;
    }
    if (name[j] == '\0' && start + j == end) return 1;
    start = i + 1U;
  }
  return 0;
}

static int command_starts_with(const char *command, const char *prefix) {
  uint32_t i = 0U;
  if (command == 0 || prefix == 0) return 0;
  while (prefix[i] != '\0') {
    if (command[i] != prefix[i]) return 0;
    ++i;
  }
  return 1;
}

int sshd_reload_control_state(const char *command) {
  if (command_starts_with(command, "xaiosctl config apply ")) {
    if (load_runtime_config() != 0) return -1;
    if (sshd_auth_load_users(g_password_auth_enabled) != 0) return -1;
    if (sshd_auth_load_pin(g_password_auth_enabled) != 0) return -1;
    ssh_log(SSH_LOG_INFO, "Applied SSH runtime configuration generation=%u\n",
            g_runtime_config.generation);
  } else if (command_starts_with(command, "xaiosctl auth key add ") ||
             command_starts_with(command, "xaiosctl auth key remove ")) {
    if (sshd_keys_load() != 0) return -1;
  } else if (command_starts_with(command,
                                 "xaiosctl auth host-key rotate")) {
    if (ssh_host_key_reload() != 0) return -1;
    for (uint32_t i = 0U; i < SSH_MAX_CONNECTIONS; ++i) {
      ssh_connection_t *connection = ssh_conn_by_index(i);
      if (connection != 0) connection->close_requested = 1U;
    }
  }
  return 0;
}
