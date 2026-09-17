/* Configuration subsystem and host-key identity of the admin control plane.
 *
 * Split out of admin_control.c so no source file exceeds 500 lines. This is
 * the active configuration: its text parser, its validator, its on-disk
 * load/store, the config.* operations, and the host-key rotation gate that
 * decides whether this machine may mint a new long-lived identity (F-05).
 * The authentication key database lives in admin_control_auth.c; the byte and
 * string primitives and the audit/mutation transaction framework stay in
 * admin_control.c and cross back through admin_control_internal.h.
 */

#include "admin_control_internal.h"

#include <xaios/entropy.h>
#include <xaios/klog.h>
#include <xaios/sha256.h>
#include <xaios/virtio_rng.h>
#include <xaios/xaiboot_fs.h>

#ifndef XAIOS_PASSWORD_AUTH_AVAILABLE
#define XAIOS_PASSWORD_AUTH_AVAILABLE 0
#endif

#define XAIOS_ADMIN_CONFIG_ALL_CHANGES UINT32_C(31)
#define XAIOS_ADMIN_MAX_SSH_CONNECTIONS UINT32_C(32)

static xaios_admin_config_t g_active_config;
static uint32_t g_initialized;

/* The bodies below were written against admin_control.c's file-local helper
   names. These aliases bind them to the prefixed exports the internal header
   declares, so the moved code reads exactly as it did in its old home. */
#define bytes_zero xaios_admin_bytes_zero
#define bytes_equal xaios_admin_bytes_equal
#define string_length xaios_admin_string_length
#define string_equal_range xaios_admin_string_equal_range
#define fnv1a64 xaios_admin_fnv1a64
#define staging_path_valid xaios_admin_staging_path_valid
#define principal_valid xaios_admin_principal_valid
#define config_valid xaios_admin_config_valid
#define parse_config_text xaios_admin_parse_config_text
#define host_key_entropy_gate xaios_admin_host_key_entropy_gate
#define begin_mutation xaios_admin_mutation_begin
#define finish_mutation xaios_admin_mutation_finish
#define abort_and_audit xaios_admin_mutation_abort_and_audit
#define audit_only xaios_admin_audit_only

uint32_t xaios_admin_control_initialized(void) { return g_initialized; }

static uint64_t config_checksum(const xaios_admin_config_t *config) {
  xaios_admin_config_t copy = *config;
  copy.checksum = 0U;
  return fnv1a64(&copy, sizeof(copy));
}

static void default_config(xaios_admin_config_t *config) {
  bytes_zero(config, sizeof(*config));
  config->magic = XAIOS_ADMIN_CONFIG_MAGIC;
  config->version = XAIOS_ADMIN_SCHEMA_VERSION;
  config->size = (uint16_t)sizeof(*config);
  config->generation = 1U;
  config->max_connections = 32U;
  config->max_channels_per_connection = 2U;
  config->max_auth_attempts = 5U;
  config->command_rate_per_minute = 60U;
  config->password_auth = XAIOS_PASSWORD_AUTH_AVAILABLE != 0
                              ? XAIOS_ADMIN_PASSWORD_DEVELOPMENT
                              : XAIOS_ADMIN_PASSWORD_DISABLED;
  config->checksum = config_checksum(config);
}

int xaios_admin_config_valid(const xaios_admin_config_t *config) {
  return config != 0 && config->magic == XAIOS_ADMIN_CONFIG_MAGIC &&
         config->version == XAIOS_ADMIN_SCHEMA_VERSION &&
         config->size == sizeof(*config) && config->generation != 0U &&
         config->max_connections >= 1U &&
         config->max_connections <= XAIOS_ADMIN_MAX_SSH_CONNECTIONS &&
         config->max_channels_per_connection >= 1U &&
         config->max_channels_per_connection <= 2U &&
         config->max_auth_attempts >= 1U &&
         config->max_auth_attempts <= 5U &&
         config->command_rate_per_minute >= 1U &&
         config->command_rate_per_minute <= 120U &&
         config->password_auth <= XAIOS_ADMIN_PASSWORD_DEVELOPMENT &&
         (config->password_auth == XAIOS_ADMIN_PASSWORD_DISABLED ||
          XAIOS_PASSWORD_AUTH_AVAILABLE != 0) &&
         config->reserved == 0U && config->checksum == config_checksum(config);
}

/* Whether a path is a staging path the config parser is allowed to read.
   Also used by admin_control_auth.c to vet key-file paths, so it crosses the
   module boundary under the xaios_admin_ prefix. */
int xaios_admin_staging_path_valid(const char *path) {
  static const char prefix[] = "/tmp/";
  uint64_t length = string_length(path);
  if (path == 0 || length <= sizeof(prefix) - 1U ||
      length >= XAIOS_XBFS_PATH_MAX) {
    return 0;
  }
  return bytes_equal(path, prefix, sizeof(prefix) - 1U);
}

int xaios_admin_principal_valid(const char *principal) {
  uint64_t length = string_length(principal);
  if (length == 0U || length >= XAIOS_ADMIN_PRINCIPAL_MAX) {
    return 0;
  }
  for (uint64_t i = 0U; i < length; ++i) {
    char value = principal[i];
    if (!((value >= 'a' && value <= 'z') ||
          (value >= 'A' && value <= 'Z') ||
          (value >= '0' && value <= '9') || value == '-' || value == '_' ||
          value == '.')) {
      return 0;
    }
  }
  return 1;
}

static int parse_u32(const char *text, uint64_t length, uint32_t *value) {
  uint32_t parsed = 0U;
  if (text == 0 || value == 0 || length == 0U) {
    return -1;
  }
  for (uint64_t i = 0U; i < length; ++i) {
    if (text[i] < '0' || text[i] > '9') {
      return -1;
    }
    uint32_t digit = (uint32_t)(text[i] - '0');
    if (parsed > (UINT32_MAX - digit) / 10U) {
      return -1;
    }
    parsed = parsed * 10U + digit;
  }
  *value = parsed;
  return 0;
}

int xaios_admin_parse_config_text(const char *text, uint64_t size,
                                  xaios_admin_config_t *candidate) {
  uint32_t seen = 0U;
  xaios_admin_config_t parsed;
  default_config(&parsed);
  parsed.password_auth = XAIOS_ADMIN_PASSWORD_DISABLED;
  for (uint64_t start = 0U; start <= size;) {
    uint64_t end = start;
    while (end < size && text[end] != '\n') {
      ++end;
    }
    uint64_t length = end - start;
    if (length != 0U && text[start + length - 1U] == '\r') {
      --length;
    }
    if (length != 0U && text[start] != '#') {
      uint64_t separator = 0U;
      while (separator < length && text[start + separator] != '=') {
        ++separator;
      }
      if (separator == 0U || separator == length) {
        return -1;
      }
      const char *key = text + start;
      const char *value = text + start + separator + 1U;
      uint64_t value_length = length - separator - 1U;
      uint32_t number = 0U;
      if (string_equal_range(key, separator, "schema")) {
        if ((seen & UINT32_C(32)) != 0U ||
            !string_equal_range(value, value_length, "xaios.config.v1")) {
          return -1;
        }
        seen |= UINT32_C(32);
      } else if (string_equal_range(key, separator,
                                    "ssh.max_connections")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.max_connections = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS;
      } else if (string_equal_range(
                     key, separator, "ssh.max_channels_per_connection")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.max_channels_per_connection = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS;
      } else if (string_equal_range(key, separator,
                                    "ssh.max_auth_attempts")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.max_auth_attempts = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS;
      } else if (string_equal_range(key, separator,
                                    "ssh.command_rate_per_minute")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.command_rate_per_minute = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE;
      } else if (string_equal_range(key, separator, "ssh.password_auth")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH) != 0U) {
          return -1;
        }
        if (string_equal_range(value, value_length, "disabled")) {
          parsed.password_auth = XAIOS_ADMIN_PASSWORD_DISABLED;
        } else if (string_equal_range(value, value_length, "development")) {
          parsed.password_auth = XAIOS_ADMIN_PASSWORD_DEVELOPMENT;
        } else {
          return -1;
        }
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH;
      } else {
        return -1;
      }
    }
    if (end == size) {
      break;
    }
    start = end + 1U;
  }
  if (seen != (XAIOS_ADMIN_CONFIG_ALL_CHANGES | UINT32_C(32))) {
    return -1;
  }
  parsed.generation = g_active_config.generation + 1U;
  if (parsed.generation == 0U) {
    return -1;
  }
  parsed.checksum = config_checksum(&parsed);
  if (!config_valid(&parsed)) {
    return -1;
  }
  *candidate = parsed;
  return 0;
}

static uint32_t config_change_mask(const xaios_admin_config_t *left,
                                   const xaios_admin_config_t *right) {
  uint32_t mask = 0U;
  if (left->max_connections != right->max_connections) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS;
  }
  if (left->max_channels_per_connection !=
      right->max_channels_per_connection) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS;
  }
  if (left->max_auth_attempts != right->max_auth_attempts) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS;
  }
  if (left->command_rate_per_minute != right->command_rate_per_minute) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE;
  }
  if (left->password_auth != right->password_auth) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH;
  }
  return mask;
}

static xaios_admin_result_t load_config_source(
    const char *path, xaios_admin_config_t *candidate, uint32_t *change_mask) {
  char source[XAIOS_ADMIN_SOURCE_BYTES];
  uint64_t size = 0U;
  if (!staging_path_valid(path) || candidate == 0 || change_mask == 0 ||
      xaiboot_fs_read(path, source, sizeof(source), &size) != XAIOS_OK ||
      size == 0U || parse_config_text(source, size, candidate) != 0) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  *change_mask = config_change_mask(&g_active_config, candidate);
  return XAIOS_ADMIN_RESULT_OK;
}

void admin_control_init(void) {
  xaios_admin_config_t stored;
  uint64_t size = 0U;
  default_config(&g_active_config);
  g_initialized = 0U;
  if (xaiboot_fs_mkdir("/state/control") != XAIOS_OK) {
    klog("admin-control: persistent state directory unavailable\n");
    return;
  }
  if (xaiboot_fs_read(XAIOS_ADMIN_CONFIG_PATH, &stored, sizeof(stored),
                      &size) == XAIOS_OK) {
    if (size != sizeof(stored) || !config_valid(&stored)) {
      klog("admin-control: active configuration invalid; safe defaults only\n");
      return;
    }
    g_active_config = stored;
  } else if (xaiboot_fs_write(XAIOS_ADMIN_CONFIG_PATH, &g_active_config,
                              sizeof(g_active_config)) != XAIOS_OK ||
             xaiboot_fs_commit("admin-initial-state") != XAIOS_OK) {
    klog("admin-control: failed to initialize active configuration\n");
    return;
  }
  g_initialized = 1U;
  klog("admin-control: initialized schema=%u generation=%lu password=%s\n",
       XAIOS_ADMIN_SCHEMA_VERSION, g_active_config.generation,
       g_active_config.password_auth == XAIOS_ADMIN_PASSWORD_DEVELOPMENT
           ? "development"
           : "disabled");
}

xaios_admin_result_t admin_control_config_get(xaios_admin_config_t *config) {
  if (config == 0 || g_initialized == 0U) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  *config = g_active_config;
  return XAIOS_ADMIN_RESULT_OK;
}

xaios_admin_result_t admin_control_config_validate(
    const char *path, xaios_admin_config_t *candidate, uint32_t *change_mask) {
  if (g_initialized == 0U) return XAIOS_ADMIN_RESULT_INVALID;
  return load_config_source(path, candidate, change_mask);
}

xaios_admin_result_t admin_control_config_apply(
    const char *path, const char *actor, uint32_t role, uint64_t operation_id,
    xaios_admin_config_t *applied, uint32_t *change_mask) {
  xaios_admin_config_t candidate;
  uint32_t changes = 0U;
  xaios_admin_result_t begin = begin_mutation(
      actor, role, XAIOS_ADMIN_ROLE_OPERATOR, operation_id, "config.apply");
  if (begin != XAIOS_ADMIN_RESULT_OK) return begin;
  xaios_admin_result_t validation =
      load_config_source(path, &candidate, &changes);
  if (validation != XAIOS_ADMIN_RESULT_OK) {
    return abort_and_audit(actor, role, operation_id, "config.apply",
                           validation);
  }
  if (xaiboot_fs_write(XAIOS_ADMIN_CONFIG_PATH, &candidate,
                       sizeof(candidate)) != XAIOS_OK) {
    return abort_and_audit(actor, role, operation_id, "config.apply",
                           XAIOS_ADMIN_RESULT_IO);
  }
  uint8_t object_hash[32];
  xaios_sha256(&candidate, sizeof(candidate), object_hash);
  xaios_admin_result_t finish = finish_mutation(
      actor, role, operation_id, "config.apply", object_hash);
  if (finish != XAIOS_ADMIN_RESULT_OK) {
    return audit_only(actor, role, operation_id, "config.apply", finish);
  }
  g_active_config = candidate;
  if (applied != 0) *applied = candidate;
  if (change_mask != 0) *change_mask = changes;
  return XAIOS_ADMIN_RESULT_OK;
}

static void bytes_to_hex(const uint8_t *bytes, uint32_t size, char *text) {
  static const char digits[] = "0123456789abcdef";
  for (uint32_t i = 0U; i < size; ++i) {
    text[i * 2U] = digits[bytes[i] >> 4U];
    text[i * 2U + 1U] = digits[bytes[i] & 15U];
  }
}

/* Whether this machine may mint a new long-lived identity. F-05, decided.

   A host key is exactly the kind of secret F-05 is about: it outlives the
   boot, it identifies the machine to everyone who connects, and on a
   platform whose only entropy is a seed file baked into the image it is
   reproducible by anyone holding that image. This used to warn, on the
   reasoning that refusing would take working machines off the network over a
   property they have always had.

   That reasoning does not survive looking at what rotation actually does.
   Rotation is not what gives a machine its first host key -- sshd mints that
   at boot if none is stored (userspace/sshd/ssh_host_key.c), and nothing
   here touches it. Refusing a rotation leaves the existing key in place and
   the machine exactly as reachable as it was a second earlier. What it
   declines to do is mint a *new* long-lived identity that anyone holding the
   image can derive, at the moment an operator has deliberately asked for a
   fresh one -- which is the moment they are least likely to read a warning,
   because they have just been told it worked. The cost of refusing is
   nothing; the cost of warning is a key an operator believes is new and is
   not.

   The first-boot mint is deliberately left alone. Refusing there would leave
   a machine with no host key and no SSH, and the operator who would fix that
   is the one who cannot get in. It names its provenance instead.

   The other half of F-05 is unchanged and still the operator's: provisioning
   a machine with real entropy. On every hypervisor this project supports but
   Fusion that is a virtio-rng device; on Fusion it is the open question. */
xaios_admin_result_t xaios_admin_host_key_entropy_gate(void) {
  if (entropy_is_production_grade() != 0U) return XAIOS_ADMIN_RESULT_OK;
  klog("admin: refusing to mint a host key on development-grade entropy "
       "(source=%u). A key minted from a seed baked into the image is "
       "reproducible by anyone holding that image. The existing key is "
       "unchanged and this machine is still reachable; provision real "
       "entropy and rotate again.\n", entropy_source());
  return XAIOS_ADMIN_RESULT_DENIED;
}

xaios_admin_result_t admin_control_host_key_rotate(
    const char *actor, uint32_t actor_role, uint64_t operation_id) {
  xaios_admin_result_t begin = begin_mutation(
      actor, actor_role, XAIOS_ADMIN_ROLE_ADMIN, operation_id,
      "auth.host.rotate");
  if (begin != XAIOS_ADMIN_RESULT_OK) return begin;
  uint8_t private_seed[32];
  char encoded[64];
  xaios_admin_result_t entropy_gate = host_key_entropy_gate();
  if (entropy_gate != XAIOS_ADMIN_RESULT_OK) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.host.rotate", entropy_gate);
  }
  if (virtio_rng_read(private_seed, sizeof(private_seed)) != XAIOS_OK) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.host.rotate", XAIOS_ADMIN_RESULT_IO);
  }
  bytes_to_hex(private_seed, sizeof(private_seed), encoded);
  if (xaiboot_fs_write(XAIOS_ADMIN_HOST_KEY_PATH, encoded, sizeof(encoded)) !=
      XAIOS_OK) {
    bytes_zero(private_seed, sizeof(private_seed));
    bytes_zero(encoded, sizeof(encoded));
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.host.rotate", XAIOS_ADMIN_RESULT_IO);
  }
  uint8_t object_hash[32];
  static const char rotation_object[] = "xaios-host-key-generation";
  xaios_sha256(rotation_object, sizeof(rotation_object) - 1U, object_hash);
  xaios_admin_result_t result = finish_mutation(
      actor, actor_role, operation_id, "auth.host.rotate", object_hash);
  bytes_zero(private_seed, sizeof(private_seed));
  bytes_zero(encoded, sizeof(encoded));
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return audit_only(actor, actor_role, operation_id, "auth.host.rotate",
                      result);
  }
  return result;
}

