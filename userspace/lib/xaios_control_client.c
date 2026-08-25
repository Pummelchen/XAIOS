#include <xaios_control_client.h>

typedef struct xaios_control_options {
  u16 operation;
  u32 json;
  u32 node_id;
  u64 timeout_ms;
  u64 operation_id;
  u64 since_cursor;
  u32 since_set;
  u32 limit;
  u32 follow;
  u32 assigned_role;
  u32 principal_role;
  u32 storage_partition_type;
  u32 dry_run;
  u32 verify_data;
  u32 read_only;
  u32 checksum_data;
  u32 trim_all_free;
  u64 size_bytes;
  u64 chunk_size;
  u64 block_size;
  u64 trim_offset;
  u64 trim_length;
  char component[XAIOS_CONTROL_LOG_COMPONENT_MAX];
  char argument[XAIOS_CONTROL_PATH_MAX];
  char replica[XAIOS_CONTROL_PATH_MAX];
  char replica_package_id[65];
  char storage_name[37];
  char confirmation[37];
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char target_principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  unsigned char model_uuid[16];
  unsigned char package_id[32];
  unsigned char signer_public_key[32];
  unsigned char signature[64];
  unsigned char source_revision[32];
  char architecture_id[33];
  char target_id[33];
} xaios_control_options_t;

static u64 g_next_request_id = 1ULL;

static void bytes_copy(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  for (u64 i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static int string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (u64 i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

static int string_copy(char *destination, u64 capacity, const char *source) {
  u64 length;
  if (destination == 0 || source == 0 || capacity == 0ULL) {
    return -1;
  }
  length = xaios_strlen(source);
  if (length + 1ULL > capacity) {
    return -1;
  }
  bytes_copy(destination, source, length + 1ULL);
  return 0;
}

static int append_char(char *output, u64 capacity, u64 *offset, char value) {
  if (output == 0 || offset == 0 || *offset + 1ULL >= capacity) {
    return -1;
  }
  output[*offset] = value;
  ++(*offset);
  output[*offset] = '\0';
  return 0;
}

static int append_text(char *output, u64 capacity, u64 *offset,
                       const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0ULL) {
    return -1;
  }
  for (u64 i = 0; text[i] != '\0'; ++i) {
    if (append_char(output, capacity, offset, text[i]) != 0) {
      return -1;
    }
  }
  return 0;
}

static int append_u64(char *output, u64 capacity, u64 *offset, u64 value) {
  char digits[24];
  u64 count = 0ULL;
  if (value == 0ULL) {
    return append_char(output, capacity, offset, '0');
  }
  while (value != 0ULL && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10ULL);
    value /= 10ULL;
  }
  while (count != 0ULL) {
    if (append_char(output, capacity, offset, digits[--count]) != 0) {
      return -1;
    }
  }
  return 0;
}

static int append_hex(char *output, u64 capacity, u64 *offset,
                      const unsigned char *bytes, u64 size) {
  static const char digits[] = "0123456789abcdef";
  for (u64 i = 0ULL; i < size; ++i) {
    if (append_char(output, capacity, offset, digits[bytes[i] >> 4U]) != 0 ||
        append_char(output, capacity, offset, digits[bytes[i] & 15U]) != 0) {
      return -1;
    }
  }
  return 0;
}

static int append_json_string(char *output, u64 capacity, u64 *offset,
                              const char *text, u64 text_size) {
  if (append_char(output, capacity, offset, '"') != 0) {
    return -1;
  }
  for (u64 i = 0; i < text_size; ++i) {
    unsigned char value = (unsigned char)text[i];
    if (value == '"' || value == '\\') {
      if (append_char(output, capacity, offset, '\\') != 0 ||
          append_char(output, capacity, offset, (char)value) != 0) {
        return -1;
      }
    } else if (value == '\n') {
      if (append_text(output, capacity, offset, "\\n") != 0) {
        return -1;
      }
    } else if (value == '\r') {
      if (append_text(output, capacity, offset, "\\r") != 0) {
        return -1;
      }
    } else if (value == '\t') {
      if (append_text(output, capacity, offset, "\\t") != 0) {
        return -1;
      }
    } else if (value < 32U) {
      if (append_text(output, capacity, offset, "?") != 0) {
        return -1;
      }
    } else if (append_char(output, capacity, offset, (char)value) != 0) {
      return -1;
    }
  }
  return append_char(output, capacity, offset, '"');
}

static int next_token(const char *text, u64 *index, char *token,
                      u64 capacity) {
  u64 i;
  u64 length = 0ULL;
  if (text == 0 || index == 0 || token == 0 || capacity == 0ULL) {
    return -1;
  }
  i = *index;
  while (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' ||
         text[i] == '\n') {
    ++i;
  }
  if (text[i] == '\0') {
    token[0] = '\0';
    *index = i;
    return 1;
  }
  while (text[i] != '\0' && text[i] != ' ' && text[i] != '\t' &&
         text[i] != '\r' && text[i] != '\n') {
    if (length + 1ULL >= capacity) {
      return -1;
    }
    token[length++] = text[i++];
  }
  token[length] = '\0';
  *index = i;
  return 0;
}

static int parse_u64(const char *text, u64 *value, u64 *digits) {
  u64 parsed = 0ULL;
  u64 i = 0ULL;
  if (text == 0 || value == 0 || digits == 0 || text[0] == '\0') {
    return -1;
  }
  while (text[i] >= '0' && text[i] <= '9') {
    u64 digit = (u64)(text[i] - '0');
    if (parsed > (~0ULL - digit) / 10ULL) {
      return -1;
    }
    parsed = parsed * 10ULL + digit;
    ++i;
  }
  if (i == 0ULL) {
    return -1;
  }
  *value = parsed;
  *digits = i;
  return 0;
}

static int parse_hex_exact(const char *text, unsigned char *output,
                           u64 output_size) {
  if (text == 0 || output == 0) return -1;
  for (u64 index = 0ULL; index < output_size; ++index) {
    unsigned char characters[2];
    for (u64 half = 0ULL; half < 2ULL; ++half) {
      char value = text[index * 2ULL + half];
      if (value >= '0' && value <= '9') {
        characters[half] = (unsigned char)(value - '0');
      } else if (value >= 'a' && value <= 'f') {
        characters[half] = (unsigned char)(value - 'a' + 10);
      } else if (value >= 'A' && value <= 'F') {
        characters[half] = (unsigned char)(value - 'A' + 10);
      } else {
        return -1;
      }
    }
    output[index] = (unsigned char)((characters[0] << 4U) | characters[1]);
  }
  return text[output_size * 2ULL] == '\0' ? 0 : -1;
}

static int parse_duration_ms(const char *text, u64 *value) {
  u64 parsed = 0ULL;
  u64 digits = 0ULL;
  if (parse_u64(text, &parsed, &digits) != 0 || parsed == 0ULL) {
    return -1;
  }
  if (text[digits] == '\0' ||
      (text[digits] == 'm' && text[digits + 1ULL] == 's' &&
       text[digits + 2ULL] == '\0')) {
    *value = parsed;
    return parsed <= 60000ULL ? 0 : -1;
  }
  if (text[digits] == 's' && text[digits + 1ULL] == '\0' &&
      parsed <= 60ULL) {
    *value = parsed * 1000ULL;
    return 0;
  }
  return -1;
}

static int parse_storage_size(const char *text, u64 *value) {
  if (text == 0 || value == 0) return -1;
  if (string_equal(text, "max")) {
    *value = 0ULL;
    return 0;
  }
  u64 parsed = 0ULL;
  u64 digits = 0ULL;
  if (parse_u64(text, &parsed, &digits) != 0 || parsed == 0ULL) return -1;
  u64 multiplier = 1ULL;
  const char *suffix = text + digits;
  if (suffix[0] == '\0' || string_equal(suffix, "B")) {
    multiplier = 1ULL;
  } else if (string_equal(suffix, "KiB")) {
    multiplier = 1ULL << 10U;
  } else if (string_equal(suffix, "MiB")) {
    multiplier = 1ULL << 20U;
  } else if (string_equal(suffix, "GiB")) {
    multiplier = 1ULL << 30U;
  } else if (string_equal(suffix, "TiB")) {
    multiplier = 1ULL << 40U;
  } else {
    return -1;
  }
  if (parsed > ~0ULL / multiplier) return -1;
  *value = parsed * multiplier;
  return 0;
}

static int parse_storage_range(char *text, u64 *offset, u64 *length) {
  if (text == 0 || offset == 0 || length == 0) return -1;
  u64 colon = 0ULL;
  while (text[colon] != '\0' && text[colon] != ':') ++colon;
  if (text[colon] != ':' || colon == 0ULL || text[colon + 1ULL] == '\0') {
    return -1;
  }
  text[colon] = '\0';
  if (string_equal(text, "0")) {
    *offset = 0ULL;
  } else if (parse_storage_size(text, offset) != 0) {
    return -1;
  }
  return parse_storage_size(text + colon + 1ULL, length);
}

static u32 parse_partition_type(const char *name) {
  if (string_equal(name, "state") || string_equal(name, "statefs")) {
    return XAIOS_STORAGE_PARTITION_STATE;
  }
  if (string_equal(name, "model") || string_equal(name, "modelfs")) {
    return XAIOS_STORAGE_PARTITION_MODEL;
  }
  if (string_equal(name, "recovery")) {
    return XAIOS_STORAGE_PARTITION_RECOVERY;
  }
  return 0U;
}

static int command_mentions_json(const char *command) {
  u64 index = 0ULL;
  char token[128];
  while (next_token(command, &index, token, sizeof(token)) == 0) {
    if (string_equal(token, "--json")) {
      return 1;
    }
  }
  return 0;
}

static u16 parse_simple_operation(const char *name) {
  if (string_equal(name, "version")) return XAIOS_CONTROL_OP_VERSION;
  if (string_equal(name, "status")) return XAIOS_CONTROL_OP_STATUS;
  if (string_equal(name, "health")) return XAIOS_CONTROL_OP_HEALTH;
  if (string_equal(name, "capabilities")) return XAIOS_CONTROL_OP_CAPABILITIES;
  if (string_equal(name, "hardware")) return XAIOS_CONTROL_OP_HARDWARE;
  if (string_equal(name, "metrics")) return XAIOS_CONTROL_OP_METRICS;
  if (string_equal(name, "logs")) return XAIOS_CONTROL_OP_LOGS;
  return 0U;
}

static const char *role_name(u32 role) {
  switch (role) {
  case XAIOS_CONTROL_ROLE_OBSERVER:
    return "observer";
  case XAIOS_CONTROL_ROLE_OPERATOR:
    return "operator";
  case XAIOS_CONTROL_ROLE_ADMIN:
    return "administrator";
  default:
    return "none";
  }
}

static u32 parse_role(const char *name) {
  if (string_equal(name, "observer")) return XAIOS_CONTROL_ROLE_OBSERVER;
  if (string_equal(name, "operator")) return XAIOS_CONTROL_ROLE_OPERATOR;
  if (string_equal(name, "administrator") || string_equal(name, "admin")) {
    return XAIOS_CONTROL_ROLE_ADMIN;
  }
  return XAIOS_CONTROL_ROLE_NONE;
}

static const char *state_name(u32 state) {
  switch (state) {
  case XAIOS_CONTROL_STATE_STOPPED:
    return "stopped";
  case XAIOS_CONTROL_STATE_RUNNING:
    return "running";
  case XAIOS_CONTROL_STATE_READY:
    return "ready";
  case XAIOS_CONTROL_STATE_DEGRADED:
    return "degraded";
  case XAIOS_CONTROL_STATE_FATAL:
    return "fatal";
  case XAIOS_CONTROL_STATE_UNSUPPORTED:
    return "unsupported";
  case XAIOS_CONTROL_STATE_INTERFACE_ONLY:
    return "interface-only";
  case XAIOS_CONTROL_STATE_FIXTURE_ONLY:
    return "fixture-only";
  case XAIOS_CONTROL_STATE_AVAILABLE:
    return "available";
  default:
    return "unknown";
  }
}

static const char *status_code(u32 status) {
  switch (status) {
  case XAIOS_CONTROL_STATUS_INVALID_REQUEST:
    return "invalid_request";
  case XAIOS_CONTROL_STATUS_UNSUPPORTED_VERSION:
    return "unsupported_version";
  case XAIOS_CONTROL_STATUS_UNKNOWN_OPERATION:
    return "unknown_operation";
  case XAIOS_CONTROL_STATUS_DENIED:
    return "permission_denied";
  case XAIOS_CONTROL_STATUS_BUFFER_TOO_SMALL:
    return "buffer_too_small";
  case XAIOS_CONTROL_STATUS_TIMEOUT:
    return "timeout";
  case XAIOS_CONTROL_STATUS_UNKNOWN_NODE:
    return "unknown_node";
  case XAIOS_CONTROL_STATUS_NOT_FOUND:
    return "not_found";
  case XAIOS_CONTROL_STATUS_REPLAYED:
    return "replayed_operation";
  case XAIOS_CONTROL_STATUS_CONFLICT:
    return "conflict";
  default:
    return "internal_error";
  }
}

static const char *status_message(u32 status) {
  switch (status) {
  case XAIOS_CONTROL_STATUS_INVALID_REQUEST:
    return "The control request is malformed.";
  case XAIOS_CONTROL_STATUS_UNSUPPORTED_VERSION:
    return "The control protocol version is not supported.";
  case XAIOS_CONTROL_STATUS_UNKNOWN_OPERATION:
    return "The control operation is not supported.";
  case XAIOS_CONTROL_STATUS_DENIED:
    return "The authenticated principal is not authorized.";
  case XAIOS_CONTROL_STATUS_BUFFER_TOO_SMALL:
    return "The response buffer is too small.";
  case XAIOS_CONTROL_STATUS_TIMEOUT:
    return "The control request timed out.";
  case XAIOS_CONTROL_STATUS_UNKNOWN_NODE:
    return "The requested node is not available.";
  case XAIOS_CONTROL_STATUS_NOT_FOUND:
    return "The requested object was not found.";
  case XAIOS_CONTROL_STATUS_REPLAYED:
    return "The operation ID has already been used.";
  case XAIOS_CONTROL_STATUS_CONFLICT:
    return "The requested mutation conflicts with current state.";
  default:
    return "The control request failed.";
  }
}

static int render_error(char *output, u64 capacity, u64 *offset, u64 request_id,
                        int json, const char *code, const char *message) {
  if (json != 0) {
    return append_text(output, capacity, offset,
                       "{\"schema_version\":1,\"request_id\":\"") ||
           append_u64(output, capacity, offset, request_id) ||
           append_text(output, capacity, offset,
                       "\",\"status\":\"error\",\"data\":null,\"error\":{"
                       "\"code\":") ||
           append_json_string(output, capacity, offset, code,
                              xaios_strlen(code)) ||
           append_text(output, capacity, offset, ",\"message\":") ||
           append_json_string(output, capacity, offset, message,
                              xaios_strlen(message)) ||
           append_text(output, capacity, offset, "}}\n");
  }
  return append_text(output, capacity, offset, "error[") ||
         append_text(output, capacity, offset, code) ||
         append_text(output, capacity, offset, "] request_id=") ||
         append_u64(output, capacity, offset, request_id) ||
         append_text(output, capacity, offset, ": ") ||
         append_text(output, capacity, offset, message) ||
         append_text(output, capacity, offset, "\n");
}

static int json_field_prefix(char *output, u64 capacity, u64 *offset,
                             int *first, const char *key) {
  if (*first == 0 && append_char(output, capacity, offset, ',') != 0) {
    return -1;
  }
  *first = 0;
  return append_json_string(output, capacity, offset, key, xaios_strlen(key)) ||
         append_char(output, capacity, offset, ':');
}

static int json_field_u64(char *output, u64 capacity, u64 *offset, int *first,
                          const char *key, u64 value) {
  if (json_field_prefix(output, capacity, offset, first, key) != 0) {
    return -1;
  }
  if (value == XAIOS_CONTROL_UNKNOWN_U64) {
    return append_text(output, capacity, offset, "null");
  }
  return append_u64(output, capacity, offset, value);
}

static int json_field_state(char *output, u64 capacity, u64 *offset,
                            int *first, const char *key, u32 state) {
  const char *name = state_name(state);
  return json_field_prefix(output, capacity, offset, first, key) ||
         append_json_string(output, capacity, offset, name, xaios_strlen(name));
}

static int json_field_string(char *output, u64 capacity, u64 *offset,
                             int *first, const char *key, const char *value) {
  return json_field_prefix(output, capacity, offset, first, key) ||
         append_json_string(output, capacity, offset, value,
                            xaios_strlen(value));
}

static int human_field_u64(char *output, u64 capacity, u64 *offset,
                           const char *key, u64 value) {
  if (append_text(output, capacity, offset, key) != 0 ||
      append_char(output, capacity, offset, '=') != 0) {
    return -1;
  }
  if (value == XAIOS_CONTROL_UNKNOWN_U64) {
    return append_text(output, capacity, offset, "unknown\n");
  }
  return append_u64(output, capacity, offset, value) ||
         append_char(output, capacity, offset, '\n');
}

static int human_field_state(char *output, u64 capacity, u64 *offset,
                             const char *key, u32 state) {
  return append_text(output, capacity, offset, key) ||
         append_char(output, capacity, offset, '=') ||
         append_text(output, capacity, offset, state_name(state)) ||
         append_char(output, capacity, offset, '\n');
}

static int json_envelope_begin(char *output, u64 capacity, u64 *offset,
                               u64 request_id) {
  return append_text(output, capacity, offset,
                     "{\"schema_version\":1,\"request_id\":\"") ||
         append_u64(output, capacity, offset, request_id) ||
         append_text(output, capacity, offset,
                     "\",\"status\":\"ok\",\"data\":{");
}

static int json_envelope_end(char *output, u64 capacity, u64 *offset) {
  return append_text(output, capacity, offset, "}}\n");
}

static int render_version(const void *payload, int json, char *output,
                          u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_version_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_string(output, capacity, offset, &first,
                             "product_version", value.product_version) ||
           json_field_string(output, capacity, offset, &first,
                             "build_identifier", value.build_identifier) ||
           json_field_string(output, capacity, offset, &first, "git_commit",
                             value.git_commit) ||
           json_field_u64(output, capacity, offset, &first,
                          "kernel_abi_version", value.kernel_abi_version) ||
           json_field_u64(output, capacity, offset, &first,
                          "control_protocol_version",
                          value.control_protocol_version) ||
           json_field_u64(output, capacity, offset, &first,
                          "model_package_version",
                          value.model_package_version) ||
           json_field_u64(output, capacity, offset, &first,
                          "model_volume_version",
                          value.model_volume_version == 0U
                              ? XAIOS_CONTROL_UNKNOWN_U64
                              : value.model_volume_version) ||
           json_field_string(output, capacity, offset, &first,
                             "architecture", value.architecture) ||
           json_field_string(output, capacity, offset, &first, "build_mode",
                             value.build_mode) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "XAIOS version\n") ||
         append_text(output, capacity, offset, "product_version=") ||
         append_text(output, capacity, offset, value.product_version) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "build_identifier=") ||
         append_text(output, capacity, offset, value.build_identifier) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "git_commit=") ||
         append_text(output, capacity, offset, value.git_commit) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "kernel_abi_version",
                         value.kernel_abi_version) ||
         human_field_u64(output, capacity, offset, "control_protocol_version",
                         value.control_protocol_version) ||
         human_field_u64(output, capacity, offset, "model_package_version",
                         value.model_package_version) ||
         human_field_u64(output, capacity, offset, "model_volume_version",
                         value.model_volume_version == 0U
                             ? XAIOS_CONTROL_UNKNOWN_U64
                             : value.model_volume_version) ||
         append_text(output, capacity, offset, "architecture=") ||
         append_text(output, capacity, offset, value.architecture) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "build_mode=") ||
         append_text(output, capacity, offset, value.build_mode) ||
         append_char(output, capacity, offset, '\n');
}

static int render_status(const void *payload, int json, char *output,
                         u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_status_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "uptime_ns",
                          value.uptime_ns) ||
           json_field_u64(output, capacity, offset, &first, "online_cpus",
                          value.online_cpus) ||
           json_field_u64(output, capacity, offset, &first, "worker_count",
                          value.worker_count) ||
           json_field_state(output, capacity, offset, &first, "init_service",
                            value.init_service_state) ||
           json_field_state(output, capacity, offset, &first,
                            "service_manager", value.manager_service_state) ||
           json_field_state(output, capacity, offset, &first, "ssh",
                            value.ssh_service_state) ||
           json_field_state(output, capacity, offset, &first, "network",
                            value.network_state) ||
           json_field_state(output, capacity, offset, &first, "storage",
                            value.storage_state) ||
           json_field_state(output, capacity, offset, &first, "model",
                            value.model_state) ||
           json_field_state(output, capacity, offset, &first, "cluster",
                            value.cluster_state) ||
           json_field_state(output, capacity, offset, &first, "readiness",
                            value.readiness_state) ||
           json_field_u64(output, capacity, offset, &first,
                          "readiness_reasons", value.readiness_reasons) ||
           json_field_u64(output, capacity, offset, &first,
                          "production_models_loaded",
                          value.production_models_loaded) ||
           json_field_u64(output, capacity, offset, &first, "queue_depth",
                          value.queue_depth) ||
           json_field_u64(output, capacity, offset, &first, "active_requests",
                          value.active_requests) ||
           json_field_u64(output, capacity, offset, &first, "physical_pages",
                          value.physical_pages) ||
           json_field_u64(output, capacity, offset, &first, "managed_pages",
                          value.managed_pages) ||
           json_field_u64(output, capacity, offset, &first, "free_pages",
                          value.free_pages) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "uptime_ns",
                         value.uptime_ns) ||
         human_field_state(output, capacity, offset, "init_service",
                           value.init_service_state) ||
         human_field_state(output, capacity, offset, "service_manager",
                           value.manager_service_state) ||
         human_field_state(output, capacity, offset, "ssh",
                           value.ssh_service_state) ||
         human_field_state(output, capacity, offset, "network",
                           value.network_state) ||
         human_field_state(output, capacity, offset, "storage",
                           value.storage_state) ||
         human_field_state(output, capacity, offset, "model",
                           value.model_state) ||
         human_field_state(output, capacity, offset, "cluster",
                           value.cluster_state) ||
         human_field_state(output, capacity, offset, "readiness",
                           value.readiness_state) ||
         human_field_u64(output, capacity, offset, "readiness_reasons",
                         value.readiness_reasons) ||
         human_field_u64(output, capacity, offset, "online_cpus",
                         value.online_cpus) ||
         human_field_u64(output, capacity, offset, "worker_count",
                         value.worker_count) ||
         human_field_u64(output, capacity, offset, "production_models_loaded",
                         value.production_models_loaded) ||
         human_field_u64(output, capacity, offset, "queue_depth",
                         value.queue_depth) ||
         human_field_u64(output, capacity, offset, "active_requests",
                         value.active_requests) ||
         human_field_u64(output, capacity, offset, "physical_pages",
                         value.physical_pages) ||
         human_field_u64(output, capacity, offset, "managed_pages",
                         value.managed_pages) ||
         human_field_u64(output, capacity, offset, "free_pages",
                         value.free_pages);
}

static int render_health(const void *payload, int json, char *output,
                         u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_health_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_state(output, capacity, offset, &first, "overall",
                            value.overall_state) ||
           json_field_state(output, capacity, offset, &first,
                            "process_liveness", value.process_liveness) ||
           json_field_state(output, capacity, offset, &first,
                            "node_readiness", value.node_readiness) ||
           json_field_state(output, capacity, offset, &first,
                            "model_readiness", value.model_readiness) ||
           json_field_state(output, capacity, offset, &first,
                            "cluster_readiness", value.cluster_readiness) ||
           json_field_u64(output, capacity, offset, &first, "fatal",
                          value.fatal) ||
           json_field_u64(output, capacity, offset, &first,
                          "readiness_reasons", value.readiness_reasons) ||
           json_field_u64(output, capacity, offset, &first,
                          "process_failures", value.process_failures) ||
           json_field_u64(output, capacity, offset, &first,
                          "memory_free_pages", value.memory_free_pages) ||
           json_field_u64(output, capacity, offset, &first,
                          "network_packet_drops",
                          value.network_packet_drops) ||
           json_field_u64(output, capacity, offset, &first, "log_overflows",
                          value.log_overflows) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_state(output, capacity, offset, "overall",
                           value.overall_state) ||
         human_field_state(output, capacity, offset, "process_liveness",
                           value.process_liveness) ||
         human_field_state(output, capacity, offset, "node_readiness",
                           value.node_readiness) ||
         human_field_state(output, capacity, offset, "model_readiness",
                           value.model_readiness) ||
         human_field_state(output, capacity, offset, "cluster_readiness",
                           value.cluster_readiness) ||
         human_field_u64(output, capacity, offset, "fatal", value.fatal) ||
         human_field_u64(output, capacity, offset, "readiness_reasons",
                         value.readiness_reasons) ||
         human_field_u64(output, capacity, offset, "process_failures",
                         value.process_failures) ||
         human_field_u64(output, capacity, offset, "memory_free_pages",
                         value.memory_free_pages) ||
         human_field_u64(output, capacity, offset, "network_packet_drops",
                         value.network_packet_drops) ||
         human_field_u64(output, capacity, offset, "log_overflows",
                         value.log_overflows);
}

static int render_capabilities(const void *payload, int json, char *output,
                               u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_capabilities_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_state(output, capacity, offset, &first, "ssh",
                            value.ssh) ||
           json_field_state(output, capacity, offset, &first, "sftp",
                            value.sftp) ||
           json_field_state(output, capacity, offset, &first, "ipv4",
                            value.ipv4) ||
           json_field_state(output, capacity, offset, &first, "ipv6",
                            value.ipv6) ||
           json_field_state(output, capacity, offset, &first, "udp",
                            value.udp) ||
           json_field_state(output, capacity, offset, &first, "mutable_fs",
                            value.mutable_fs) ||
           json_field_state(output, capacity, offset, &first,
                            "model_v1_fixture", value.model_v1_fixture) ||
           json_field_state(output, capacity, offset, &first, "model_v2",
                            value.model_v2) ||
           json_field_state(output, capacity, offset, &first,
                            "real_model_inference",
                            value.real_model_inference) ||
           json_field_state(output, capacity, offset, &first,
                            "native_macos", value.native_macos) ||
           json_field_state(output, capacity, offset, &first,
                            "distributed_inference",
                            value.distributed_inference) ||
           json_field_state(output, capacity, offset, &first,
                            "production_inference_service",
                            value.production_inference_service) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_state(output, capacity, offset, "ssh", value.ssh) ||
         human_field_state(output, capacity, offset, "sftp", value.sftp) ||
         human_field_state(output, capacity, offset, "ipv4", value.ipv4) ||
         human_field_state(output, capacity, offset, "ipv6", value.ipv6) ||
         human_field_state(output, capacity, offset, "udp", value.udp) ||
         human_field_state(output, capacity, offset, "mutable_fs",
                           value.mutable_fs) ||
         human_field_state(output, capacity, offset, "model_v1_fixture",
                           value.model_v1_fixture) ||
         human_field_state(output, capacity, offset, "model_v2",
                           value.model_v2) ||
         human_field_state(output, capacity, offset, "real_model_inference",
                           value.real_model_inference) ||
         human_field_state(output, capacity, offset, "native_macos",
                           value.native_macos) ||
         human_field_state(output, capacity, offset, "distributed_inference",
                           value.distributed_inference) ||
         human_field_state(output, capacity, offset,
                           "production_inference_service",
                           value.production_inference_service);
}

static int render_hardware(const void *payload, int json, char *output,
                           u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_hardware_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_string(output, capacity, offset, &first, "architecture",
                             value.architecture) ||
           json_field_string(output, capacity, offset, &first, "cpu_vendor",
                             value.cpu_vendor) ||
           json_field_string(output, capacity, offset, &first, "cpu_model",
                             value.cpu_model) ||
           json_field_u64(output, capacity, offset, &first, "core_count",
                          value.core_count) ||
           json_field_u64(output, capacity, offset, &first, "thread_count",
                          value.thread_count) ||
           json_field_u64(output, capacity, offset, &first, "numa_nodes",
                          value.numa_nodes) ||
           json_field_u64(output, capacity, offset, &first, "page_size",
                          value.page_size) ||
           json_field_u64(output, capacity, offset, &first, "physical_pages",
                          value.physical_pages) ||
           json_field_u64(output, capacity, offset, &first, "managed_pages",
                          value.managed_pages) ||
           json_field_u64(output, capacity, offset, &first, "free_pages",
                          value.free_pages) ||
           json_field_u64(output, capacity, offset, &first,
                          "model_reserved_bytes",
                          value.model_reserved_bytes) ||
           json_field_u64(output, capacity, offset, &first,
                          "kv_reserved_bytes", value.kv_reserved_bytes) ||
           json_field_u64(output, capacity, offset, &first,
                          "timer_frequency_hz", value.timer_frequency_hz) ||
           json_field_state(output, capacity, offset, &first, "neon",
                            value.neon) ||
           json_field_state(output, capacity, offset, &first, "sve",
                            value.sve) ||
           json_field_state(output, capacity, offset, &first, "avx2",
                            value.avx2) ||
           json_field_state(output, capacity, offset, &first, "avx512",
                            value.avx512) ||
           json_field_state(output, capacity, offset, &first, "vnni",
                            value.vnni) ||
           json_field_state(output, capacity, offset, &first, "amx",
                            value.amx) ||
           json_field_string(output, capacity, offset, &first,
                             "selected_backend", value.selected_backend) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "architecture=") ||
         append_text(output, capacity, offset, value.architecture) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "cpu_vendor=") ||
         append_text(output, capacity, offset, value.cpu_vendor) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "cpu_model=") ||
         append_text(output, capacity, offset, value.cpu_model) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "core_count",
                         value.core_count) ||
         human_field_u64(output, capacity, offset, "thread_count",
                         value.thread_count) ||
         human_field_u64(output, capacity, offset, "numa_nodes",
                         value.numa_nodes) ||
         human_field_u64(output, capacity, offset, "page_size",
                         value.page_size) ||
         human_field_u64(output, capacity, offset, "physical_pages",
                         value.physical_pages) ||
         human_field_u64(output, capacity, offset, "managed_pages",
                         value.managed_pages) ||
         human_field_u64(output, capacity, offset, "free_pages",
                         value.free_pages) ||
         human_field_u64(output, capacity, offset, "model_reserved_bytes",
                         value.model_reserved_bytes) ||
         human_field_u64(output, capacity, offset, "kv_reserved_bytes",
                         value.kv_reserved_bytes) ||
         human_field_u64(output, capacity, offset, "timer_frequency_hz",
                         value.timer_frequency_hz) ||
         human_field_state(output, capacity, offset, "neon", value.neon) ||
         human_field_state(output, capacity, offset, "sve", value.sve) ||
         human_field_state(output, capacity, offset, "avx2", value.avx2) ||
         human_field_state(output, capacity, offset, "avx512", value.avx512) ||
         human_field_state(output, capacity, offset, "vnni", value.vnni) ||
         human_field_state(output, capacity, offset, "amx", value.amx) ||
         append_text(output, capacity, offset, "selected_backend=") ||
         append_text(output, capacity, offset, value.selected_backend) ||
         append_char(output, capacity, offset, '\n');
}

static int render_metrics(const void *payload, int json, char *output,
                          u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_metrics_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  struct metric_field {
    const char *name;
    u64 value;
  } fields[] = {
      {"uptime_ns", value.uptime_ns},
      {"control_requests", value.control_requests},
      {"control_failures", value.control_failures},
      {"control_denials", value.control_denials},
      {"requests_accepted", value.requests_accepted},
      {"requests_completed", value.requests_completed},
      {"requests_failed", value.requests_failed},
      {"requests_cancelled", value.requests_cancelled},
      {"queue_depth", value.queue_depth},
      {"active_sessions", value.active_sessions},
      {"tokens_generated", value.tokens_generated},
      {"prefill_tokens_per_second", value.prefill_tokens_per_second},
      {"decode_tokens_per_second", value.decode_tokens_per_second},
      {"time_to_first_token_ns", value.time_to_first_token_ns},
      {"user_cpu_utilization_tenths", value.user_cpu_utilization_tenths},
      {"physical_pages", value.physical_pages},
      {"managed_pages", value.managed_pages},
      {"free_pages", value.free_pages},
      {"model_resident_bytes", value.model_resident_bytes},
      {"kv_cache_bytes", value.kv_cache_bytes},
      {"kv_cache_evictions", value.kv_cache_evictions},
      {"storage_reads", value.storage_reads},
      {"storage_read_bytes", value.storage_read_bytes},
      {"network_rx_packets", value.network_rx_packets},
      {"network_tx_packets", value.network_tx_packets},
      {"network_rx_bytes", value.network_rx_bytes},
      {"network_tx_bytes", value.network_tx_bytes},
      {"network_errors", value.network_errors},
      {"cluster_rpc_retries", value.cluster_rpc_retries},
      {"cluster_rpc_timeouts", value.cluster_rpc_timeouts},
      {"fixture_inferences", value.fixture_inferences},
      {"log_buffer_bytes", value.log_buffer_bytes},
      {"log_overflows", value.log_overflows},
      {"worker_count", value.worker_count},
  };
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0) {
      return -1;
    }
    for (u64 i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
      if (json_field_u64(output, capacity, offset, &first, fields[i].name,
                         fields[i].value) != 0) {
        return -1;
      }
    }
    if (json_field_state(output, capacity, offset, &first,
                         "per_worker_health", value.per_worker_health) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  for (u64 i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    if (human_field_u64(output, capacity, offset, fields[i].name,
                        fields[i].value) != 0) {
      return -1;
    }
  }
  return human_field_state(output, capacity, offset, "per_worker_health",
                           value.per_worker_health);
}

static int render_logs(const void *payload, u64 payload_length, int json,
                       char *output, u64 capacity, u64 *offset,
                       u64 request_id) {
  xaios_control_logs_payload_user_t value;
  if (payload_length < sizeof(value)) {
    return -1;
  }
  bytes_copy(&value, payload, sizeof(value));
  const char *records = (const char *)payload + sizeof(value);
  u64 records_size = payload_length - sizeof(value);
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "start_cursor",
                          value.start_cursor) ||
           json_field_u64(output, capacity, offset, &first, "next_cursor",
                          value.next_cursor) ||
           json_field_u64(output, capacity, offset, &first, "latest_cursor",
                          value.latest_cursor) ||
           json_field_u64(output, capacity, offset, &first, "record_count",
                          value.record_count) ||
           json_field_u64(output, capacity, offset, &first, "redacted_count",
                          value.redacted_count) ||
           json_field_u64(output, capacity, offset, &first, "timed_out",
                          value.timed_out) ||
           json_field_prefix(output, capacity, offset, &first, "records") ||
           append_json_string(output, capacity, offset, records, records_size) ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "start_cursor",
                      value.start_cursor) != 0 ||
      human_field_u64(output, capacity, offset, "next_cursor",
                      value.next_cursor) != 0 ||
      human_field_u64(output, capacity, offset, "latest_cursor",
                      value.latest_cursor) != 0 ||
      human_field_u64(output, capacity, offset, "record_count",
                      value.record_count) != 0 ||
      human_field_u64(output, capacity, offset, "redacted_count",
                      value.redacted_count) != 0 ||
      human_field_u64(output, capacity, offset, "timed_out",
                      value.timed_out) != 0) {
    return -1;
  }
  for (u64 i = 0; i < records_size; ++i) {
    if (append_char(output, capacity, offset, records[i]) != 0) {
      return -1;
    }
  }
  return 0;
}

static const char *password_auth_name(u32 mode) {
  return mode == XAIOS_ADMIN_PASSWORD_DEVELOPMENT ? "development"
                                                   : "disabled";
}

static int render_config(const void *payload, int json, char *output,
                         u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_config_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          value.config.generation) ||
           json_field_u64(output, capacity, offset, &first,
                          "max_connections", value.config.max_connections) ||
           json_field_u64(output, capacity, offset, &first,
                          "max_channels_per_connection",
                          value.config.max_channels_per_connection) ||
           json_field_u64(output, capacity, offset, &first,
                          "max_auth_attempts",
                          value.config.max_auth_attempts) ||
           json_field_u64(output, capacity, offset, &first,
                          "command_rate_per_minute",
                          value.config.command_rate_per_minute) ||
           json_field_string(output, capacity, offset, &first,
                             "password_auth",
                             password_auth_name(value.config.password_auth)) ||
           json_field_u64(output, capacity, offset, &first, "change_mask",
                          value.change_mask) ||
           json_field_u64(output, capacity, offset, &first, "validated",
                          value.validated) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "generation",
                         value.config.generation) ||
         human_field_u64(output, capacity, offset, "max_connections",
                         value.config.max_connections) ||
         human_field_u64(output, capacity, offset,
                         "max_channels_per_connection",
                         value.config.max_channels_per_connection) ||
         human_field_u64(output, capacity, offset, "max_auth_attempts",
                         value.config.max_auth_attempts) ||
         human_field_u64(output, capacity, offset, "command_rate_per_minute",
                         value.config.command_rate_per_minute) ||
         append_text(output, capacity, offset, "password_auth=") ||
         append_text(output, capacity, offset,
                     password_auth_name(value.config.password_auth)) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "change_mask",
                         value.change_mask) ||
         human_field_u64(output, capacity, offset, "validated",
                         value.validated);
}

static int fixed_string_valid(const char *text, u64 capacity) {
  if (text == 0 || capacity == 0ULL || text[capacity - 1ULL] != '\0') {
    return 0;
  }
  for (u64 i = 0ULL; i < capacity; ++i) {
    if (text[i] == '\0') return i != 0ULL;
  }
  return 0;
}

static int fixed_string_terminated(const char *text, u64 capacity) {
  if (text == 0 || capacity == 0ULL || text[capacity - 1ULL] != '\0') {
    return 0;
  }
  for (u64 index = 0ULL; index < capacity; ++index) {
    if (text[index] == '\0') return 1;
  }
  return 0;
}

static int append_quoted_hex(char *output, u64 capacity, u64 *offset,
                             const unsigned char *bytes, u64 size) {
  return append_char(output, capacity, offset, '"') ||
         append_hex(output, capacity, offset, bytes, size) ||
         append_char(output, capacity, offset, '"');
}

static int render_auth_keys(const void *payload, u64 payload_length, int json,
                            char *output, u64 capacity, u64 *offset,
                            u64 request_id) {
  xaios_control_auth_keys_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (metadata.key_count > XAIOS_ADMIN_MAX_KEYS ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.key_count *
                                sizeof(xaios_admin_key_view_user_t)) {
    return -1;
  }
  const xaios_admin_key_view_user_t *keys =
      (const xaios_admin_key_view_user_t *)((const unsigned char *)payload +
                                             sizeof(metadata));
  for (u32 i = 0U; i < metadata.key_count; ++i) {
    if (!fixed_string_valid(keys[i].principal, sizeof(keys[i].principal)) ||
        keys[i].role < XAIOS_CONTROL_ROLE_OBSERVER ||
        keys[i].role > XAIOS_CONTROL_ROLE_ADMIN || keys[i].reserved != 0U) {
      return -1;
    }
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_u64(output, capacity, offset, &first, "generation",
                       metadata.generation) != 0 ||
        json_field_u64(output, capacity, offset, &first, "key_count",
                       metadata.key_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "revoked_count",
                       metadata.revoked_count) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "keys") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 i = 0U; i < metadata.key_count; ++i) {
      if ((i != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_text(output, capacity, offset, "{\"fingerprint\":") != 0 ||
          append_quoted_hex(output, capacity, offset, keys[i].fingerprint,
                            sizeof(keys[i].fingerprint)) != 0 ||
          append_text(output, capacity, offset, ",\"principal\":") != 0 ||
          append_json_string(output, capacity, offset, keys[i].principal,
                             xaios_strlen(keys[i].principal)) != 0 ||
          append_text(output, capacity, offset, ",\"role\":") != 0 ||
          append_json_string(output, capacity, offset, role_name(keys[i].role),
                             xaios_strlen(role_name(keys[i].role))) != 0 ||
          append_char(output, capacity, offset, '}') != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "generation",
                      metadata.generation) != 0 ||
      human_field_u64(output, capacity, offset, "key_count",
                      metadata.key_count) != 0 ||
      human_field_u64(output, capacity, offset, "revoked_count",
                      metadata.revoked_count) != 0) {
    return -1;
  }
  for (u32 i = 0U; i < metadata.key_count; ++i) {
    if (append_text(output, capacity, offset, "fingerprint=") != 0 ||
        append_hex(output, capacity, offset, keys[i].fingerprint,
                   sizeof(keys[i].fingerprint)) != 0 ||
        append_text(output, capacity, offset, " principal=") != 0 ||
        append_text(output, capacity, offset, keys[i].principal) != 0 ||
        append_text(output, capacity, offset, " role=") != 0 ||
        append_text(output, capacity, offset, role_name(keys[i].role)) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

static int storage_boolean_valid(u32 value) { return value <= 1U; }

static int render_storage_devices(const void *payload, u64 payload_length,
                                  int json, char *output, u64 capacity,
                                  u64 *offset, u64 request_id) {
  xaios_control_storage_devices_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (metadata.record_count > XAIOS_CONTROL_STORAGE_MAX_DEVICES ||
      metadata.total_count < metadata.record_count || metadata.truncated > 1U ||
      metadata.reserved != 0U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_control_storage_device_record_user_t)) {
    return -1;
  }
  const xaios_control_storage_device_record_user_t *records =
      (const xaios_control_storage_device_record_user_t *)(
          (const unsigned char *)payload + sizeof(metadata));
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    if (!fixed_string_valid(records[index].identifier,
                            sizeof(records[index].identifier)) ||
        !fixed_string_valid(records[index].backend,
                            sizeof(records[index].backend)) ||
        !storage_boolean_valid(records[index].read_only) ||
        !storage_boolean_valid(records[index].flush_supported) ||
        !storage_boolean_valid(records[index].discard_supported) ||
        !storage_boolean_valid(records[index].write_zeroes_supported)) {
      return -1;
    }
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_count",
                       metadata.total_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "truncated",
                       metadata.truncated) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "devices") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 index = 0U; index < metadata.record_count; ++index) {
      const xaios_control_storage_device_record_user_t *record =
          &records[index];
      if ((index != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_text(output, capacity, offset, "{\"identifier\":") != 0 ||
          append_json_string(output, capacity, offset, record->identifier,
                             xaios_strlen(record->identifier)) != 0 ||
          append_text(output, capacity, offset, ",\"backend\":") != 0 ||
          append_json_string(output, capacity, offset, record->backend,
                             xaios_strlen(record->backend)) != 0 ||
          append_text(output, capacity, offset, ",\"capacity_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->capacity_bytes) != 0 ||
          append_text(output, capacity, offset,
                      ",\"capacity_logical_sectors\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->capacity_logical_sectors) != 0 ||
          append_text(output, capacity, offset,
                      ",\"logical_sector_size\":") != 0 ||
          append_u64(output, capacity, offset, record->logical_sector_size) != 0 ||
          append_text(output, capacity, offset,
                      ",\"physical_block_size\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->physical_block_size) != 0 ||
          append_text(output, capacity, offset,
                      ",\"max_transfer_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->max_transfer_bytes) != 0 ||
          append_text(output, capacity, offset,
                      ",\"discard_granularity\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->discard_granularity) != 0 ||
          append_text(output, capacity, offset,
                      ",\"max_discard_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->max_discard_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"read_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->read_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"write_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->write_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"discarded_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->discarded_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"io_errors\":") != 0 ||
          append_u64(output, capacity, offset, record->io_errors) != 0 ||
          append_text(output, capacity, offset, ",\"read_only\":") != 0 ||
          append_u64(output, capacity, offset, record->read_only) != 0 ||
          append_text(output, capacity, offset,
                      ",\"flush_supported\":") != 0 ||
          append_u64(output, capacity, offset, record->flush_supported) != 0 ||
          append_text(output, capacity, offset,
                      ",\"discard_supported\":") != 0 ||
          append_u64(output, capacity, offset, record->discard_supported) != 0 ||
          append_text(output, capacity, offset,
                      ",\"write_zeroes_supported\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->write_zeroes_supported) != 0 ||
          append_char(output, capacity, offset, '}') != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "record_count",
                      metadata.record_count) != 0 ||
      human_field_u64(output, capacity, offset, "total_count",
                      metadata.total_count) != 0 ||
      human_field_u64(output, capacity, offset, "truncated",
                      metadata.truncated) != 0) {
    return -1;
  }
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    const xaios_control_storage_device_record_user_t *record = &records[index];
    if (append_text(output, capacity, offset, "device=") != 0 ||
        append_text(output, capacity, offset, record->identifier) != 0 ||
        append_text(output, capacity, offset, " backend=") != 0 ||
        append_text(output, capacity, offset, record->backend) != 0 ||
        append_text(output, capacity, offset, " capacity_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->capacity_bytes) != 0 ||
        append_text(output, capacity, offset, " logical_sector_size=") != 0 ||
        append_u64(output, capacity, offset, record->logical_sector_size) != 0 ||
        append_text(output, capacity, offset, " read_only=") != 0 ||
        append_u64(output, capacity, offset, record->read_only) != 0 ||
        append_text(output, capacity, offset, " discard_supported=") != 0 ||
        append_u64(output, capacity, offset, record->discard_supported) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

static int render_storage_filesystems(const void *payload, u64 payload_length,
                                      int json, char *output, u64 capacity,
                                      u64 *offset, u64 request_id) {
  xaios_control_storage_filesystems_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (metadata.record_count > XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS ||
      metadata.total_count < metadata.record_count || metadata.truncated > 1U ||
      metadata.reserved != 0U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_control_storage_filesystem_record_user_t)) {
    return -1;
  }
  const xaios_control_storage_filesystem_record_user_t *records =
      (const xaios_control_storage_filesystem_record_user_t *)(
          (const unsigned char *)payload + sizeof(metadata));
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    if (!fixed_string_valid(records[index].mount_path,
                            sizeof(records[index].mount_path)) ||
        !fixed_string_valid(records[index].filesystem,
                            sizeof(records[index].filesystem)) ||
        !fixed_string_valid(records[index].device_identifier,
                            sizeof(records[index].device_identifier)) ||
        !storage_boolean_valid(records[index].mounted) ||
        !storage_boolean_valid(records[index].read_only) ||
        !storage_boolean_valid(records[index].staging_writable)) {
      return -1;
    }
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_count",
                       metadata.total_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "truncated",
                       metadata.truncated) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "filesystems") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 index = 0U; index < metadata.record_count; ++index) {
      const xaios_control_storage_filesystem_record_user_t *record =
          &records[index];
      if ((index != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_text(output, capacity, offset, "{\"mount_path\":") != 0 ||
          append_json_string(output, capacity, offset, record->mount_path,
                             xaios_strlen(record->mount_path)) != 0 ||
          append_text(output, capacity, offset, ",\"filesystem\":") != 0 ||
          append_json_string(output, capacity, offset, record->filesystem,
                             xaios_strlen(record->filesystem)) != 0 ||
          append_text(output, capacity, offset,
                      ",\"device_identifier\":") != 0 ||
          append_json_string(output, capacity, offset, record->device_identifier,
                             xaios_strlen(record->device_identifier)) != 0 ||
          append_text(output, capacity, offset, ",\"total_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->total_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"allocated_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->allocated_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"free_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->free_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"reserved_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->reserved_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"file_count\":") != 0 ||
          append_u64(output, capacity, offset, record->file_count) != 0 ||
          append_text(output, capacity, offset, ",\"directory_count\":") != 0 ||
          append_u64(output, capacity, offset, record->directory_count) != 0 ||
          append_text(output, capacity, offset, ",\"generation\":") != 0 ||
          append_u64(output, capacity, offset, record->generation) != 0 ||
          append_text(output, capacity, offset, ",\"block_size\":") != 0 ||
          append_u64(output, capacity, offset, record->block_size) != 0 ||
          append_text(output, capacity, offset, ",\"format_version\":") != 0 ||
          append_u64(output, capacity, offset, record->format_version) != 0 ||
          append_text(output, capacity, offset, ",\"package_count\":") != 0 ||
          append_u64(output, capacity, offset, record->package_count) != 0 ||
          append_text(output, capacity, offset, ",\"active_packages\":") != 0 ||
          append_u64(output, capacity, offset, record->active_packages) != 0 ||
          append_text(output, capacity, offset, ",\"staging_packages\":") != 0 ||
          append_u64(output, capacity, offset, record->staging_packages) != 0 ||
          append_text(output, capacity, offset,
                      ",\"quarantined_packages\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->quarantined_packages) != 0 ||
          append_text(output, capacity, offset, ",\"mounted\":") != 0 ||
          append_u64(output, capacity, offset, record->mounted) != 0 ||
          append_text(output, capacity, offset, ",\"read_only\":") != 0 ||
          append_u64(output, capacity, offset, record->read_only) != 0 ||
          append_text(output, capacity, offset,
                      ",\"staging_writable\":") != 0 ||
          append_u64(output, capacity, offset, record->staging_writable) != 0 ||
          append_char(output, capacity, offset, '}') != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "record_count",
                      metadata.record_count) != 0 ||
      human_field_u64(output, capacity, offset, "total_count",
                      metadata.total_count) != 0) {
    return -1;
  }
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    const xaios_control_storage_filesystem_record_user_t *record =
        &records[index];
    if (append_text(output, capacity, offset, "mount=") != 0 ||
        append_text(output, capacity, offset, record->mount_path) != 0 ||
        append_text(output, capacity, offset, " filesystem=") != 0 ||
        append_text(output, capacity, offset, record->filesystem) != 0 ||
        append_text(output, capacity, offset, " device=") != 0 ||
        append_text(output, capacity, offset, record->device_identifier) != 0 ||
        append_text(output, capacity, offset, " total_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->total_bytes) != 0 ||
        append_text(output, capacity, offset, " allocated_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->allocated_bytes) != 0 ||
        append_text(output, capacity, offset, " free_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->free_bytes) != 0 ||
        append_text(output, capacity, offset, " generation=") != 0 ||
        append_u64(output, capacity, offset, record->generation) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

static const char *partition_type_name(u32 type) {
  if (type == XAIOS_STORAGE_PARTITION_STATE) return "state";
  if (type == XAIOS_STORAGE_PARTITION_MODEL) return "model";
  if (type == XAIOS_STORAGE_PARTITION_RECOVERY) return "recovery";
  return "unknown";
}

static int partition_report_valid(
    const xaios_storage_partition_report_user_t *report) {
  return fixed_string_valid(report->device_identifier,
                            sizeof(report->device_identifier)) &&
         fixed_string_valid(report->disk_guid, sizeof(report->disk_guid)) &&
         storage_boolean_valid(report->primary_valid) &&
         storage_boolean_valid(report->backup_valid) &&
         storage_boolean_valid(report->copies_consistent) &&
         storage_boolean_valid(report->mutation_allowed) &&
         report->selected_copy <= 2U && report->reserved == 0U;
}

static int partition_record_valid(
    const xaios_storage_partition_record_user_t *record) {
  return fixed_string_valid(record->identifier, sizeof(record->identifier)) &&
         fixed_string_valid(record->name, sizeof(record->name)) &&
         fixed_string_valid(record->type_guid, sizeof(record->type_guid)) &&
         fixed_string_valid(record->unique_guid,
                            sizeof(record->unique_guid)) &&
         record->first_lba <= record->last_lba &&
         record->known_type <= XAIOS_STORAGE_PARTITION_RECOVERY;
}

static int append_partition_record_json(
    char *output, u64 capacity, u64 *offset,
    const xaios_storage_partition_record_user_t *record) {
  const char *type = partition_type_name(record->known_type);
  return append_text(output, capacity, offset, "{\"identifier\":") ||
         append_json_string(output, capacity, offset, record->identifier,
                            xaios_strlen(record->identifier)) ||
         append_text(output, capacity, offset, ",\"name\":") ||
         append_json_string(output, capacity, offset, record->name,
                            xaios_strlen(record->name)) ||
         append_text(output, capacity, offset, ",\"type\":") ||
         append_json_string(output, capacity, offset, type,
                            xaios_strlen(type)) ||
         append_text(output, capacity, offset, ",\"type_guid\":") ||
         append_json_string(output, capacity, offset, record->type_guid,
                            xaios_strlen(record->type_guid)) ||
         append_text(output, capacity, offset, ",\"unique_guid\":") ||
         append_json_string(output, capacity, offset, record->unique_guid,
                            xaios_strlen(record->unique_guid)) ||
         append_text(output, capacity, offset, ",\"first_lba\":") ||
         append_u64(output, capacity, offset, record->first_lba) ||
         append_text(output, capacity, offset, ",\"last_lba\":") ||
         append_u64(output, capacity, offset, record->last_lba) ||
         append_text(output, capacity, offset, ",\"size_bytes\":") ||
         append_u64(output, capacity, offset, record->size_bytes) ||
         append_text(output, capacity, offset, ",\"attributes\":") ||
         append_u64(output, capacity, offset, record->attributes) ||
         append_text(output, capacity, offset, ",\"table_index\":") ||
         append_u64(output, capacity, offset, record->table_index) ||
         append_char(output, capacity, offset, '}');
}

static int append_partition_report_json(
    char *output, u64 capacity, u64 *offset, int *first,
    const xaios_storage_partition_report_user_t *report) {
  return json_field_string(output, capacity, offset, first,
                           "device_identifier", report->device_identifier) ||
         json_field_string(output, capacity, offset, first, "disk_guid",
                           report->disk_guid) ||
         json_field_u64(output, capacity, offset, first, "capacity_bytes",
                        report->capacity_bytes) ||
         json_field_u64(output, capacity, offset, first,
                        "logical_sector_size", report->logical_sector_size) ||
         json_field_u64(output, capacity, offset, first, "first_usable_lba",
                        report->first_usable_lba) ||
         json_field_u64(output, capacity, offset, first, "last_usable_lba",
                        report->last_usable_lba) ||
         json_field_u64(output, capacity, offset, first, "partition_count",
                        report->partition_count) ||
         json_field_u64(output, capacity, offset, first, "primary_valid",
                        report->primary_valid) ||
         json_field_u64(output, capacity, offset, first, "backup_valid",
                        report->backup_valid) ||
         json_field_u64(output, capacity, offset, first, "copies_consistent",
                        report->copies_consistent) ||
         json_field_u64(output, capacity, offset, first, "selected_copy",
                        report->selected_copy) ||
         json_field_u64(output, capacity, offset, first, "mutation_allowed",
                        report->mutation_allowed);
}

static int append_partition_report_human(
    char *output, u64 capacity, u64 *offset,
    const xaios_storage_partition_report_user_t *report) {
  return append_text(output, capacity, offset, "device=") ||
         append_text(output, capacity, offset, report->device_identifier) ||
         append_text(output, capacity, offset, " disk_guid=") ||
         append_text(output, capacity, offset, report->disk_guid) ||
         append_text(output, capacity, offset, " capacity_bytes=") ||
         append_u64(output, capacity, offset, report->capacity_bytes) ||
         append_text(output, capacity, offset, " partitions=") ||
         append_u64(output, capacity, offset, report->partition_count) ||
         append_text(output, capacity, offset, " primary_valid=") ||
         append_u64(output, capacity, offset, report->primary_valid) ||
         append_text(output, capacity, offset, " backup_valid=") ||
         append_u64(output, capacity, offset, report->backup_valid) ||
         append_text(output, capacity, offset, " copies_consistent=") ||
         append_u64(output, capacity, offset, report->copies_consistent) ||
         append_text(output, capacity, offset, " mutation_allowed=") ||
         append_u64(output, capacity, offset, report->mutation_allowed) ||
         append_char(output, capacity, offset, '\n');
}

static int render_storage_partitions(const void *payload, u64 payload_length,
                                     int json, char *output, u64 capacity,
                                     u64 *offset, u64 request_id) {
  xaios_control_storage_partitions_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (!partition_report_valid(&metadata.report) ||
      metadata.record_count > XAIOS_CONTROL_STORAGE_MAX_PARTITIONS ||
      metadata.total_count < metadata.record_count || metadata.truncated > 1U ||
      metadata.reserved != 0U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_storage_partition_record_user_t)) {
    return -1;
  }
  const xaios_storage_partition_record_user_t *records =
      (const xaios_storage_partition_record_user_t *)(
          (const unsigned char *)payload + sizeof(metadata));
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    if (!partition_record_valid(&records[index])) return -1;
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        append_partition_report_json(output, capacity, offset, &first,
                                     &metadata.report) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_count",
                       metadata.total_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "truncated",
                       metadata.truncated) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "partitions") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 index = 0U; index < metadata.record_count; ++index) {
      if ((index != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_partition_record_json(output, capacity, offset,
                                       &records[index]) != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (append_partition_report_human(output, capacity, offset,
                                    &metadata.report) != 0) {
    return -1;
  }
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    const xaios_storage_partition_record_user_t *record = &records[index];
    if (append_text(output, capacity, offset, "partition=") != 0 ||
        append_text(output, capacity, offset, record->identifier) != 0 ||
        append_text(output, capacity, offset, " name=") != 0 ||
        append_text(output, capacity, offset, record->name) != 0 ||
        append_text(output, capacity, offset, " type=") != 0 ||
        append_text(output, capacity, offset,
                    partition_type_name(record->known_type)) != 0 ||
        append_text(output, capacity, offset, " unique_guid=") != 0 ||
        append_text(output, capacity, offset, record->unique_guid) != 0 ||
        append_text(output, capacity, offset, " size_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->size_bytes) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

static int render_storage_partition_plan(
    const void *payload, u64 payload_length, int json, char *output,
    u64 capacity, u64 *offset, u64 request_id) {
  xaios_storage_partition_plan_user_t plan;
  if (payload_length != sizeof(plan)) return -1;
  bytes_copy(&plan, payload, sizeof(plan));
  if (!partition_report_valid(&plan.report) || plan.changed > 1U ||
      plan.dry_run > 1U ||
      (plan.partition.identifier[0] != '\0' &&
       !partition_record_valid(&plan.partition))) {
    return -1;
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        append_partition_report_json(output, capacity, offset, &first,
                                     &plan.report) != 0 ||
        json_field_u64(output, capacity, offset, &first,
                       "resulting_partition_count",
                       plan.resulting_partition_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "affected_bytes",
                       plan.affected_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "changed",
                       plan.changed) != 0 ||
        json_field_u64(output, capacity, offset, &first, "dry_run",
                       plan.dry_run) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "partition") != 0) {
      return -1;
    }
    if (plan.partition.identifier[0] == '\0') {
      if (append_text(output, capacity, offset, "null") != 0) return -1;
    } else if (append_partition_record_json(output, capacity, offset,
                                            &plan.partition) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  if (append_partition_report_human(output, capacity, offset, &plan.report) !=
          0 ||
      human_field_u64(output, capacity, offset, "resulting_partition_count",
                      plan.resulting_partition_count) != 0 ||
      human_field_u64(output, capacity, offset, "affected_bytes",
                      plan.affected_bytes) != 0 ||
      human_field_u64(output, capacity, offset, "changed", plan.changed) != 0 ||
      human_field_u64(output, capacity, offset, "dry_run", plan.dry_run) != 0) {
    return -1;
  }
  if (plan.partition.identifier[0] != '\0' &&
      (append_text(output, capacity, offset, "partition=") != 0 ||
       append_text(output, capacity, offset, plan.partition.identifier) != 0 ||
       append_text(output, capacity, offset, " unique_guid=") != 0 ||
       append_text(output, capacity, offset, plan.partition.unique_guid) != 0 ||
       append_text(output, capacity, offset, " size_bytes=") != 0 ||
       append_u64(output, capacity, offset, plan.partition.size_bytes) != 0 ||
       append_char(output, capacity, offset, '\n') != 0)) {
    return -1;
  }
  return 0;
}

static const char *model_volume_check_name(u32 state) {
  if (state == XAIOS_MODEL_VOLUME_CHECK_CLEAN) return "clean";
  if (state == XAIOS_MODEL_VOLUME_CHECK_REPAIRABLE) return "repairable";
  if (state == XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE) {
    return "corrupt_unrepairable";
  }
  if (state == XAIOS_MODEL_VOLUME_CHECK_REPAIRED) return "repaired";
  return "unknown";
}

static int render_storage_volume_report(
    const void *payload, u64 payload_length, int json, char *output,
    u64 capacity, u64 *offset, u64 request_id) {
  xaios_model_volume_admin_report_user_t report;
  if (payload_length != sizeof(report)) return -1;
  bytes_copy(&report, payload, sizeof(report));
  if (!fixed_string_valid(report.target, sizeof(report.target)) ||
      !fixed_string_terminated(report.partition_uuid,
                               sizeof(report.partition_uuid)) ||
      !fixed_string_terminated(report.volume_uuid,
                               sizeof(report.volume_uuid)) ||
      !fixed_string_terminated(report.bad_package_id,
                               sizeof(report.bad_package_id)) ||
      !storage_boolean_valid(report.first_superblock_valid) ||
      !storage_boolean_valid(report.second_superblock_valid) ||
      !storage_boolean_valid(report.copies_compatible) ||
      !storage_boolean_valid(report.discard_supported) ||
      !storage_boolean_valid(report.dry_run) ||
      report.check_state > XAIOS_MODEL_VOLUME_CHECK_REPAIRED) {
    return -1;
  }
  const char *check = model_volume_check_name(report.check_state);
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_string(output, capacity, offset, &first, "target",
                             report.target) ||
           json_field_string(output, capacity, offset, &first,
                             "partition_uuid", report.partition_uuid) ||
           json_field_string(output, capacity, offset, &first, "volume_uuid",
                             report.volume_uuid) ||
           json_field_string(output, capacity, offset, &first, "check_state",
                             check) ||
           json_field_u64(output, capacity, offset, &first, "partition_bytes",
                          report.partition_bytes) ||
           json_field_u64(output, capacity, offset, &first, "volume_bytes",
                          report.volume_bytes) ||
           json_field_u64(output, capacity, offset, &first, "allocated_bytes",
                          report.allocated_bytes) ||
           json_field_u64(output, capacity, offset, &first, "free_bytes",
                          report.free_bytes) ||
           json_field_u64(output, capacity, offset, &first, "chunk_size",
                          report.chunk_size) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          report.generation) ||
           json_field_u64(output, capacity, offset, &first, "package_count",
                          report.package_count) ||
           json_field_u64(output, capacity, offset, &first, "active_packages",
                          report.active_packages) ||
           json_field_u64(output, capacity, offset, &first, "staging_packages",
                          report.staging_packages) ||
           json_field_u64(output, capacity, offset, &first,
                          "quarantined_packages",
                          report.quarantined_packages) ||
           json_field_u64(output, capacity, offset, &first, "checked_bytes",
                          report.checked_bytes) ||
           json_field_string(output, capacity, offset, &first,
                             "bad_package_id", report.bad_package_id) ||
           json_field_u64(output, capacity, offset, &first,
                          "bad_logical_offset", report.bad_logical_offset) ||
           json_field_u64(output, capacity, offset, &first,
                          "first_superblock_valid",
                          report.first_superblock_valid) ||
           json_field_u64(output, capacity, offset, &first,
                          "second_superblock_valid",
                          report.second_superblock_valid) ||
           json_field_u64(output, capacity, offset, &first,
                          "copies_compatible", report.copies_compatible) ||
           json_field_u64(output, capacity, offset, &first,
                          "discard_supported", report.discard_supported) ||
           json_field_u64(output, capacity, offset, &first, "dry_run",
                          report.dry_run) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "target=") ||
         append_text(output, capacity, offset, report.target) ||
         append_text(output, capacity, offset, " partition_uuid=") ||
         append_text(output, capacity, offset, report.partition_uuid) ||
         append_text(output, capacity, offset, " volume_uuid=") ||
         append_text(output, capacity, offset, report.volume_uuid) ||
         append_text(output, capacity, offset, " check_state=") ||
         append_text(output, capacity, offset, check) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "partition_bytes",
                         report.partition_bytes) ||
         human_field_u64(output, capacity, offset, "volume_bytes",
                         report.volume_bytes) ||
         human_field_u64(output, capacity, offset, "allocated_bytes",
                         report.allocated_bytes) ||
         human_field_u64(output, capacity, offset, "free_bytes",
                         report.free_bytes) ||
         human_field_u64(output, capacity, offset, "chunk_size",
                         report.chunk_size) ||
         human_field_u64(output, capacity, offset, "generation",
                         report.generation) ||
         human_field_u64(output, capacity, offset, "package_count",
                         report.package_count) ||
         human_field_u64(output, capacity, offset, "active_packages",
                         report.active_packages) ||
         human_field_u64(output, capacity, offset, "staging_packages",
                         report.staging_packages) ||
         human_field_u64(output, capacity, offset, "quarantined_packages",
                         report.quarantined_packages) ||
         human_field_u64(output, capacity, offset, "checked_bytes",
                         report.checked_bytes) ||
         human_field_u64(output, capacity, offset, "first_superblock_valid",
                         report.first_superblock_valid) ||
         human_field_u64(output, capacity, offset, "second_superblock_valid",
                         report.second_superblock_valid) ||
         human_field_u64(output, capacity, offset, "copies_compatible",
                         report.copies_compatible) ||
         human_field_u64(output, capacity, offset, "discard_supported",
                         report.discard_supported) ||
         human_field_u64(output, capacity, offset, "dry_run", report.dry_run);
}

static int render_mutation(const void *payload, int json, char *output,
                           u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_mutation_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "operation_id",
                          value.operation_id) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          value.generation) ||
           json_field_u64(output, capacity, offset, &first, "changed",
                          value.changed) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "operation_id",
                         value.operation_id) ||
         human_field_u64(output, capacity, offset, "generation",
                         value.generation) ||
         human_field_u64(output, capacity, offset, "changed", value.changed);
}

static int render_model_cleanup(const void *payload, int json, char *output,
                                u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_model_cleanup_report_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (value.changed > 1U || value.reserved != 0U) return -1;
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "operation_id",
                          value.operation_id) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          value.generation) ||
           json_field_u64(output, capacity, offset, &first,
                          "reclaimed_bytes", value.reclaimed_bytes) ||
           json_field_u64(output, capacity, offset, &first, "changed",
                          value.changed) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "operation_id",
                         value.operation_id) ||
         human_field_u64(output, capacity, offset, "generation",
                         value.generation) ||
         human_field_u64(output, capacity, offset, "reclaimed_bytes",
                         value.reclaimed_bytes) ||
         human_field_u64(output, capacity, offset, "changed", value.changed);
}

static const char *maintenance_state_name(u32 state) {
  switch (state) {
  case XAIOS_MODEL_MAINTENANCE_IDLE: return "idle";
  case XAIOS_MODEL_MAINTENANCE_RUNNING: return "running";
  case XAIOS_MODEL_MAINTENANCE_PAUSED: return "paused";
  case XAIOS_MODEL_MAINTENANCE_COMPLETE: return "complete";
  case XAIOS_MODEL_MAINTENANCE_CANCELLED: return "cancelled";
  case XAIOS_MODEL_MAINTENANCE_FAILED: return "failed";
  default: return "unknown";
  }
}

static int render_storage_scrub(const void *payload, int json, char *output,
                                u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_storage_scrub_report_user_t report;
  bytes_copy(&report, payload, sizeof(report));
  if (report.state > XAIOS_MODEL_MAINTENANCE_FAILED ||
      report.checked_bytes > report.total_bytes) {
    return -1;
  }
  const char *state = maintenance_state_name(report.state);
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "volume_uuid") !=
            0 ||
        append_quoted_hex(output, capacity, offset, report.volume_uuid, 16U) !=
            0 ||
        json_field_string(output, capacity, offset, &first, "state", state) !=
            0 ||
        json_field_u64(output, capacity, offset, &first, "generation",
                       report.generation) != 0 ||
        json_field_u64(output, capacity, offset, &first, "package_index",
                       report.package_index) != 0 ||
        json_field_u64(output, capacity, offset, &first, "chunk_index",
                       report.chunk_index) != 0 ||
        json_field_u64(output, capacity, offset, &first, "checked_bytes",
                       report.checked_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_bytes",
                       report.total_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "error_count",
                       report.error_count) != 0 ||
        json_field_u64(output, capacity, offset, &first,
                       "bad_logical_offset", report.bad_logical_offset) != 0 ||
        json_field_prefix(output, capacity, offset, &first,
                          "bad_package_id") != 0 ||
        append_quoted_hex(output, capacity, offset, report.bad_package_id,
                          32U) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "volume_uuid=") ||
         append_hex(output, capacity, offset, report.volume_uuid, 16U) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "state=") ||
         append_text(output, capacity, offset, state) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "generation",
                         report.generation) ||
         human_field_u64(output, capacity, offset, "package_index",
                         report.package_index) ||
         human_field_u64(output, capacity, offset, "chunk_index",
                         report.chunk_index) ||
         human_field_u64(output, capacity, offset, "checked_bytes",
                         report.checked_bytes) ||
         human_field_u64(output, capacity, offset, "total_bytes",
                         report.total_bytes) ||
         human_field_u64(output, capacity, offset, "error_count",
                         report.error_count) ||
         human_field_u64(output, capacity, offset, "bad_logical_offset",
                         report.bad_logical_offset);
}

static int render_storage_trim(const void *payload, int json, char *output,
                               u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_storage_trim_report_user_t report;
  bytes_copy(&report, payload, sizeof(report));
  if (report.state > XAIOS_MODEL_MAINTENANCE_FAILED || report.dry_run > 1U ||
      report.all_free > 1U || report.trimmed_bytes > report.eligible_bytes) {
    return -1;
  }
  const char *state = maintenance_state_name(report.state);
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_prefix(output, capacity, offset, &first,
                             "volume_uuid") ||
           append_quoted_hex(output, capacity, offset, report.volume_uuid,
                             sizeof(report.volume_uuid)) ||
           json_field_string(output, capacity, offset, &first, "state", state) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          report.generation) ||
           json_field_u64(output, capacity, offset, &first, "chunk_index",
                          report.chunk_index) ||
           json_field_u64(output, capacity, offset, &first, "cursor_offset",
                          report.cursor_offset) ||
           json_field_u64(output, capacity, offset, &first,
                          "requested_offset", report.requested_offset) ||
           json_field_u64(output, capacity, offset, &first,
                          "requested_length", report.requested_length) ||
           json_field_u64(output, capacity, offset, &first, "eligible_bytes",
                          report.eligible_bytes) ||
           json_field_u64(output, capacity, offset, &first, "processed_bytes",
                          report.trimmed_bytes) ||
           json_field_u64(output, capacity, offset, &first,
                          "processed_ranges", report.trimmed_ranges) ||
           json_field_u64(output, capacity, offset, &first, "error_count",
                          report.error_count) ||
           json_field_u64(output, capacity, offset, &first, "dry_run",
                          report.dry_run) ||
           json_field_u64(output, capacity, offset, &first, "all_free",
                          report.all_free) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "volume_uuid=") ||
         append_hex(output, capacity, offset, report.volume_uuid,
                    sizeof(report.volume_uuid)) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "state=") ||
         append_text(output, capacity, offset, state) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "generation",
                         report.generation) ||
         human_field_u64(output, capacity, offset, "chunk_index",
                         report.chunk_index) ||
         human_field_u64(output, capacity, offset, "cursor_offset",
                         report.cursor_offset) ||
         human_field_u64(output, capacity, offset, "requested_offset",
                         report.requested_offset) ||
         human_field_u64(output, capacity, offset, "requested_length",
                         report.requested_length) ||
         human_field_u64(output, capacity, offset, "eligible_bytes",
                         report.eligible_bytes) ||
         human_field_u64(output, capacity, offset, "processed_bytes",
                         report.trimmed_bytes) ||
         human_field_u64(output, capacity, offset, "processed_ranges",
                         report.trimmed_ranges) ||
         human_field_u64(output, capacity, offset, "error_count",
                         report.error_count) ||
         human_field_u64(output, capacity, offset, "dry_run", report.dry_run) ||
         human_field_u64(output, capacity, offset, "all_free",
                         report.all_free);
}

static const char *audit_result_name(u32 result) {
  switch (result) {
  case 0U: return "ok";
  case 1U: return "invalid";
  case 2U: return "denied";
  case 3U: return "not-found";
  case 4U: return "replay";
  case 5U: return "conflict";
  case 6U: return "no-memory";
  case 7U: return "io-error";
  default: return "unknown";
  }
}

static int render_audit(const void *payload, u64 payload_length, int json,
                        char *output, u64 capacity, u64 *offset,
                        u64 request_id) {
  xaios_control_audit_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (metadata.record_count > 16U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_admin_audit_record_user_t)) {
    return -1;
  }
  const xaios_admin_audit_record_user_t *records =
      (const xaios_admin_audit_record_user_t *)((const unsigned char *)payload +
                                                 sizeof(metadata));
  for (u32 i = 0U; i < metadata.record_count; ++i) {
    if (!fixed_string_valid(records[i].principal,
                            sizeof(records[i].principal)) ||
        !fixed_string_valid(records[i].operation,
                            sizeof(records[i].operation))) {
      return -1;
    }
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_u64(output, capacity, offset, &first, "next_sequence",
                       metadata.next_sequence) != 0 ||
        json_field_u64(output, capacity, offset, &first, "latest_sequence",
                       metadata.latest_sequence) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "records") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 i = 0U; i < metadata.record_count; ++i) {
      const char *result = audit_result_name(records[i].result);
      if ((i != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_text(output, capacity, offset, "{\"sequence\":") != 0 ||
          append_u64(output, capacity, offset, records[i].sequence) != 0 ||
          append_text(output, capacity, offset, ",\"operation_id\":") != 0 ||
          append_u64(output, capacity, offset, records[i].operation_id) != 0 ||
          append_text(output, capacity, offset, ",\"principal\":") != 0 ||
          append_json_string(output, capacity, offset, records[i].principal,
                             xaios_strlen(records[i].principal)) != 0 ||
          append_text(output, capacity, offset, ",\"role\":") != 0 ||
          append_json_string(output, capacity, offset,
                             role_name(records[i].role),
                             xaios_strlen(role_name(records[i].role))) != 0 ||
          append_text(output, capacity, offset, ",\"operation\":") != 0 ||
          append_json_string(output, capacity, offset, records[i].operation,
                             xaios_strlen(records[i].operation)) != 0 ||
          append_text(output, capacity, offset, ",\"result\":") != 0 ||
          append_json_string(output, capacity, offset, result,
                             xaios_strlen(result)) != 0 ||
          append_text(output, capacity, offset, ",\"object_hash\":") != 0 ||
          append_quoted_hex(output, capacity, offset, records[i].object_hash,
                            sizeof(records[i].object_hash)) != 0 ||
          append_char(output, capacity, offset, '}') != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "next_sequence",
                      metadata.next_sequence) != 0 ||
      human_field_u64(output, capacity, offset, "latest_sequence",
                      metadata.latest_sequence) != 0 ||
      human_field_u64(output, capacity, offset, "record_count",
                      metadata.record_count) != 0) {
    return -1;
  }
  for (u32 i = 0U; i < metadata.record_count; ++i) {
    if (append_text(output, capacity, offset, "sequence=") != 0 ||
        append_u64(output, capacity, offset, records[i].sequence) != 0 ||
        append_text(output, capacity, offset, " operation_id=") != 0 ||
        append_u64(output, capacity, offset, records[i].operation_id) != 0 ||
        append_text(output, capacity, offset, " principal=") != 0 ||
        append_text(output, capacity, offset, records[i].principal) != 0 ||
        append_text(output, capacity, offset, " role=") != 0 ||
        append_text(output, capacity, offset, role_name(records[i].role)) != 0 ||
        append_text(output, capacity, offset, " operation=") != 0 ||
        append_text(output, capacity, offset, records[i].operation) != 0 ||
        append_text(output, capacity, offset, " result=") != 0 ||
        append_text(output, capacity, offset,
                    audit_result_name(records[i].result)) != 0 ||
        append_text(output, capacity, offset, " object_hash=") != 0 ||
        append_hex(output, capacity, offset, records[i].object_hash,
                   sizeof(records[i].object_hash)) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

static int parse_options(const char *command, xaios_control_options_t *options,
                         const char **error_code, const char **error_message) {
  enum {
    SEEN_JSON = 1U,
    SEEN_TIMEOUT = 2U,
    SEEN_NODE = 4U,
    SEEN_COMPONENT = 8U,
    SEEN_SINCE = 16U,
    SEEN_LIMIT = 32U,
    SEEN_FOLLOW = 64U,
    SEEN_OPERATION_ID = 128U,
    SEEN_PRINCIPAL = 256U,
    SEEN_ROLE = 512U,
    SEEN_STORAGE_TYPE = 1024U,
    SEEN_STORAGE_SIZE = 2048U,
    SEEN_STORAGE_NAME = 4096U,
    SEEN_CONFIRMATION = 8192U,
    SEEN_DRY_RUN = 16384U,
    SEEN_CHUNK_SIZE = 32768U,
    SEEN_BLOCK_SIZE = 65536U,
    SEEN_CHECKSUM_DATA = 131072U,
    SEEN_VERIFY_DATA = 262144U,
    SEEN_READ_ONLY = 524288U,
    SEEN_CHECK = 1048576U,
    SEEN_REPAIR = 2097152U,
    SEEN_MODEL_UUID = 4194304U,
    SEEN_SIGNER_KEY = 8388608U,
    SEEN_SIGNATURE = 16777216U,
    SEEN_SOURCE_REVISION = 33554432U,
    SEEN_ARCHITECTURE = 67108864U,
    SEEN_TARGET = 134217728U,
    SEEN_SCRUB_ACTION = 268435456U,
    SEEN_TRIM_ALL_FREE = 536870912U,
    SEEN_TRIM_RANGE = 1073741824U,
  };
  u64 index = 0ULL;
  char token[160];
  char value[160];
  u32 seen = 0U;
  int needs_argument = 0;
  int needs_mount_path = 0;
  int needs_replica = 0;
  xaios_memzero(options, sizeof(*options));
  options->timeout_ms = 1000ULL;
  if (next_token(command, &index, token, sizeof(token)) != 0 ||
      !string_equal(token, "xaiosctl") ||
      next_token(command, &index, token, sizeof(token)) != 0) {
    *error_code = "invalid_argument";
    *error_message = "Usage: xaiosctl COMMAND [OPTIONS].";
    return -1;
  }
  options->operation = parse_simple_operation(token);
  if (options->operation == 0U && string_equal(token, "config")) {
    if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
    if (string_equal(token, "show")) {
      options->operation = XAIOS_CONTROL_OP_CONFIG_SHOW;
    } else if (string_equal(token, "validate")) {
      options->operation = XAIOS_CONTROL_OP_CONFIG_VALIDATE;
      needs_argument = 1;
    } else if (string_equal(token, "diff")) {
      options->operation = XAIOS_CONTROL_OP_CONFIG_DIFF;
      needs_argument = 1;
    } else if (string_equal(token, "apply")) {
      options->operation = XAIOS_CONTROL_OP_CONFIG_APPLY;
      needs_argument = 1;
    } else {
      goto unknown;
    }
  } else if (options->operation == 0U && string_equal(token, "auth")) {
    if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
    if (string_equal(token, "key")) {
      if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
      if (string_equal(token, "list")) {
        options->operation = XAIOS_CONTROL_OP_AUTH_KEY_LIST;
      } else if (string_equal(token, "add")) {
        options->operation = XAIOS_CONTROL_OP_AUTH_KEY_ADD;
        needs_argument = 1;
      } else if (string_equal(token, "remove")) {
        options->operation = XAIOS_CONTROL_OP_AUTH_KEY_REMOVE;
        needs_argument = 1;
      } else {
        goto unknown;
      }
    } else if (string_equal(token, "host-key")) {
      if (next_token(command, &index, token, sizeof(token)) != 0 ||
          !string_equal(token, "rotate")) {
        goto unknown;
      }
      options->operation = XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE;
    } else {
      goto unknown;
    }
  } else if (options->operation == 0U && string_equal(token, "audit")) {
    if (next_token(command, &index, token, sizeof(token)) != 0 ||
        !string_equal(token, "show")) {
      goto unknown;
    }
    options->operation = XAIOS_CONTROL_OP_AUDIT_SHOW;
  } else if (options->operation == 0U && string_equal(token, "model")) {
    if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
    if (string_equal(token, "verify")) {
      options->operation = XAIOS_CONTROL_OP_MODEL_VERIFY;
      needs_argument = 1;
    } else if (string_equal(token, "activate")) {
      options->operation = XAIOS_CONTROL_OP_MODEL_ACTIVATE;
      needs_argument = 1;
    } else if (string_equal(token, "register")) {
      options->operation = XAIOS_CONTROL_OP_MODEL_REGISTER;
      needs_argument = 1;
    } else if (string_equal(token, "cleanup")) {
      options->operation = XAIOS_CONTROL_OP_MODEL_CLEANUP;
      needs_argument = 1;
    } else {
      goto unknown;
    }
  } else if (options->operation == 0U && string_equal(token, "storage")) {
    if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
    if (string_equal(token, "device")) {
      if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
      if (string_equal(token, "list")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST;
      } else if (string_equal(token, "show")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW;
        needs_argument = 1;
      } else {
        goto unknown;
      }
    } else if (string_equal(token, "filesystem")) {
      if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
      if (string_equal(token, "list")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST;
      } else if (string_equal(token, "show")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW;
        needs_argument = 1;
      } else {
        goto unknown;
      }
    } else if (string_equal(token, "partition")) {
      if (next_token(command, &index, token, sizeof(token)) != 0) goto usage;
      if (string_equal(token, "list")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST;
      } else if (string_equal(token, "verify")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY;
      } else if (string_equal(token, "plan-create")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE;
      } else if (string_equal(token, "create")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE;
      } else if (string_equal(token, "plan-delete")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE;
      } else if (string_equal(token, "delete")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE;
      } else if (string_equal(token, "plan-resize")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE;
      } else if (string_equal(token, "resize")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE;
      } else if (string_equal(token, "repair")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR;
      } else {
        goto unknown;
      }
      needs_argument = 1;
    } else if (string_equal(token, "mount-status")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST;
    } else if (string_equal(token, "usage")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW;
      needs_argument = 1;
    } else if (string_equal(token, "format") ||
               string_equal(token, "format-plan")) {
      options->operation = string_equal(token, "format-plan")
                               ? XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN
                               : XAIOS_CONTROL_OP_STORAGE_FORMAT;
      needs_argument = 1;
    } else if (string_equal(token, "mount")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_MOUNT;
      needs_argument = 1;
      needs_mount_path = 1;
    } else if (string_equal(token, "unmount")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_UNMOUNT;
      needs_argument = 1;
    } else if (string_equal(token, "fsck")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FSCK;
      needs_argument = 1;
    } else if (string_equal(token, "repair-from-replica")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA;
      needs_argument = 1;
      needs_replica = 1;
    } else if (string_equal(token, "resize-plan")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN;
      needs_argument = 1;
    } else if (string_equal(token, "resize")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FS_RESIZE;
      needs_argument = 1;
    } else if (string_equal(token, "scrub")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_SCRUB_START;
      needs_argument = 1;
    } else if (string_equal(token, "trim")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_TRIM_START;
      needs_argument = 1;
    } else if (string_equal(token, "trim-status")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS;
      needs_argument = 1;
    } else if (string_equal(token, "trim-cancel")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL;
      needs_argument = 1;
    } else {
      goto unknown;
    }
  } else if (options->operation == 0U) {
    goto unknown;
  }
  if (needs_argument != 0) {
    if (next_token(command, &index, token, sizeof(token)) != 0 ||
        token[0] == '-' ||
        string_copy(options->argument, sizeof(options->argument), token) != 0) {
      *error_code = "invalid_argument";
      *error_message = "The command requires one bounded path or fingerprint.";
      return -1;
    }
  }
  if (needs_mount_path != 0) {
    if (next_token(command, &index, token, sizeof(token)) != 0 ||
        token[0] == '-' ||
        string_copy(options->mount_path, sizeof(options->mount_path), token) !=
            0) {
      *error_code = "invalid_mount_path";
      *error_message = "Mount requires one bounded absolute mount path.";
      return -1;
    }
  } else if (options->operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT) {
    if (string_copy(options->mount_path, sizeof(options->mount_path),
                    options->argument) != 0) {
      goto usage;
    }
  }
  if (needs_replica != 0) {
    if (next_token(command, &index, token, sizeof(token)) != 0 ||
        token[0] == '-' ||
        string_copy(options->replica, sizeof(options->replica), token) != 0 ||
        next_token(command, &index, token, sizeof(token)) != 0 ||
        parse_hex_exact(token, options->package_id,
                        sizeof(options->package_id)) != 0 ||
        string_copy(options->replica_package_id,
                    sizeof(options->replica_package_id), token) != 0) {
      *error_code = "invalid_replica_repair";
      *error_message = "Replica repair requires target, replica, and a 64-hex package ID.";
      return -1;
    }
  }
  options->limit = options->operation == XAIOS_CONTROL_OP_AUDIT_SHOW ? 16U
                                                                      : 100U;
  while (next_token(command, &index, token, sizeof(token)) == 0) {
    if (string_equal(token, "--json")) {
      if ((seen & SEEN_JSON) != 0U) goto duplicate;
      seen |= SEEN_JSON;
      options->json = 1U;
    } else if (string_equal(token, "--timeout")) {
      if ((seen & SEEN_TIMEOUT) != 0U) goto duplicate;
      seen |= SEEN_TIMEOUT;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_duration_ms(value, &options->timeout_ms) != 0) {
        *error_code = "invalid_timeout";
        *error_message = "Timeout must be 1ms through 60s.";
        return -1;
      }
    } else if (string_equal(token, "--node")) {
      u64 parsed = 0ULL;
      u64 digits = 0ULL;
      if ((seen & SEEN_NODE) != 0U) goto duplicate;
      seen |= SEEN_NODE;
      if (next_token(command, &index, value, sizeof(value)) != 0) {
        *error_code = "invalid_node";
        *error_message = "Node ID is required.";
        return -1;
      }
      if (string_equal(value, "local")) {
        options->node_id = 0U;
      } else if (parse_u64(value, &parsed, &digits) != 0 ||
                 value[digits] != '\0' || parsed > 0xffffffffULL) {
        *error_code = "invalid_node";
        *error_message = "Node ID must be local or an unsigned integer.";
        return -1;
      } else {
        options->node_id = (u32)parsed;
      }
    } else if (string_equal(token, "--component") ||
               string_equal(token, "--filter")) {
      if ((seen & SEEN_COMPONENT) != 0U) goto duplicate;
      seen |= SEEN_COMPONENT;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          string_copy(options->component, sizeof(options->component), value) !=
              0) {
        *error_code = "invalid_component";
        *error_message = "Log component is missing or too long.";
        return -1;
      }
    } else if (string_equal(token, "--since")) {
      u64 digits = 0ULL;
      if ((seen & SEEN_SINCE) != 0U) goto duplicate;
      seen |= SEEN_SINCE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_u64(value, &options->since_cursor, &digits) != 0 ||
          value[digits] != '\0') {
        *error_code = "invalid_cursor";
        *error_message = "Cursor must be an unsigned integer.";
        return -1;
      }
      options->since_set = 1U;
    } else if (string_equal(token, "--limit")) {
      u64 parsed = 0ULL;
      u64 digits = 0ULL;
      u64 maximum = options->operation == XAIOS_CONTROL_OP_AUDIT_SHOW
                        ? 16ULL
                        : 1000ULL;
      if ((seen & SEEN_LIMIT) != 0U) goto duplicate;
      seen |= SEEN_LIMIT;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_u64(value, &parsed, &digits) != 0 || value[digits] != '\0' ||
          parsed == 0ULL || parsed > maximum) {
        *error_code = "invalid_limit";
        *error_message = "Limit is outside the command's supported range.";
        return -1;
      }
      options->limit = (u32)parsed;
    } else if (string_equal(token, "--follow")) {
      if ((seen & SEEN_FOLLOW) != 0U) goto duplicate;
      seen |= SEEN_FOLLOW;
      options->follow = 1U;
    } else if (string_equal(token, "--operation-id")) {
      u64 digits = 0ULL;
      if ((seen & SEEN_OPERATION_ID) != 0U) goto duplicate;
      seen |= SEEN_OPERATION_ID;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_u64(value, &options->operation_id, &digits) != 0 ||
          value[digits] != '\0' || options->operation_id == 0ULL) {
        *error_code = "invalid_operation_id";
        *error_message = "Operation ID must be a nonzero unsigned integer.";
        return -1;
      }
    } else if (string_equal(token, "--principal")) {
      if ((seen & SEEN_PRINCIPAL) != 0U) goto duplicate;
      seen |= SEEN_PRINCIPAL;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          string_copy(options->target_principal,
                      sizeof(options->target_principal), value) != 0) {
        *error_code = "invalid_principal";
        *error_message = "Principal is missing or too long.";
        return -1;
      }
    } else if (string_equal(token, "--role")) {
      if ((seen & SEEN_ROLE) != 0U) goto duplicate;
      seen |= SEEN_ROLE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          (options->assigned_role = parse_role(value)) ==
              XAIOS_CONTROL_ROLE_NONE) {
        *error_code = "invalid_role";
        *error_message = "Role must be observer, operator, or administrator.";
        return -1;
      }
    } else if (string_equal(token, "--type")) {
      if ((seen & SEEN_STORAGE_TYPE) != 0U) goto duplicate;
      seen |= SEEN_STORAGE_TYPE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          (options->storage_partition_type = parse_partition_type(value)) ==
              0U) {
        *error_code = "invalid_partition_type";
        *error_message = "Partition type must be state, model, or recovery.";
        return -1;
      }
    } else if (string_equal(token, "--size") ||
               string_equal(token, "--grow-to")) {
      if ((seen & SEEN_STORAGE_SIZE) != 0U) goto duplicate;
      seen |= SEEN_STORAGE_SIZE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_storage_size(value, &options->size_bytes) != 0) {
        *error_code = "invalid_storage_size";
        *error_message = "Size must be max or a checked byte/KiB/MiB/GiB/TiB value.";
        return -1;
      }
    } else if (string_equal(token, "--chunk-size")) {
      if ((seen & SEEN_CHUNK_SIZE) != 0U) goto duplicate;
      seen |= SEEN_CHUNK_SIZE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_storage_size(value, &options->chunk_size) != 0 ||
          options->chunk_size == 0ULL) {
        *error_code = "invalid_chunk_size";
        *error_message = "Chunk size must be a checked byte/KiB/MiB value.";
        return -1;
      }
    } else if (string_equal(token, "--block-size")) {
      if ((seen & SEEN_BLOCK_SIZE) != 0U) goto duplicate;
      seen |= SEEN_BLOCK_SIZE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_storage_size(value, &options->block_size) != 0 ||
          options->block_size != 4096ULL) {
        *error_code = "invalid_block_size";
        *error_message = "ModelFS v1 requires a 4096-byte block size.";
        return -1;
      }
    } else if (string_equal(token, "--checksum-data")) {
      if ((seen & SEEN_CHECKSUM_DATA) != 0U) goto duplicate;
      seen |= SEEN_CHECKSUM_DATA;
      options->checksum_data = 1U;
    } else if (string_equal(token, "--verify-data")) {
      if ((seen & SEEN_VERIFY_DATA) != 0U) goto duplicate;
      seen |= SEEN_VERIFY_DATA;
      options->verify_data = 1U;
    } else if (string_equal(token, "--read-only")) {
      if ((seen & SEEN_READ_ONLY) != 0U) goto duplicate;
      seen |= SEEN_READ_ONLY;
      options->read_only = 1U;
    } else if (string_equal(token, "--model-uuid")) {
      if ((seen & SEEN_MODEL_UUID) != 0U) goto duplicate;
      seen |= SEEN_MODEL_UUID;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->model_uuid,
                          sizeof(options->model_uuid)) != 0) {
        *error_code = "invalid_model_uuid";
        *error_message = "Model UUID must contain exactly 32 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--signer-key")) {
      if ((seen & SEEN_SIGNER_KEY) != 0U) goto duplicate;
      seen |= SEEN_SIGNER_KEY;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->signer_public_key,
                          sizeof(options->signer_public_key)) != 0) {
        *error_code = "invalid_signer_key";
        *error_message = "Signer key must contain exactly 64 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--signature")) {
      if ((seen & SEEN_SIGNATURE) != 0U) goto duplicate;
      seen |= SEEN_SIGNATURE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->signature,
                          sizeof(options->signature)) != 0) {
        *error_code = "invalid_signature";
        *error_message = "Signature must contain exactly 128 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--source-revision")) {
      if ((seen & SEEN_SOURCE_REVISION) != 0U) goto duplicate;
      seen |= SEEN_SOURCE_REVISION;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->source_revision,
                          sizeof(options->source_revision)) != 0) {
        *error_code = "invalid_source_revision";
        *error_message = "Source revision must contain exactly 64 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--architecture")) {
      if ((seen & SEEN_ARCHITECTURE) != 0U) goto duplicate;
      seen |= SEEN_ARCHITECTURE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          string_copy(options->architecture_id,
                      sizeof(options->architecture_id), value) != 0) {
        *error_code = "invalid_architecture";
        *error_message = "Architecture ID is missing or exceeds 32 bytes.";
        return -1;
      }
    } else if (string_equal(token, "--target")) {
      if ((seen & SEEN_TARGET) != 0U) goto duplicate;
      seen |= SEEN_TARGET;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          string_copy(options->target_id, sizeof(options->target_id), value) !=
              0) {
        *error_code = "invalid_target";
        *error_message = "Target ID is missing or exceeds 32 bytes.";
        return -1;
      }
    } else if (string_equal(token, "--start") ||
               string_equal(token, "--status") ||
               string_equal(token, "--pause") ||
               string_equal(token, "--resume") ||
               string_equal(token, "--cancel")) {
      if ((seen & SEEN_SCRUB_ACTION) != 0U ||
          options->operation < XAIOS_CONTROL_OP_STORAGE_SCRUB_START ||
          options->operation > XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
        *error_code = "invalid_option";
        *error_message = "Scrub action applies only to storage scrub and may be specified once.";
        return -1;
      }
      seen |= SEEN_SCRUB_ACTION;
      if (string_equal(token, "--status")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS;
      } else if (string_equal(token, "--pause")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE;
      } else if (string_equal(token, "--resume")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME;
      } else if (string_equal(token, "--cancel")) {
        options->operation = XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL;
      }
    } else if (string_equal(token, "--check")) {
      if ((seen & SEEN_CHECK) != 0U) goto duplicate;
      seen |= SEEN_CHECK;
    } else if (string_equal(token, "--repair")) {
      if ((seen & SEEN_REPAIR) != 0U) goto duplicate;
      seen |= SEEN_REPAIR;
      if (options->operation != XAIOS_CONTROL_OP_STORAGE_FSCK) {
        *error_code = "invalid_option";
        *error_message = "Repair applies only to storage fsck.";
        return -1;
      }
      options->operation = XAIOS_CONTROL_OP_STORAGE_FS_REPAIR;
    } else if (string_equal(token, "--name") ||
               string_equal(token, "--label")) {
      if ((seen & SEEN_STORAGE_NAME) != 0U) goto duplicate;
      seen |= SEEN_STORAGE_NAME;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          string_copy(options->storage_name, sizeof(options->storage_name),
                      value) != 0) {
        *error_code = "invalid_partition_name";
        *error_message = "Partition name is missing or too long.";
        return -1;
      }
    } else if (string_equal(token, "--confirm-device") ||
               string_equal(token, "--confirm-partition")) {
      if ((seen & SEEN_CONFIRMATION) != 0U) goto duplicate;
      seen |= SEEN_CONFIRMATION;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          string_copy(options->confirmation, sizeof(options->confirmation),
                      value) != 0) {
        *error_code = "invalid_confirmation";
        *error_message = "An exact target UUID confirmation is required.";
        return -1;
      }
    } else if (string_equal(token, "--dry-run")) {
      if ((seen & SEEN_DRY_RUN) != 0U) goto duplicate;
      seen |= SEEN_DRY_RUN;
      options->dry_run = 1U;
    } else if (string_equal(token, "--all-free")) {
      if ((seen & SEEN_TRIM_ALL_FREE) != 0U) goto duplicate;
      seen |= SEEN_TRIM_ALL_FREE;
      options->trim_all_free = 1U;
    } else if (string_equal(token, "--range")) {
      if ((seen & SEEN_TRIM_RANGE) != 0U) goto duplicate;
      seen |= SEEN_TRIM_RANGE;
      if (next_token(command, &index, value, sizeof(value)) != 0 ||
          parse_storage_range(value, &options->trim_offset,
                              &options->trim_length) != 0) {
        *error_code = "invalid_trim_range";
        *error_message = "Trim range must be OFFSET:LENGTH with checked byte or IEC-unit values.";
        return -1;
      }
    } else {
      *error_code = "invalid_option";
      *error_message = "Unsupported xaiosctl option.";
      return -1;
    }
  }
  if (options->operation != XAIOS_CONTROL_OP_LOGS &&
      (seen & (SEEN_COMPONENT | SEEN_FOLLOW)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Log filter and follow options require xaiosctl logs.";
    return -1;
  }
  if (options->operation != XAIOS_CONTROL_OP_LOGS &&
      options->operation != XAIOS_CONTROL_OP_AUDIT_SHOW &&
      (seen & (SEEN_SINCE | SEEN_LIMIT)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Cursor and limit options require logs or audit show.";
    return -1;
  }
  int mutation = options->operation == XAIOS_CONTROL_OP_CONFIG_APPLY ||
                 options->operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
                 options->operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE ||
                 options->operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE ||
                 options->operation == XAIOS_CONTROL_OP_MODEL_REGISTER ||
                 options->operation == XAIOS_CONTROL_OP_MODEL_CLEANUP ||
                 options->operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_MOUNT ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_START ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_START ||
                 options->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL;

  int partition_command =
      options->operation >= XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR;
  int volume_command =
      options->operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE;
  int replica_repair =
      options->operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA;
  int model_register =
      options->operation == XAIOS_CONTROL_OP_MODEL_REGISTER;
  int scrub_command =
      options->operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL;
  int trim_command =
      options->operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL;
  u32 model_registration_fields =
      SEEN_MODEL_UUID | SEEN_SIGNER_KEY | SEEN_SIGNATURE |
      SEEN_SOURCE_REVISION | SEEN_ARCHITECTURE | SEEN_TARGET;
  if (model_register != 0) {
    if ((seen & model_registration_fields) != model_registration_fields ||
        (seen & SEEN_STORAGE_SIZE) == 0U ||
        parse_hex_exact(options->argument, options->package_id,
                        sizeof(options->package_id)) != 0) {
      *error_code = "model_registration_required";
      *error_message = "Model register requires a 64-hex package ID, --model-uuid, --signer-key, --signature, --source-revision, --architecture, --target, and --size.";
      return -1;
    }
  } else if ((seen & model_registration_fields) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Model identity options require model register.";
    return -1;
  }
  if (scrub_command == 0 && (seen & SEEN_SCRUB_ACTION) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Scrub actions require storage scrub.";
    return -1;
  }
  if (options->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_START) {
    if ((seen & (SEEN_TRIM_ALL_FREE | SEEN_TRIM_RANGE)) == 0U &&
        options->dry_run != 0U) {
      options->trim_all_free = 1U;
      seen |= SEEN_TRIM_ALL_FREE;
    }
    if (((seen & SEEN_TRIM_ALL_FREE) != 0U) ==
        ((seen & SEEN_TRIM_RANGE) != 0U)) {
      *error_code = "trim_scope_required";
      *error_message = "Trim requires exactly one of --all-free or --range OFFSET:LENGTH.";
      return -1;
    }
  } else if ((seen & (SEEN_TRIM_ALL_FREE | SEEN_TRIM_RANGE)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Trim scope applies only to storage trim.";
    return -1;
  }
  int format_command =
      options->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT;
  int filesystem_resize =
      options->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE;
  int filesystem_check =
      options->operation == XAIOS_CONTROL_OP_STORAGE_FSCK ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR;
  int partition_create =
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE;
  int partition_resize =
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE;
  if (partition_command == 0 && volume_command == 0 && replica_repair == 0 &&
      model_register == 0 &&
      trim_command == 0 &&
      (seen & (SEEN_STORAGE_TYPE | SEEN_STORAGE_SIZE | SEEN_STORAGE_NAME |
               SEEN_CONFIRMATION | SEEN_DRY_RUN | SEEN_CHUNK_SIZE |
               SEEN_BLOCK_SIZE | SEEN_CHECKSUM_DATA | SEEN_VERIFY_DATA |
               SEEN_READ_ONLY | SEEN_CHECK | SEEN_REPAIR)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Storage options require a storage command.";
    return -1;
  }
  if (partition_create != 0 &&
      (seen & (SEEN_STORAGE_TYPE | SEEN_STORAGE_SIZE | SEEN_STORAGE_NAME)) !=
          (SEEN_STORAGE_TYPE | SEEN_STORAGE_SIZE | SEEN_STORAGE_NAME)) {
    *error_code = "partition_layout_required";
    *error_message = "Partition create requires --type, --size, and --name.";
    return -1;
  }
  if (partition_create == 0 && format_command == 0 &&
      (seen & (SEEN_STORAGE_TYPE | SEEN_STORAGE_NAME)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Partition type and name apply only to create.";
    return -1;
  }
  if ((partition_resize != 0 || filesystem_resize != 0) &&
      (seen & SEEN_STORAGE_SIZE) == 0U) {
    *error_code = "resize_target_required";
    *error_message = "Partition resize requires --grow-to.";
    return -1;
  }
  if (partition_create == 0 && partition_resize == 0 &&
      filesystem_resize == 0 && model_register == 0 &&
      (seen & SEEN_STORAGE_SIZE) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Size applies only to create or resize.";
    return -1;
  }
  if (format_command != 0 &&
      ((seen & (SEEN_STORAGE_TYPE | SEEN_STORAGE_NAME | SEEN_BLOCK_SIZE |
                SEEN_CHECKSUM_DATA)) !=
           (SEEN_STORAGE_TYPE | SEEN_STORAGE_NAME | SEEN_BLOCK_SIZE |
            SEEN_CHECKSUM_DATA) ||
       options->storage_partition_type != XAIOS_STORAGE_PARTITION_MODEL)) {
    *error_code = "format_layout_required";
    *error_message = "ModelFS format requires --type modelfs, --label, --block-size 4096, and --checksum-data.";
    return -1;
  }
  if (format_command == 0 &&
      (seen & (SEEN_CHUNK_SIZE | SEEN_BLOCK_SIZE | SEEN_CHECKSUM_DATA)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Block, chunk, and checksum options apply only to format.";
    return -1;
  }
  if (filesystem_check == 0 &&
      (seen & (SEEN_VERIFY_DATA | SEEN_CHECK | SEEN_REPAIR)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Check, repair, and data verification apply only to fsck.";
    return -1;
  }
  if ((seen & SEEN_CHECK) != 0U && (seen & SEEN_REPAIR) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Choose either --check or --repair.";
    return -1;
  }
  if (options->operation != XAIOS_CONTROL_OP_STORAGE_MOUNT &&
      (seen & SEEN_READ_ONLY) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Read-only applies only to storage mount.";
    return -1;
  }
  if (options->dry_run != 0U) {
    if (options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE;
      mutation = 0;
    } else if (options->operation ==
               XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE;
      mutation = 0;
    } else if (options->operation ==
               XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE;
      mutation = 0;
    } else if (options->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN;
      mutation = 0;
    } else if (options->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN;
      mutation = 0;
    } else if (options->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_START) {
      mutation = 0;
    } else {
      *error_code = "invalid_option";
      *error_message = "Dry-run applies only to create, delete, format, or resize.";
      return -1;
    }
  }
  int partition_mutation =
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR;
  int volume_confirmation =
      options->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA;
  if ((partition_mutation != 0 || volume_confirmation != 0) &&
      (seen & SEEN_CONFIRMATION) == 0U) {
    *error_code = "confirmation_required";
    *error_message = "Storage mutations require exact UUID confirmation.";
    return -1;
  }
  if (partition_mutation == 0 && volume_confirmation == 0 &&
      (seen & SEEN_CONFIRMATION) != 0U) {
    *error_code = "invalid_option";
    *error_message = "UUID confirmation is accepted only for mutations.";
    return -1;
  }
  if (mutation != 0 && (seen & SEEN_OPERATION_ID) == 0U) {
    *error_code = "operation_id_required";
    *error_message = "Mutations require --operation-id.";
    return -1;
  }
  int partition_plan =
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE;
  int volume_plan =
      options->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN;
  if (mutation == 0 && partition_plan == 0 && volume_plan == 0 &&
      (seen & SEEN_OPERATION_ID) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Operation IDs are accepted only for mutations.";
    return -1;
  }
  if (options->operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD) {
    if ((seen & (SEEN_PRINCIPAL | SEEN_ROLE)) !=
        (SEEN_PRINCIPAL | SEEN_ROLE)) {
      *error_code = "identity_required";
      *error_message = "Key add requires --principal and --role.";
      return -1;
    }
  } else if ((seen & (SEEN_PRINCIPAL | SEEN_ROLE)) != 0U) {
    *error_code = "invalid_option";
    *error_message = "Principal and role are accepted only for key add.";
    return -1;
  }
  if (options->follow != 0U && options->timeout_ms > 5000ULL) {
    *error_code = "invalid_timeout";
    *error_message = "Log follow is bounded to at most 5s.";
    return -1;
  }
  return 0;

usage:
  *error_code = "invalid_argument";
  *error_message = "The xaiosctl command is incomplete.";
  return -1;
unknown:
  *error_code = "unknown_operation";
  *error_message = "Unknown xaiosctl command.";
  return -1;
duplicate:
  *error_code = "duplicate_option";
  *error_message = "An xaiosctl option was specified more than once.";
  return -1;
}

static u64 build_request(const xaios_control_options_t *options,
                         u64 request_id, unsigned char *request) {
  xaios_control_request_header_user_t header;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = options->operation;
  header.request_id = request_id;
  header.principal_role = options->principal_role;
  header.node_id = options->node_id;
  header.timeout_ms = options->timeout_ms;
  bytes_copy(request, &header, sizeof(header));
  if (options->operation == XAIOS_CONTROL_OP_LOGS) {
    xaios_control_log_request_payload_user_t logs;
    xaios_memzero(&logs, sizeof(logs));
    logs.since_cursor = options->since_cursor;
    logs.limit = options->limit;
    logs.follow = options->follow;
    bytes_copy(logs.component, options->component,
               xaios_strlen(options->component) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_LOG_REQUEST;
    header.payload_length = sizeof(logs);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &logs, sizeof(logs));
    return sizeof(header) + sizeof(logs);
  }
  if (options->operation == XAIOS_CONTROL_OP_CONFIG_VALIDATE ||
      options->operation == XAIOS_CONTROL_OP_CONFIG_DIFF ||
      options->operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY) {
    xaios_control_path_request_payload_user_t path;
    xaios_memzero(&path, sizeof(path));
    bytes_copy(path.path, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_PATH_REQUEST;
    header.payload_length = sizeof(path);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &path, sizeof(path));
    return sizeof(header) + sizeof(path);
  }
  if (options->operation >=
          XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR) {
    xaios_control_storage_partition_request_payload_user_t storage;
    xaios_memzero(&storage, sizeof(storage));
    bytes_copy(storage.request.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(storage.request.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(storage.request.name, options->storage_name,
               xaios_strlen(options->storage_name) + 1ULL);
    storage.request.size_bytes = options->size_bytes;
    storage.request.operation_id = options->operation_id;
    storage.request.partition_type = options->storage_partition_type;
    bytes_copy(storage.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_REQUEST;
    header.payload_length = sizeof(storage);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &storage, sizeof(storage));
    return sizeof(header) + sizeof(storage);
  }
  if (options->operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) {
    xaios_control_storage_volume_request_payload_user_t storage;
    xaios_memzero(&storage, sizeof(storage));
    bytes_copy(storage.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(storage.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(storage.mount_path, options->mount_path,
               xaios_strlen(options->mount_path) + 1ULL);
    bytes_copy(storage.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    storage.size_bytes = options->size_bytes;
    storage.chunk_size = options->chunk_size;
    storage.operation_id = options->operation_id;
    storage.verify_data = options->verify_data;
    storage.read_only = options->read_only;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST;
    header.payload_length = sizeof(storage);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &storage, sizeof(storage));
    return sizeof(header) + sizeof(storage);
  }
  if (options->operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA) {
    xaios_control_storage_replica_repair_request_payload_user_t repair;
    xaios_memzero(&repair, sizeof(repair));
    bytes_copy(repair.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(repair.replica, options->replica,
               xaios_strlen(options->replica) + 1ULL);
    bytes_copy(repair.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(repair.package_id, options->replica_package_id,
               xaios_strlen(options->replica_package_id) + 1ULL);
    bytes_copy(repair.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    repair.operation_id = options->operation_id;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_REPLICA_REPAIR_REQUEST;
    header.payload_length = sizeof(repair);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &repair, sizeof(repair));
    return sizeof(header) + sizeof(repair);
  }
  if (options->operation == XAIOS_CONTROL_OP_MODEL_REGISTER) {
    xaios_control_model_register_request_payload_user_t registration;
    xaios_memzero(&registration, sizeof(registration));
    registration.operation_id = options->operation_id;
    registration.logical_size = options->size_bytes;
    bytes_copy(registration.model_uuid, options->model_uuid,
               sizeof(registration.model_uuid));
    bytes_copy(registration.package_id, options->package_id,
               sizeof(registration.package_id));
    bytes_copy(registration.signer_public_key, options->signer_public_key,
               sizeof(registration.signer_public_key));
    bytes_copy(registration.signature, options->signature,
               sizeof(registration.signature));
    bytes_copy(registration.source_revision, options->source_revision,
               sizeof(registration.source_revision));
    bytes_copy(registration.architecture_id, options->architecture_id,
               xaios_strlen(options->architecture_id) + 1ULL);
    bytes_copy(registration.target_id, options->target_id,
               xaios_strlen(options->target_id) + 1ULL);
    bytes_copy(registration.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_MODEL_REGISTER_REQUEST;
    header.payload_length = sizeof(registration);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &registration, sizeof(registration));
    return sizeof(header) + sizeof(registration);
  }
  if (options->operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
    xaios_control_storage_volume_request_payload_user_t storage;
    xaios_memzero(&storage, sizeof(storage));
    bytes_copy(storage.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(storage.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    storage.operation_id = options->operation_id;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST;
    header.payload_length = sizeof(storage);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &storage, sizeof(storage));
    return sizeof(header) + sizeof(storage);
  }
  if (options->operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
    xaios_control_storage_trim_request_payload_user_t trim;
    xaios_memzero(&trim, sizeof(trim));
    bytes_copy(trim.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(trim.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    trim.offset = options->trim_offset;
    trim.length = options->trim_length;
    trim.operation_id = options->operation_id;
    trim.dry_run = options->dry_run;
    trim.all_free = options->trim_all_free;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REQUEST;
    header.payload_length = sizeof(trim);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &trim, sizeof(trim));
    return sizeof(header) + sizeof(trim);
  }
  if (options->operation == XAIOS_CONTROL_OP_AUDIT_SHOW) {
    xaios_control_audit_request_payload_user_t audit;
    xaios_memzero(&audit, sizeof(audit));
    audit.since_sequence = options->since_cursor;
    audit.limit = options->limit;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_AUDIT_REQUEST;
    header.payload_length = sizeof(audit);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &audit, sizeof(audit));
    return sizeof(header) + sizeof(audit);
  }
  if (options->operation == XAIOS_CONTROL_OP_CONFIG_APPLY ||
      options->operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
      options->operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE ||
      options->operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE ||
      options->operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE ||
      options->operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
    xaios_control_mutation_request_payload_user_t mutation;
    xaios_memzero(&mutation, sizeof(mutation));
    mutation.operation_id = options->operation_id;
    mutation.assigned_role = options->assigned_role;
    bytes_copy(mutation.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    if (options->argument[0] != '\0') {
      bytes_copy(mutation.argument, options->argument,
                 xaios_strlen(options->argument) + 1ULL);
    }
    if (options->target_principal[0] != '\0') {
      bytes_copy(mutation.target_principal, options->target_principal,
                 xaios_strlen(options->target_principal) + 1ULL);
    }
    header.payload_type = XAIOS_CONTROL_PAYLOAD_MUTATION_REQUEST;
    header.payload_length = sizeof(mutation);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &mutation, sizeof(mutation));
    return sizeof(header) + sizeof(mutation);
  }
  return sizeof(header);
}

static int query_once(const xaios_control_options_t *options, u64 request_id,
                      unsigned char *response, u64 *response_size) {
  unsigned char request[XAIOS_CONTROL_MAX_REQUEST_BYTES];
  u64 request_size = build_request(options, request_id, request);
  return xaios_control_query(request, request_size, response,
                             XAIOS_CONTROL_MAX_RESPONSE_BYTES, response_size);
}

static int validate_response(const unsigned char *response, u64 response_size,
                             u64 request_id, u16 operation,
                             xaios_control_response_header_user_t *header) {
  if (response_size < sizeof(*header)) {
    return -1;
  }
  bytes_copy(header, response, sizeof(*header));
  if (header->magic != XAIOS_CONTROL_MAGIC ||
      header->version != XAIOS_CONTROL_VERSION ||
      header->header_size != sizeof(*header) ||
      header->operation != operation || header->flags != 0U ||
      header->request_id != request_id ||
      header->payload_length > response_size - sizeof(*header) ||
      response_size != sizeof(*header) + header->payload_length) {
    return -1;
  }
  return 0;
}

static int follow_logs(xaios_control_options_t *options, u64 request_id,
                       unsigned char *response, u64 *response_size) {
  xaios_control_response_header_user_t header;
  xaios_control_logs_payload_user_t logs;
  if (validate_response(response, *response_size, request_id,
                        options->operation, &header) != 0 ||
      header.status != XAIOS_CONTROL_STATUS_OK ||
      header.payload_type != XAIOS_CONTROL_PAYLOAD_LOGS ||
      header.payload_length < sizeof(logs)) {
    return 0;
  }
  bytes_copy(&logs, response + sizeof(header), sizeof(logs));
  if (options->since_set == 0U) {
    options->since_cursor = logs.latest_cursor;
    options->since_set = 1U;
    logs.record_count = 0U;
  } else if (logs.record_count != 0U) {
    return 0;
  }
  u64 started = xaios_clock_nanos();
  u64 duration_ns = options->timeout_ms * 1000000ULL;
  u64 deadline = started + duration_ns;
  if (deadline < started) deadline = ~0ULL;
  while (xaios_clock_nanos() < deadline) {
    if (query_once(options, request_id, response, response_size) != 0 ||
        validate_response(response, *response_size, request_id,
                          options->operation, &header) != 0 ||
        header.status != XAIOS_CONTROL_STATUS_OK ||
        header.payload_type != XAIOS_CONTROL_PAYLOAD_LOGS ||
        header.payload_length < sizeof(logs)) {
      return -1;
    }
    bytes_copy(&logs, response + sizeof(header), sizeof(logs));
    if (logs.record_count != 0U) {
      return 0;
    }
    options->since_cursor = logs.next_cursor;
  }
  logs.timed_out = 1U;
  bytes_copy(response + sizeof(header), &logs, sizeof(logs));
  return 0;
}

int xaios_control_is_command(const char *command) {
  static const char prefix[] = "xaiosctl";
  if (command == 0) {
    return 0;
  }
  for (u64 i = 0; i < sizeof(prefix) - 1ULL; ++i) {
    if (command[i] != prefix[i]) {
      return 0;
    }
  }
  char next = command[sizeof(prefix) - 1ULL];
  return next == '\0' || next == ' ' || next == '\t' || next == '\r' ||
         next == '\n';
}

int xaios_control_run_as(const char *command, u32 principal_role,
                         const char *principal, char *output,
                         u64 output_capacity, u64 *output_size) {
  xaios_control_options_t options;
  unsigned char response[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  xaios_control_response_header_user_t header;
  const char *error_code = 0;
  const char *error_message = 0;
  u64 response_size = 0ULL;
  u64 offset = 0ULL;
  u64 request_id = g_next_request_id++;
  int json = command_mentions_json(command);
  int render_result = -1;
  if (g_next_request_id == 0ULL) g_next_request_id = 1ULL;
  if (output == 0 || output_size == 0 || output_capacity < 2ULL) {
    return -1;
  }
  output[0] = '\0';
  *output_size = 0ULL;
  if (parse_options(command, &options, &error_code, &error_message) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       error_code, error_message);
    *output_size = offset;
    return -1;
  }
  if (principal_role < XAIOS_CONTROL_ROLE_OBSERVER ||
      principal_role > XAIOS_CONTROL_ROLE_ADMIN ||
      principal == 0 || principal[0] == '\0' ||
      string_copy(options.principal, sizeof(options.principal), principal) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "invalid_principal",
                       "The authenticated principal context is invalid.");
    *output_size = offset;
    return -1;
  }
  options.principal_role = principal_role;
  json = (int)options.json;
  if (query_once(&options, request_id, response, &response_size) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "transport_error", "The control syscall failed.");
    *output_size = offset;
    return -1;
  }
  if (options.operation == XAIOS_CONTROL_OP_LOGS && options.follow != 0U &&
      follow_logs(&options, request_id, response, &response_size) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "transport_error", "Log follow failed.");
    *output_size = offset;
    return -1;
  }
  if (validate_response(response, response_size, request_id,
                        options.operation, &header) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "invalid_response",
                       "The control service returned an invalid response.");
    *output_size = offset;
    return -1;
  }
  if (header.status != XAIOS_CONTROL_STATUS_OK) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       status_code(header.status),
                       status_message(header.status));
    *output_size = offset;
    return -1;
  }
  const void *payload = response + sizeof(header);
  if (options.operation == XAIOS_CONTROL_OP_VERSION &&
      header.payload_type == XAIOS_CONTROL_PAYLOAD_VERSION &&
      header.payload_length == sizeof(xaios_control_version_payload_user_t)) {
    render_result = render_version(payload, json, output, output_capacity,
                                   &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_STATUS &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_STATUS &&
             header.payload_length ==
                 sizeof(xaios_control_status_payload_user_t)) {
    render_result = render_status(payload, json, output, output_capacity,
                                  &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_HEALTH &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_HEALTH &&
             header.payload_length ==
                 sizeof(xaios_control_health_payload_user_t)) {
    render_result = render_health(payload, json, output, output_capacity,
                                  &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_CAPABILITIES &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_CAPABILITIES &&
             header.payload_length ==
                 sizeof(xaios_control_capabilities_payload_user_t)) {
    render_result = render_capabilities(payload, json, output, output_capacity,
                                        &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_HARDWARE &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_HARDWARE &&
             header.payload_length ==
                 sizeof(xaios_control_hardware_payload_user_t)) {
    render_result = render_hardware(payload, json, output, output_capacity,
                                    &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_METRICS &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_METRICS &&
             header.payload_length ==
                 sizeof(xaios_control_metrics_payload_user_t)) {
    render_result = render_metrics(payload, json, output, output_capacity,
                                   &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_LOGS &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_LOGS) {
    render_result = render_logs(payload, header.payload_length, json, output,
                                output_capacity, &offset, request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_CONFIG_SHOW ||
              options.operation == XAIOS_CONTROL_OP_CONFIG_VALIDATE ||
              options.operation == XAIOS_CONTROL_OP_CONFIG_DIFF ||
              options.operation == XAIOS_CONTROL_OP_CONFIG_APPLY) &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_CONFIG &&
             header.payload_length ==
                 sizeof(xaios_control_config_payload_user_t)) {
    render_result = render_config(payload, json, output, output_capacity,
                                  &offset, request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_AUTH_KEY_LIST ||
              options.operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
              options.operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE) &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_AUTH_KEYS) {
    render_result = render_auth_keys(payload, header.payload_length, json,
                                     output, output_capacity, &offset,
                                     request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE ||
              options.operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
              options.operation == XAIOS_CONTROL_OP_MODEL_REGISTER ||
              options.operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE) &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_MUTATION &&
             header.payload_length ==
                 sizeof(xaios_control_mutation_payload_user_t)) {
    render_result = render_mutation(payload, json, output, output_capacity,
                                    &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_MODEL_CLEANUP &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_MODEL_CLEANUP_REPORT &&
             header.payload_length ==
                 sizeof(xaios_control_model_cleanup_report_user_t)) {
    render_result = render_model_cleanup(payload, json, output,
                                         output_capacity, &offset, request_id);
  } else if (options.operation == XAIOS_CONTROL_OP_AUDIT_SHOW &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_AUDIT) {
    render_result = render_audit(payload, header.payload_length, json, output,
                                 output_capacity, &offset, request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST ||
              options.operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW) &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES) {
    render_result = render_storage_devices(
        payload, header.payload_length, json, output, output_capacity, &offset,
        request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST ||
              options.operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW) &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS) {
    render_result = render_storage_filesystems(
        payload, header.payload_length, json, output, output_capacity, &offset,
        request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST ||
              options.operation ==
                  XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY) &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITIONS) {
    render_result = render_storage_partitions(
        payload, header.payload_length, json, output, output_capacity, &offset,
        request_id);
  } else if (options.operation >=
                 XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE &&
             options.operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_PLAN) {
    render_result = render_storage_partition_plan(
        payload, header.payload_length, json, output, output_capacity, &offset,
        request_id);
  } else if (options.operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
             options.operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT) {
    render_result = render_storage_volume_report(
        payload, header.payload_length, json, output, output_capacity, &offset,
        request_id);
  } else if (options.operation ==
                 XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT) {
    render_result = render_storage_volume_report(
        payload, header.payload_length, json, output, output_capacity, &offset,
        request_id);
  } else if (options.operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
             options.operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_SCRUB_REPORT &&
             header.payload_length ==
                 sizeof(xaios_control_storage_scrub_report_user_t)) {
    render_result = render_storage_scrub(payload, json, output,
                                         output_capacity, &offset, request_id);
  } else if (options.operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
             options.operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REPORT &&
             header.payload_length ==
                 sizeof(xaios_control_storage_trim_report_user_t)) {
    render_result = render_storage_trim(payload, json, output, output_capacity,
                                        &offset, request_id);
  }
  if (render_result != 0) {
    offset = 0ULL;
    output[0] = '\0';
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "invalid_response",
                       "The typed response did not match the operation.");
    *output_size = offset;
    return -1;
  }
  *output_size = offset;
  if (options.operation == XAIOS_CONTROL_OP_HEALTH) {
    xaios_control_health_payload_user_t health;
    bytes_copy(&health, payload, sizeof(health));
    return health.overall_state == XAIOS_CONTROL_STATE_READY ? 0 : 1;
  }
  if (options.operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
      options.operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
    xaios_control_storage_scrub_report_user_t scrub;
    bytes_copy(&scrub, payload, sizeof(scrub));
    return scrub.state == XAIOS_MODEL_MAINTENANCE_FAILED ? 1 : 0;
  }
  if (options.operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
      options.operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
    xaios_control_storage_trim_report_user_t trim;
    bytes_copy(&trim, payload, sizeof(trim));
    return trim.state == XAIOS_MODEL_MAINTENANCE_FAILED ? 1 : 0;
  }
  return 0;
}

int xaios_control_run(const char *command, char *output, u64 output_capacity,
                      u64 *output_size) {
  return xaios_control_run_as(command, XAIOS_CONTROL_ROLE_OBSERVER,
                              "local-observer", output, output_capacity,
                              output_size);
}
