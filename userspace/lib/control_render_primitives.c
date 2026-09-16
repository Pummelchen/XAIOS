/*
 * The control client's formatting and parsing primitives.
 * See xaios_control_internal.h.
 */

#include "xaios_control_internal.h"

void bytes_copy(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  for (u64 i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

int string_equal(const char *lhs, const char *rhs) {
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

int string_copy(char *destination, u64 capacity, const char *source) {
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

int append_char(char *output, u64 capacity, u64 *offset, char value) {
  if (output == 0 || offset == 0 || *offset + 1ULL >= capacity) {
    return -1;
  }
  output[*offset] = value;
  ++(*offset);
  output[*offset] = '\0';
  return 0;
}

int append_text(char *output, u64 capacity, u64 *offset,
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

int append_u64(char *output, u64 capacity, u64 *offset, u64 value) {
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

int append_hex(char *output, u64 capacity, u64 *offset,
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

int append_json_string(char *output, u64 capacity, u64 *offset,
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

int next_token(const char *text, u64 *index, char *token,
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

int parse_u64(const char *text, u64 *value, u64 *digits) {
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

int parse_hex_exact(const char *text, unsigned char *output,
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

int parse_duration_ms(const char *text, u64 *value) {
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

int parse_storage_size(const char *text, u64 *value) {
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

int parse_storage_range(char *text, u64 *offset, u64 *length) {
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

u32 parse_partition_type(const char *name) {
  if (string_equal(name, "state") || string_equal(name, "statefs")) {
    return XAIOS_STORAGE_PARTITION_STATE;
  }
  if (string_equal(name, "model") || string_equal(name, "modelfs")) {
    return XAIOS_STORAGE_PARTITION_MODEL;
  }
  if (string_equal(name, "recovery")) {
    return XAIOS_STORAGE_PARTITION_RECOVERY;
  }
  if (string_equal(name, "esp") || string_equal(name, "efi")) {
    return XAIOS_STORAGE_PARTITION_ESP;
  }
  return 0U;
}

int command_mentions_json(const char *command) {
  u64 index = 0ULL;
  char token[128];
  while (next_token(command, &index, token, sizeof(token)) == 0) {
    if (string_equal(token, "--json")) {
      return 1;
    }
  }
  return 0;
}

u16 parse_simple_operation(const char *name) {
  if (string_equal(name, "version")) return XAIOS_CONTROL_OP_VERSION;
  if (string_equal(name, "status")) return XAIOS_CONTROL_OP_STATUS;
  if (string_equal(name, "health")) return XAIOS_CONTROL_OP_HEALTH;
  if (string_equal(name, "capabilities")) return XAIOS_CONTROL_OP_CAPABILITIES;
  if (string_equal(name, "hardware")) return XAIOS_CONTROL_OP_HARDWARE;
  if (string_equal(name, "metrics")) return XAIOS_CONTROL_OP_METRICS;
  if (string_equal(name, "logs")) return XAIOS_CONTROL_OP_LOGS;
  return 0U;
}

const char *role_name(u32 role) {
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

u32 parse_role(const char *name) {
  if (string_equal(name, "observer")) return XAIOS_CONTROL_ROLE_OBSERVER;
  if (string_equal(name, "operator")) return XAIOS_CONTROL_ROLE_OPERATOR;
  if (string_equal(name, "administrator") || string_equal(name, "admin")) {
    return XAIOS_CONTROL_ROLE_ADMIN;
  }
  return XAIOS_CONTROL_ROLE_NONE;
}

const char *state_name(u32 state) {
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

const char *status_code(u32 status) {
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

const char *status_message(u32 status) {
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

int render_error(char *output, u64 capacity, u64 *offset, u64 request_id,
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

int json_field_prefix(char *output, u64 capacity, u64 *offset,
                             int *first, const char *key) {
  if (*first == 0 && append_char(output, capacity, offset, ',') != 0) {
    return -1;
  }
  *first = 0;
  return append_json_string(output, capacity, offset, key, xaios_strlen(key)) ||
         append_char(output, capacity, offset, ':');
}

int json_field_u64(char *output, u64 capacity, u64 *offset, int *first,
                          const char *key, u64 value) {
  if (json_field_prefix(output, capacity, offset, first, key) != 0) {
    return -1;
  }
  if (value == XAIOS_CONTROL_UNKNOWN_U64) {
    return append_text(output, capacity, offset, "null");
  }
  return append_u64(output, capacity, offset, value);
}

int json_field_state(char *output, u64 capacity, u64 *offset,
                            int *first, const char *key, u32 state) {
  const char *name = state_name(state);
  return json_field_prefix(output, capacity, offset, first, key) ||
         append_json_string(output, capacity, offset, name, xaios_strlen(name));
}

int json_field_string(char *output, u64 capacity, u64 *offset,
                             int *first, const char *key, const char *value) {
  return json_field_prefix(output, capacity, offset, first, key) ||
         append_json_string(output, capacity, offset, value,
                            xaios_strlen(value));
}

int human_field_u64(char *output, u64 capacity, u64 *offset,
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

int human_field_state(char *output, u64 capacity, u64 *offset,
                             const char *key, u32 state) {
  return append_text(output, capacity, offset, key) ||
         append_char(output, capacity, offset, '=') ||
         append_text(output, capacity, offset, state_name(state)) ||
         append_char(output, capacity, offset, '\n');
}

int json_envelope_begin(char *output, u64 capacity, u64 *offset,
                               u64 request_id) {
  return append_text(output, capacity, offset,
                     "{\"schema_version\":1,\"request_id\":\"") ||
         append_u64(output, capacity, offset, request_id) ||
         append_text(output, capacity, offset,
                     "\",\"status\":\"ok\",\"data\":{");
}

int json_envelope_end(char *output, u64 capacity, u64 *offset) {
  return append_text(output, capacity, offset, "}}\n");
}
