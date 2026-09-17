/*
 * The control client's administrative renderers: the configuration
 * record, the authorised-key list and the audit trail. They were the
 * last renderers in xaios_control_client.c and each turns one decoded
 * reply payload into the text or JSON a caller prints.
 *
 * fixed_string_valid, fixed_string_terminated and append_quoted_hex
 * stay in xaios_control_client.c, where the storage and operation
 * renderers also call them.
 */

#include "control_render_config_internal.h"

#include "xaios_control_internal.h"

static const char *password_auth_name(u32 mode) {
  return mode == XAIOS_ADMIN_PASSWORD_DEVELOPMENT ? "development"
                                                   : "disabled";
}

int cfg_render_config(const void *payload, int json, char *output,
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

int cfg_render_auth_keys(const void *payload, u64 payload_length, int json,
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

int cfg_render_audit(const void *payload, u64 payload_length, int json,
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
