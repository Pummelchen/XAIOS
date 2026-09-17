#include <xaios_control_client.h>

#include "xaios_control_internal.h"
#include "control_render_config_internal.h"
#include "control_request_internal.h"
#include "control_dispatch_internal.h"
#include "control_parse_internal.h"

static u64 g_next_request_id = 1ULL;

int fixed_string_valid(const char *text, u64 capacity) {
  if (text == 0 || capacity == 0ULL || text[capacity - 1ULL] != '\0') {
    return 0;
  }
  for (u64 i = 0ULL; i < capacity; ++i) {
    if (text[i] == '\0') return i != 0ULL;
  }
  return 0;
}

int fixed_string_terminated(const char *text, u64 capacity) {
  if (text == 0 || capacity == 0ULL || text[capacity - 1ULL] != '\0') {
    return 0;
  }
  for (u64 index = 0ULL; index < capacity; ++index) {
    if (text[index] == '\0') return 1;
  }
  return 0;
}

int append_quoted_hex(char *output, u64 capacity, u64 *offset,
                             const unsigned char *bytes, u64 size) {
  return append_char(output, capacity, offset, '"') ||
         append_hex(output, capacity, offset, bytes, size) ||
         append_char(output, capacity, offset, '"');
}

/*
 * The confirmation spellings parse_options accepts. They are matched here,
 * beside the parser's command verbs, rather than in the option loop that
 * moved to control_parse_flags.c: the boot-media gate reads this file for
 * the literal "--confirm-device" the READMEs tell operators to type.
 */
int control_confirmation_option_matches(const char *token) {
  return string_equal(token, "--confirm-device") ||
         string_equal(token, "--confirm-partition");
}

static int parse_options(const char *command, xaios_control_options_t *options,
                         const char **error_code, const char **error_message) {
  u64 index = 0ULL;
  char token[160];
  u32 seen = 0U;
  int needs_argument = 0;
  int needs_mount_path = 0;
  int needs_replica = 0;
  int needs_install_source = 0;
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
    } else if (string_equal(token, "install")) {
      options->operation = XAIOS_CONTROL_OP_STORAGE_INSTALL;
      needs_argument = 1;
      needs_install_source = 1;
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
  if (needs_install_source != 0) {
    /* "storage install <disk> from <esp>". The word is required rather than
       positional-only so that a command that destroys a disk reads as a
       sentence at the point it is typed. */
    if (next_token(command, &index, token, sizeof(token)) != 0 ||
        !string_equal(token, "from") ||
        next_token(command, &index, token, sizeof(token)) != 0 ||
        token[0] == '-' ||
        string_copy(options->install_source, sizeof(options->install_source),
                    token) != 0) {
      *error_code = "invalid_install";
      *error_message =
          "Install requires a target disk and \"from\" a source EFI partition.";
      return -1;
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
  if (control_parse_options_flags(command, &index, options, &seen, error_code,
                                  error_message) != 0) {
    return -1;
  }
  return control_validate_options(seen, options, error_code, error_message);

usage:
  *error_code = "invalid_argument";
  *error_message = "The xaiosctl command is incomplete.";
  return -1;
unknown:
  *error_code = "unknown_operation";
  *error_message = "Unknown xaiosctl command.";
  return -1;
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
  if (req_query_once(&options, request_id, response, &response_size) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "transport_error", "The control syscall failed.");
    *output_size = offset;
    return -1;
  }
  if (options.operation == XAIOS_CONTROL_OP_LOGS && options.follow != 0U &&
      req_follow_logs(&options, request_id, response, &response_size) != 0) {
    (void)render_error(output, output_capacity, &offset, request_id, json,
                       "transport_error", "Log follow failed.");
    *output_size = offset;
    return -1;
  }
  if (req_validate_response(response, response_size, request_id,
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
  render_result = control_dispatch_response(
      &options, &header, payload, json, output, output_capacity, &offset,
      request_id);
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
