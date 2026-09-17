#include <xaios_control_client.h>

#include "xaios_control_internal.h"
#include "control_render_config_internal.h"
#include "control_request_internal.h"

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
        *error_message = "xaiFS v1 requires a 4096-byte block size.";
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
                 options->operation == XAIOS_CONTROL_OP_STORAGE_INSTALL ||
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
  if (options->operation == XAIOS_CONTROL_OP_STORAGE_INSTALL) {
    /* Same bar as any other operation that destroys a disk: a named actor and
       the disk's own GUID, or it does not go. */
    /* The confirmation and the operation id come from the command line, so
       this is where they are checked. The actor does not: it is the identity
       of whoever is calling, which xaios_control_run_as sets *after* parsing
       and refuses to leave empty. Requiring it here made the check impossible
       to satisfy -- options.principal is always empty at this point -- so
       every install through this client was rejected for want of a principal
       it was carrying. Nothing caught it because the install the gates
       exercise is the kernel's own, which does not come through here. */
    if (options->confirmation[0] == '\0' || options->operation_id == 0ULL) {
      *error_code = "invalid_install";
      *error_message =
          "Install requires --confirm-device with the target disk GUID and "
          "--operation-id.";
      return -1;
    }
  }
  /* Install is a storage command like the rest, and takes a confirmation like
     the rest. It was in none of the categories this guard recognises, so the
     confirmation it requires was itself rejected as an option without a
     command to belong to -- an install could satisfy neither the check that
     demanded the flag nor the one that refused it. */
  int install_command =
      options->operation == XAIOS_CONTROL_OP_STORAGE_INSTALL;
  if (partition_command == 0 && volume_command == 0 && replica_repair == 0 &&
      model_register == 0 && install_command == 0 &&
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
    *error_message = "xaiFS format requires --type modelfs, --label, --block-size 4096, and --checksum-data.";
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
      options->operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA ||
      /* Install writes a partition table and formats what it creates, so it
         is a mutation and takes the same confirmation as one. Leaving it out
         made the confirmation it separately required into an option that
         "applies only to mutations" -- the third of three checks an install
         could not satisfy at once. */
      options->operation == XAIOS_CONTROL_OP_STORAGE_INSTALL;
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
    render_result = cfg_render_config(payload, json, output, output_capacity,
                                  &offset, request_id);
  } else if ((options.operation == XAIOS_CONTROL_OP_AUTH_KEY_LIST ||
              options.operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
              options.operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE) &&
             header.payload_type == XAIOS_CONTROL_PAYLOAD_AUTH_KEYS) {
    render_result = cfg_render_auth_keys(payload, header.payload_length, json,
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
    render_result = cfg_render_audit(payload, header.payload_length, json, output,
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
  } else if (options.operation == XAIOS_CONTROL_OP_STORAGE_INSTALL &&
             header.payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_INSTALL_RESULT) {
    render_result = render_storage_install(payload, header.payload_length,
                                           json, output, output_capacity,
                                           &offset, request_id);
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
