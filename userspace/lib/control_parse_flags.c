/*
 * The control client's option loop, split out of xaios_control_client.c.
 *
 * parse_options consumes the command verb and its positional operands and
 * then calls this to walk the remaining "--flag value" pairs, recording
 * which were seen. The cross-option validation that follows is in
 * control_parse_validate.c; both halves share the SEEN_ enumerators from
 * control_parse_internal.h.
 */

#include "control_parse_internal.h"
#include "xaios_control_internal.h"

int control_parse_options_flags(const char *command, u64 *index,
                                xaios_control_options_t *options,
                                u32 *seen_out, const char **error_code,
                                const char **error_message) {
  char token[160];
  char value[160];
  u32 seen = 0U;
  while (next_token(command, index, token, sizeof(token)) == 0) {
    if (string_equal(token, "--json")) {
      if ((seen & SEEN_JSON) != 0U) goto duplicate;
      seen |= SEEN_JSON;
      options->json = 1U;
    } else if (string_equal(token, "--timeout")) {
      if ((seen & SEEN_TIMEOUT) != 0U) goto duplicate;
      seen |= SEEN_TIMEOUT;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0) {
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_u64(value, &options->operation_id, &digits) != 0 ||
          value[digits] != '\0' || options->operation_id == 0ULL) {
        *error_code = "invalid_operation_id";
        *error_message = "Operation ID must be a nonzero unsigned integer.";
        return -1;
      }
    } else if (string_equal(token, "--principal")) {
      if ((seen & SEEN_PRINCIPAL) != 0U) goto duplicate;
      seen |= SEEN_PRINCIPAL;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          string_copy(options->target_principal,
                      sizeof(options->target_principal), value) != 0) {
        *error_code = "invalid_principal";
        *error_message = "Principal is missing or too long.";
        return -1;
      }
    } else if (string_equal(token, "--role")) {
      if ((seen & SEEN_ROLE) != 0U) goto duplicate;
      seen |= SEEN_ROLE;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          (options->assigned_role = parse_role(value)) ==
              XAIOS_CONTROL_ROLE_NONE) {
        *error_code = "invalid_role";
        *error_message = "Role must be observer, operator, or administrator.";
        return -1;
      }
    } else if (string_equal(token, "--type")) {
      if ((seen & SEEN_STORAGE_TYPE) != 0U) goto duplicate;
      seen |= SEEN_STORAGE_TYPE;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_storage_size(value, &options->size_bytes) != 0) {
        *error_code = "invalid_storage_size";
        *error_message = "Size must be max or a checked byte/KiB/MiB/GiB/TiB value.";
        return -1;
      }
    } else if (string_equal(token, "--chunk-size")) {
      if ((seen & SEEN_CHUNK_SIZE) != 0U) goto duplicate;
      seen |= SEEN_CHUNK_SIZE;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_storage_size(value, &options->chunk_size) != 0 ||
          options->chunk_size == 0ULL) {
        *error_code = "invalid_chunk_size";
        *error_message = "Chunk size must be a checked byte/KiB/MiB value.";
        return -1;
      }
    } else if (string_equal(token, "--block-size")) {
      if ((seen & SEEN_BLOCK_SIZE) != 0U) goto duplicate;
      seen |= SEEN_BLOCK_SIZE;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->model_uuid,
                          sizeof(options->model_uuid)) != 0) {
        *error_code = "invalid_model_uuid";
        *error_message = "Model UUID must contain exactly 32 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--signer-key")) {
      if ((seen & SEEN_SIGNER_KEY) != 0U) goto duplicate;
      seen |= SEEN_SIGNER_KEY;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->signer_public_key,
                          sizeof(options->signer_public_key)) != 0) {
        *error_code = "invalid_signer_key";
        *error_message = "Signer key must contain exactly 64 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--signature")) {
      if ((seen & SEEN_SIGNATURE) != 0U) goto duplicate;
      seen |= SEEN_SIGNATURE;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->signature,
                          sizeof(options->signature)) != 0) {
        *error_code = "invalid_signature";
        *error_message = "Signature must contain exactly 128 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--source-revision")) {
      if ((seen & SEEN_SOURCE_REVISION) != 0U) goto duplicate;
      seen |= SEEN_SOURCE_REVISION;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          parse_hex_exact(value, options->source_revision,
                          sizeof(options->source_revision)) != 0) {
        *error_code = "invalid_source_revision";
        *error_message = "Source revision must contain exactly 64 hexadecimal characters.";
        return -1;
      }
    } else if (string_equal(token, "--architecture")) {
      if ((seen & SEEN_ARCHITECTURE) != 0U) goto duplicate;
      seen |= SEEN_ARCHITECTURE;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          string_copy(options->architecture_id,
                      sizeof(options->architecture_id), value) != 0) {
        *error_code = "invalid_architecture";
        *error_message = "Architecture ID is missing or exceeds 32 bytes.";
        return -1;
      }
    } else if (string_equal(token, "--target")) {
      if ((seen & SEEN_TARGET) != 0U) goto duplicate;
      seen |= SEEN_TARGET;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
          string_copy(options->storage_name, sizeof(options->storage_name),
                      value) != 0) {
        *error_code = "invalid_partition_name";
        *error_message = "Partition name is missing or too long.";
        return -1;
      }
    } else if (control_confirmation_option_matches(token)) {
      if ((seen & SEEN_CONFIRMATION) != 0U) goto duplicate;
      seen |= SEEN_CONFIRMATION;
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
      if (next_token(command, index, value, sizeof(value)) != 0 ||
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
  *seen_out = seen;
  return 0;
duplicate:
  *error_code = "duplicate_option";
  *error_message = "An xaiosctl option was specified more than once.";
  return -1;
}
