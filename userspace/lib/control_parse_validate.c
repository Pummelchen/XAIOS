/*
 * The control client's cross-option validation, split out of
 * xaios_control_client.c.
 *
 * The option loop in control_parse_flags.c records which options were seen;
 * this rejects the combinations that are only wrong together -- a storage
 * option without a storage command, a mutation without a confirmation, a
 * dry run of something that cannot be planned -- and rewrites the operation
 * when a plan is what was asked for. parse_options calls it once, after the
 * loop, so the order of checks is unchanged.
 */

#include "control_parse_internal.h"
#include "xaios_control_internal.h"

int control_validate_options(u32 seen, xaios_control_options_t *options,
                             const char **error_code,
                             const char **error_message) {
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
}
