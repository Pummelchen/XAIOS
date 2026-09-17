/*
 * Declarations shared by the control client's option parser and the two
 * translation units its halves moved to.
 *
 * parse_options itself stays in xaios_control_client.c beside the command
 * verbs it dispatches on, and the parser's positional-operand handling there
 * still spells the storage install verb and its "from" keyword. The option
 * loop moved to control_parse_flags.c and the cross-option validation to
 * control_parse_validate.c, so the seen-bits the two halves share, and the
 * two entry points themselves, are named here. The confirmation spellings
 * are matched by a predicate defined beside parse_options, in the parent, so
 * that the flag the boot-media gate reads for stays in that file.
 */

#ifndef XAIOS_USERSPACE_LIB_CONTROL_PARSE_INTERNAL_H
#define XAIOS_USERSPACE_LIB_CONTROL_PARSE_INTERNAL_H

#include <xaios_control_client.h>

#include "control_request_internal.h"

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

/* Consume every option after the operands parse_options has already taken. */
int control_parse_options_flags(const char *command, u64 *index,
                                xaios_control_options_t *options,
                                u32 *seen_out, const char **error_code,
                                const char **error_message);

/* Reject the combinations the option loop alone cannot see. */
int control_validate_options(u32 seen, xaios_control_options_t *options,
                             const char **error_code,
                             const char **error_message);

/*
 * Whether a token is one of the confirmation spellings. Defined in
 * xaios_control_client.c, which keeps "--confirm-device" where the
 * boot-media gate can read it, and called by the option loop.
 */
int control_confirmation_option_matches(const char *token);

#endif /* XAIOS_USERSPACE_LIB_CONTROL_PARSE_INTERNAL_H */
