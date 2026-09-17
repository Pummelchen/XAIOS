/*
 * The control client's reply dispatcher, from control_dispatch.c: given a
 * validated response it picks the renderer for the operation and payload
 * type. xaios_control_run_as in xaios_control_client.c calls it once, after
 * the status and framing checks.
 */

#ifndef XAIOS_USERSPACE_LIB_CONTROL_DISPATCH_INTERNAL_H
#define XAIOS_USERSPACE_LIB_CONTROL_DISPATCH_INTERNAL_H

#include <xaios_control_client.h>

#include "control_request_internal.h"

int control_dispatch_response(
    const xaios_control_options_t *options,
    const xaios_control_response_header_user_t *header, const void *payload,
    int json, char *output, u64 output_capacity, u64 *offset, u64 request_id);

#endif /* XAIOS_USERSPACE_LIB_CONTROL_DISPATCH_INTERNAL_H */
