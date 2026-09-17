/*
 * Declarations for control_render_config.c: the control client's
 * configuration, authorised-key and audit renderers. The reply dispatcher
 * in xaios_control_client.c calls them; the formatting primitives they use
 * are declared in xaios_control_internal.h.
 */

#ifndef XAIOS_USERSPACE_LIB_CONTROL_RENDER_CONFIG_INTERNAL_H
#define XAIOS_USERSPACE_LIB_CONTROL_RENDER_CONFIG_INTERNAL_H

#include <xaios_control_client.h>

int cfg_render_config(const void *payload, int json, char *output,
                      u64 capacity, u64 *offset, u64 request_id);
int cfg_render_auth_keys(const void *payload, u64 payload_length, int json,
                         char *output, u64 capacity, u64 *offset,
                         u64 request_id);
int cfg_render_audit(const void *payload, u64 payload_length, int json,
                     char *output, u64 capacity, u64 *offset,
                     u64 request_id);

#endif /* XAIOS_USERSPACE_LIB_CONTROL_RENDER_CONFIG_INTERNAL_H */
