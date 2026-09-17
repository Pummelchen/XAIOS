/*
 * Declarations shared between the control client's translation units.
 *
 * The primitives -- bounded string and JSON formatting, the tokenizer and the
 * field parsers -- were the first 490 lines of xaios_control_client.c and own
 * no state of their own, so they moved to control_render_primitives.c and are
 * declared here rather than in the public header, which is for callers outside
 * this directory.
 */

#ifndef XAIOS_USERSPACE_LIB_CONTROL_INTERNAL_H
#define XAIOS_USERSPACE_LIB_CONTROL_INTERNAL_H

#include <xaios_control_client.h>

void bytes_copy(void *dst, const void *src, u64 size);
int string_equal(const char *lhs, const char *rhs);
int string_copy(char *destination, u64 capacity, const char *source);
int append_char(char *output, u64 capacity, u64 *offset, char value);
int append_text(char *output, u64 capacity, u64 *offset, const char *text);
int append_u64(char *output, u64 capacity, u64 *offset, u64 value);
int append_hex(char *output, u64 capacity, u64 *offset, const unsigned char *bytes, u64 size);
int append_json_string(char *output, u64 capacity, u64 *offset, const char *text, u64 text_size);
int next_token(const char *text, u64 *index, char *token, u64 capacity);
int parse_u64(const char *text, u64 *value, u64 *digits);
int parse_hex_exact(const char *text, unsigned char *output, u64 output_size);
int parse_duration_ms(const char *text, u64 *value);
int parse_storage_size(const char *text, u64 *value);
int parse_storage_range(char *text, u64 *offset, u64 *length);
u32 parse_partition_type(const char *name);
int command_mentions_json(const char *command);
u16 parse_simple_operation(const char *name);
const char *role_name(u32 role);
u32 parse_role(const char *name);
const char *state_name(u32 state);
const char *status_code(u32 status);
const char *status_message(u32 status);
int render_error(char *output, u64 capacity, u64 *offset, u64 request_id, int json, const char *code, const char *message);
int json_field_prefix(char *output, u64 capacity, u64 *offset, int *first, const char *key);
int json_field_u64(char *output, u64 capacity, u64 *offset, int *first, const char *key, u64 value);
int json_field_state(char *output, u64 capacity, u64 *offset, int *first, const char *key, u32 state);
int json_field_string(char *output, u64 capacity, u64 *offset, int *first, const char *key, const char *value);
int human_field_u64(char *output, u64 capacity, u64 *offset, const char *key, u64 value);
int human_field_state(char *output, u64 capacity, u64 *offset, const char *key, u32 state);
int json_envelope_begin(char *output, u64 capacity, u64 *offset, u64 request_id);
int json_envelope_end(char *output, u64 capacity, u64 *offset);

/*
 * The system and status renderers, from control_render_system.c. They were the
 * second group to leave xaios_control_client.c and are called by its reply
 * dispatcher; "status" here is the observability family, with configuration,
 * auth keys and storage left behind for later rounds.
 */
int render_version(const void *payload, int json, char *output, u64 capacity,
                   u64 *offset, u64 request_id);
int render_status(const void *payload, int json, char *output, u64 capacity,
                  u64 *offset, u64 request_id);
int render_health(const void *payload, int json, char *output, u64 capacity,
                  u64 *offset, u64 request_id);
int render_capabilities(const void *payload, int json, char *output,
                        u64 capacity, u64 *offset, u64 request_id);
int render_hardware(const void *payload, int json, char *output, u64 capacity,
                    u64 *offset, u64 request_id);
int render_metrics(const void *payload, int json, char *output, u64 capacity,
                   u64 *offset, u64 request_id);
int render_logs(const void *payload, u64 payload_length, int json, char *output,
                u64 capacity, u64 *offset, u64 request_id);

#endif /* XAIOS_USERSPACE_LIB_CONTROL_INTERNAL_H */
