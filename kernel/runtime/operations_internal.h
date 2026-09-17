#ifndef XAIOS_KERNEL_RUNTIME_OPERATIONS_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_OPERATIONS_INTERNAL_H

#include <xaios/ip_addr.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define OPERATIONS_RECORD_PATH "/state/lifecycle/record"
#define OPERATIONS_RESCUE_PATH "/state/lifecycle/rescue"

/* Which power transition the shell asked the boot path to perform. */
typedef enum operations_power_action {
  OPERATIONS_POWER_NONE = 0,
  OPERATIONS_POWER_OFF = 1,
  OPERATIONS_POWER_REBOOT = 2,
} operations_power_action_t;

/* Lifecycle state owned by operations.c and read by the command path.
   Each object below is defined exactly once, in operations.c. */
extern uint32_t ops_state_persistent;
extern uint32_t ops_state_boot_ready;
extern uint32_t ops_state_rescue;
extern uint32_t ops_state_unclean_boots;
extern uint64_t ops_state_boots;
extern operations_power_action_t ops_state_power_action;

/* Schedule a power transition once storage has been quiesced (operations.c). */
void ops_request_power(operations_power_action_t action);

/* Text and number helpers, defined once in operations_format.c. */
uint64_t ops_str_len(const char *value);
uint32_t ops_str_equal(const char *left, const char *right);
uint32_t ops_str_starts(const char *value, const char *prefix);
const char *ops_skip_spaces(const char *value);
uint32_t ops_next_token(const char **cursor, char *token, uint64_t capacity);
void ops_append(char *output, uint64_t capacity, uint64_t *used,
                const char *value);
void ops_append_u64(char *output, uint64_t capacity, uint64_t *used,
                    uint64_t value);
void ops_append_status(char *output, uint64_t capacity, uint64_t *used,
                       xaios_status_t status);
void ops_append_ipv4(char *output, uint64_t capacity, uint64_t *used,
                     uint32_t ip);
void ops_append_hex16(char *output, uint64_t capacity, uint64_t *used,
                      uint16_t value);
void ops_append_ipv6(char *output, uint64_t capacity, uint64_t *used,
                     const xaios_ip_addr_t *address);
xaios_status_t ops_parse_u64(const char *text, uint64_t *value);
xaios_status_t ops_parse_ipv4(const char *text, uint32_t *ip);
uint64_t ops_find_decimal(const char *text, const char *key);

/* Resource-pressure verdict shared by the limits/support output and the
   boot-path self-test; defined in operations_commands.c. */
const char *ops_pressure_name(uint64_t free_pages, uint64_t total_pages,
                              uint64_t active_processes);

#endif
