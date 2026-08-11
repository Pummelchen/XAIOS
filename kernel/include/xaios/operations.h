#ifndef XAIOS_OPERATIONS_H
#define XAIOS_OPERATIONS_H

#include <xaios/status.h>
#include <xaios/types.h>

void operations_init(uint32_t persistent_available);
void operations_mark_boot_ready(void);
void operations_tick(void);
uint32_t operations_rescue_mode(void);
uint32_t operations_is_command(const char *command);
uint32_t operations_command_allowed_in_rescue(const char *command);
xaios_status_t operations_execute(const char *command, char *output,
                                  uint64_t capacity, uint64_t *output_bytes);
void operations_self_test(void);

#endif
