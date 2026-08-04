#ifndef XAIOS_USERSPACE_CONTROL_CLIENT_H
#define XAIOS_USERSPACE_CONTROL_CLIENT_H

#include <xaios_user.h>

int xaios_control_is_command(const char *command);
int xaios_control_run(const char *command, char *output, u64 output_capacity,
                      u64 *output_size);
int xaios_control_run_as(const char *command, u32 principal_role,
                         const char *principal, char *output,
                         u64 output_capacity, u64 *output_size);

#endif
