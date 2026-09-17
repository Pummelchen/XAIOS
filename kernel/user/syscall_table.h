/*
 * The syscall table and the small pure helpers the dispatcher shares with it.
 *
 * Split out of syscall.c. The table owns only its own array -- the row type,
 * the entries, the linear lookup, the capability helper for control-plane
 * operations, and the string and formatting helpers that read nothing but
 * their arguments. `syscall_dispatch` and the kernel socket table stay behind.
 */

#ifndef XAIOS_KERNEL_USER_SYSCALL_TABLE_H
#define XAIOS_KERNEL_USER_SYSCALL_TABLE_H

#include <xaios/status.h>
#include <xaios/syscall.h>

typedef struct xaios_syscall_entry {
  uint64_t number;
  const char *name;
  uint64_t required_capability;
} xaios_syscall_entry_t;

const xaios_syscall_entry_t *syscall_table_lookup(uint64_t number);
uint64_t syscall_table_entry_count(void);
xaios_status_t syscall_table_copy_user_string(uint64_t user_ptr, uint64_t length,
                                              char *buffer,
                                              uint64_t buffer_size);
uint64_t syscall_table_control_operation_capability(uint16_t operation);
void syscall_table_format_u64_decimal(uint64_t value, char output[21]);
int syscall_table_command_starts_with(const char *command, const char *name);
int syscall_table_path_equal(const char *left, const char *right);

#endif /* XAIOS_KERNEL_USER_SYSCALL_TABLE_H */
