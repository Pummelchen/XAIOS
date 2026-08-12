#ifndef XAIOS_USER_H
#define XAIOS_USER_H

#include <xaios/elf_loader.h>
#include <xaios/initramfs.h>
#include <xaios/status.h>
#include <xaios/syscall.h>
#include <xaios/types.h>

#define XAIOS_MAX_USER_PROCESSES 1024U
#define XAIOS_USER_ARG_MAX 16U
#define XAIOS_USER_ARG_BYTES_MAX 1024U
#define XAIOS_USER_EXIT_RETURN_MAGIC UINT64_C(0x4f53414900000000)
#define XAIOS_USER_EXIT_RETURN_MASK UINT64_C(0xffffffff00000000)
#define XAIOS_USER_FAULT_EXIT_CODE 128

typedef enum xaios_user_process_state {
  XAIOS_USER_PROCESS_EMPTY = 0,
  XAIOS_USER_PROCESS_LOADED = 1,
  XAIOS_USER_PROCESS_RUNNABLE = 2,
  XAIOS_USER_PROCESS_RUNNING = 3,
  XAIOS_USER_PROCESS_WAITING = 4,
  XAIOS_USER_PROCESS_EXITED = 5,
  XAIOS_USER_PROCESS_FAILED = 6,
} xaios_user_process_state_t;

typedef struct xaios_user_process {
  uint32_t pid;
  uint32_t parent_pid;
  const char *name;
  xaios_user_process_state_t state;
  int exit_code;
  uint64_t capability_mask;
  uint64_t syscall_count;
  uint64_t rejected_syscall_count;
  uint64_t entry;
  uint64_t stack_top;
  uint64_t argv_user;
  uint32_t argc;
  uint32_t reserved_args;
  uint64_t stack_guard_low;
  uint64_t stack_guard_high;
  uint64_t mapped_low;
  uint64_t mapped_high;
  uint64_t scheduler_ticks;
  uint64_t started_ns;
  uint64_t runtime_ns;
  uint64_t running_since_ns;
  uint64_t resident_pages;
  uint32_t running_cpu_id;
  uint32_t runtime_sequence;
  xaios_process_aspace_t aspace;
} xaios_user_process_t;

typedef struct xaios_cpu_usage_snapshot {
  uint32_t cpu_id;
  uint32_t active_pid;
  uint64_t busy_ns;
  uint64_t elapsed_ns;
} xaios_cpu_usage_snapshot_t;

void user_process_table_init(void);
void user_process_lifecycle_self_test(void);
void user_scheduler_self_test(void);
const xaios_user_process_t *user_current_process(void);
xaios_status_t user_bind_current_process(uint32_t pid);
void user_clear_current_process(void);
xaios_status_t user_process_has_capability(uint64_t capability);
void user_process_note_syscall(uint32_t rejected);
uint64_t user_process_note_exit(int exit_code);
uint64_t user_process_note_fault(void);
xaios_status_t user_load_init(const xaios_initramfs_file_t *file,
                             xaios_user_process_t *process);
xaios_status_t user_load_process(const xaios_initramfs_file_t *file,
                                uint32_t pid, uint64_t capability_mask,
                                xaios_user_process_t *process);
xaios_status_t user_process_set_arguments(xaios_user_process_t *process,
                                          uint32_t argc,
                                          const char *const argv[]);
xaios_status_t user_process_snapshot(uint32_t pid, xaios_user_process_t *process);
xaios_status_t user_process_snapshot_at(uint32_t pid, uint64_t now_ns,
                                        xaios_user_process_t *process);
void user_process_runtime_start(uint32_t pid, uint32_t cpu_id, uint64_t now_ns);
void user_process_runtime_stop(uint32_t pid, uint32_t cpu_id, uint64_t now_ns);
void user_thread_runtime_start(uint32_t pid, uint32_t cpu_id,
                               uint64_t now_ns);
void user_thread_runtime_stop(uint32_t pid, uint32_t cpu_id,
                              uint64_t started_ns, uint64_t now_ns);
uint32_t user_cpu_usage_count(void);
xaios_status_t user_cpu_usage_snapshot(uint32_t ordinal, uint64_t now_ns,
                                       xaios_cpu_usage_snapshot_t *snapshot);
uint64_t user_cpu_busy_total(uint64_t now_ns);
void user_process_idle_until(uint64_t deadline_ns);
xaios_status_t user_process_make_runnable(uint32_t pid, uint32_t parent_pid);
xaios_status_t user_process_wait(uint32_t pid);
xaios_status_t user_process_wake(uint32_t pid);
int user_process_run(const xaios_user_process_t *process);
int user_process_run_concurrent(const xaios_user_process_t *process);
xaios_status_t user_process_run_transient(
    const xaios_initramfs_file_t *file, uint64_t capability_mask,
    int *exit_code);
xaios_status_t user_process_run_transient_args(
    const xaios_initramfs_file_t *file, uint64_t capability_mask,
    uint32_t argc, const char *const argv[], int *exit_code);
void user_process_reclaim_address_space(const xaios_user_process_t *process);
xaios_status_t user_process_reap(uint32_t pid);
xaios_status_t user_process_terminate(uint32_t pid, int exit_code);
void user_switch_address_space(uint32_t pid);
uint64_t user_process_transition_count(void);
uint64_t user_process_loaded_count(void);
uint64_t user_process_runnable_count(void);
uint64_t user_process_running_count(void);
uint64_t user_process_waiting_count(void);
uint64_t user_process_exited_count(void);
uint64_t user_process_failed_count(void);
uint64_t user_process_current_failed_count(void);
uint64_t user_process_reclaim_count(void);
uint64_t user_process_scheduled_count(void);
uint64_t user_process_wait_count(void);
uint64_t user_process_wake_count(void);
uint64_t user_process_active_count(void);

#endif
