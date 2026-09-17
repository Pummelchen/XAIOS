#ifndef XAIOS_APPS_XTOP_SNAPSHOT_H
#define XAIOS_APPS_XTOP_SNAPSHOT_H

/*
 * Private interface shared by xtop.c, xtop_snapshot.c and xtop_report.c.
 *
 * xtop_snapshot.c owns the control queries, the retained sample ring and the
 * ordering that turns a runtime snapshot into the process table; xtop_report.c
 * assembles the plain-text report, the frame and the extras the frame shows;
 * xtop.c keeps the string, token, figure and arena helpers all three use.
 * Each declaration below names the file that defines it.
 */

#include <xaios_user.h>
#include <xaios/types.h>
#include "xtop_serve.h"
#include "xtop_draw.h"

/* The three error spellings the application uses; the libc header carries
   only XAIOS_ERR_UNSUPPORTED and XAIOS_ERR_BUSY. */
#define XAIOS_ERR_INVALID (-1)
#define XAIOS_ERR_NOT_FOUND (-2)
#define XAIOS_ERR_NO_MEMORY (-3)

#define XAIOS_XTOP_MAX_PROCESSES 1024U
#define XAIOS_XTOP_CPU_PAGE_MAX 256U
#define XAIOS_XTOP_ARENA_BYTES 131072U

/* Runtime-state spellings, single-instanced here.  xtop_draw.h spells the
   process ones under the same guard, so this only adds them if it did not. */
#ifndef XAIOS_USER_PROCESS_RUNNABLE
#define XAIOS_USER_PROCESS_LOADED XAIOS_RUNTIME_PROCESS_LOADED
#define XAIOS_USER_PROCESS_RUNNABLE XAIOS_RUNTIME_PROCESS_RUNNABLE
#define XAIOS_USER_PROCESS_RUNNING XAIOS_RUNTIME_PROCESS_RUNNING
#define XAIOS_USER_PROCESS_WAITING XAIOS_RUNTIME_PROCESS_WAITING
#define XAIOS_USER_PROCESS_EXITED XAIOS_RUNTIME_PROCESS_EXITED
#define XAIOS_USER_PROCESS_FAILED XAIOS_RUNTIME_PROCESS_FAILED
#endif
#define XAIOS_CPU_ROLE_HOUSEKEEPING XAIOS_RUNTIME_CPU_HOUSEKEEPING
#define XAIOS_CPU_ROLE_SCHEDULING XAIOS_RUNTIME_CPU_SCHEDULING
#define XAIOS_CPU_ROLE_AI_HOT XAIOS_RUNTIME_CPU_AI_HOT

/* defined in xtop.c */
void *xtop_arena_alloc(uint64_t size, uint64_t alignment);
void xtop_arena_free(void *pointer);
int xtop_contains_substring(const char *text, const char *needle);
xaios_status_t xtop_command_fail(char *output, uint64_t capacity,
                                 uint64_t *offset, const char *message);
const char *xtop_state_name(uint32_t state);
int xtop_state_active(uint32_t state);
uint64_t xtop_ratio_tenths(uint64_t numerator, uint64_t denominator);

/* defined in xtop_snapshot.c */
int xtop_snapshot_wait(uint32_t wait_ms);
int xtop_snapshot_simple_query(uint32_t operation, uint32_t payload_type,
                              void *payload, uint64_t payload_size);
int xtop_snapshot_gather_snapshot(
    uint32_t cpu_start, uint32_t cpu_want,
    xaios_control_runtime_cpu_record_user_t *cpus, uint32_t cpu_capacity,
    uint32_t *cpu_count,
    xaios_control_runtime_process_record_user_t *records, uint32_t capacity,
    uint64_t *runtime_by_pid, uint32_t *count,
    xaios_control_runtime_snapshot_payload_user_t *metadata);
int xtop_snapshot_gather_cpu_page(
    uint32_t cpu_start, uint32_t cpu_count,
    xaios_control_runtime_cpu_record_user_t *records, uint32_t capacity,
    uint32_t *record_count,
    xaios_control_runtime_snapshot_payload_user_t *metadata);
int xtop_snapshot_ring_has(uint64_t now_ns, uint64_t window_ns,
                           uint32_t cpu_start);
int xtop_snapshot_ring_read(
    uint64_t now_ns, uint64_t window_ns, uint32_t cpu_start,
    xaios_control_runtime_snapshot_payload_user_t *meta,
    uint64_t *runtime_by_pid, uint32_t runtime_capacity,
    xaios_control_runtime_cpu_record_user_t *cpus, uint32_t cpu_capacity,
    uint32_t *cpu_count);
void xtop_snapshot_ring_push(
    const xaios_control_runtime_snapshot_payload_user_t *meta,
    const xaios_control_runtime_process_record_user_t *processes,
    uint32_t process_count,
    const xaios_control_runtime_cpu_record_user_t *cpus, uint32_t cpu_count,
    uint32_t cpu_start);
void xtop_snapshot_sort_rows(xtop_process_row_t *rows, uint32_t count,
                             xtop_sort_key_t key, int reverse);
int xtop_snapshot_arrange_tree(xtop_process_row_t *rows, uint32_t count);

#endif /* XAIOS_APPS_XTOP_SNAPSHOT_H */
