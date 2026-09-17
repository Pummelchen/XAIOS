#ifndef XAIOS_APPS_XTOP_DRAW_H
#define XAIOS_APPS_XTOP_DRAW_H

/*
 * Private interface between xtop.c and xtop_draw.c.
 *
 * xtop_draw.c owns the dashboard: the frame that lays the gauges, the cores
 * panel and the process list onto the canvas, plus the geometry that decides
 * how much of what fits.  xtop.c owns the control queries, the retained
 * samples and the plain-text report.  The extras the dashboard shows are
 * xtop.c's file-scope state, filled by the serving loop; it is handed to
 * xtop_render_color as a read-only pointer for the duration of one call and
 * never kept, so the dashboard cannot reach around xtop.c to mutate it.
 */

#include "xtop_glyph.h"
#include "xtop_render.h"

/* The process-state aliases the dashboard uses. xtop.c defines them for its
   own switch; the drawing helper needs them too, so they live here once. */
#ifndef XAIOS_USER_PROCESS_RUNNABLE
#define XAIOS_USER_PROCESS_RUNNABLE XAIOS_RUNTIME_PROCESS_RUNNABLE
#define XAIOS_USER_PROCESS_RUNNING XAIOS_RUNTIME_PROCESS_RUNNING
#define XAIOS_USER_PROCESS_WAITING XAIOS_RUNTIME_PROCESS_WAITING
#define XAIOS_USER_PROCESS_EXITED XAIOS_RUNTIME_PROCESS_EXITED
#define XAIOS_USER_PROCESS_FAILED XAIOS_RUNTIME_PROCESS_FAILED
#define XAIOS_USER_PROCESS_LOADED XAIOS_RUNTIME_PROCESS_LOADED
#endif

/* Per-CPU usage, read out of the snapshot xtop.c gathered. */
typedef struct xaios_cpu_usage_snapshot {
  uint32_t cpu_id;
  uint32_t active_pid;
  uint64_t busy_ns;
  uint64_t elapsed_ns;
} xaios_cpu_usage_snapshot_t;

/* One process row, filtered and arranged by xtop.c for the frame to draw. */
typedef struct xtop_process_row {
  uint32_t pid;
  uint32_t parent_pid;
  uint32_t cpu_id;
  uint32_t state;
  uint64_t cpu_tenths;
  uint64_t memory_tenths;
  uint64_t runtime_ns;
  uint64_t resident_pages;
  uint64_t syscall_count;
  uint32_t tree_depth;
  const char *name;
} xtop_process_row_t;

/* Implemented in xtop_draw.c. */
uint32_t xtop_cpu_page_capacity(uint32_t terminal_columns,
                                uint32_t terminal_rows,
                                uint32_t label_columns);
uint32_t xtop_render_color(
    xtop_canvas_t *cv, uint32_t columns, uint32_t terminal_rows,
    uint32_t cpu_start, uint32_t cpu_shown, uint32_t cpu_total,
    const uint64_t *before_cpu, uint64_t after_ns, uint64_t elapsed_ns,
    uint64_t managed_pages, uint64_t free_pages, uint32_t active_tasks,
    uint32_t failed_tasks, const xtop_process_row_t *process_rows,
    uint32_t process_count, uint32_t process_start, uint32_t selected,
    xtop_sort_key_t sort_key, int reverse, int interactive, const char *filter,
    uint32_t refresh_ms, uint32_t layout, int serve_frame,
    const xtop_extras_t *extras);

/* Implemented in xtop.c and called by the dashboard. */
uint64_t xtop_capacity_tenths(uint64_t numerator, uint64_t denominator);
void xtop_append_percent(char *output, uint64_t output_capacity,
                         uint64_t *output_bytes, uint64_t tenths);
void xtop_append_u64_width(char *output, uint64_t output_capacity,
                           uint64_t *output_bytes, uint64_t value,
                           uint32_t width);
void xtop_load_average_hundredths(uint32_t output[3]);
int xtop_user_cpu_usage_snapshot(uint32_t ordinal, uint64_t now_ns,
                                 xaios_cpu_usage_snapshot_t *usage);

#endif /* XAIOS_APPS_XTOP_DRAW_H */
