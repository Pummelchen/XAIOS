/* The dashboard: the frame that lays the gauges, the cores panel and the
   process list onto the canvas, and the geometry that decides what fits.
   Split out of xtop.c; see xtop_draw.h for what crosses. */

#include <xaios_user.h>
#include <xaios_screen.h>
#include <xaios/types.h>
#include "xtop_serve.h"
#include "xtop_render.h"
#include "xtop_draw.h"

static uint16_t g_last_cpu_tenths;
static uint16_t g_last_mem_tenths;

/* The retained samples are the renderer's; these read them out. */
uint16_t xtop_last_cpu_tenths(void) { return g_last_cpu_tenths; }
uint16_t xtop_last_mem_tenths(void) { return g_last_mem_tenths; }

static char xtop_state_character(uint32_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_RUNNING:
    return 'R';
  case XAIOS_USER_PROCESS_RUNNABLE:
    return 'R';
  case XAIOS_USER_PROCESS_WAITING:
    return 'S';
  case XAIOS_USER_PROCESS_EXITED:
    return 'Z';
  case XAIOS_USER_PROCESS_FAILED:
    return 'F';
  case XAIOS_USER_PROCESS_LOADED:
    return 'L';
  default:
    return '?';
  }
}

static uint32_t xtop_cpu_max_columns(uint32_t terminal_columns,
                                     uint32_t label_columns) {
  if (label_columns < 5U) label_columns = 5U;
  uint32_t cells = terminal_columns / (label_columns + 10U);
  if (cells >= 16U) return 16U;
  if (cells >= 8U) return 8U;
  if (cells >= 4U) return 4U;
  if (cells >= 2U) return 2U;
  return 1U;
}

static uint32_t xtop_cpu_grid_columns(uint32_t cpu_count,
                                      uint32_t terminal_columns,
                                      uint32_t label_columns) {
  uint32_t requested = 1U;
  if (cpu_count > 64U) requested = 16U;
  else if (cpu_count > 32U) requested = 8U;
  else if (cpu_count > 16U) requested = 4U;
  else if (cpu_count > 8U) requested = 2U;
  uint32_t maximum = xtop_cpu_max_columns(terminal_columns, label_columns);
  return requested < maximum ? requested : maximum;
}

static uint32_t xtop_cpu_grid_rows(uint32_t cpu_count,
                                   uint32_t grid_columns) {
  if (cpu_count == 0U) return 0U;
  return (cpu_count + grid_columns - 1U) / grid_columns;
}

uint32_t xtop_cpu_page_capacity(uint32_t terminal_columns,
                                       uint32_t terminal_rows,
                                       uint32_t label_columns) {
  uint32_t rows = terminal_rows > 10U ? terminal_rows - 10U : 1U;
  if (rows > 8U) rows = 8U;
  uint32_t columns = xtop_cpu_max_columns(terminal_columns, label_columns);
  return rows > UINT32_MAX / columns ? UINT32_MAX : rows * columns;
}

uint32_t xtop_render_color(
    xtop_canvas_t *cv, uint32_t columns, uint32_t terminal_rows, uint32_t cpu_start,
    uint32_t cpu_shown, uint32_t cpu_total, const uint64_t *before_cpu,
    uint64_t after_ns, uint64_t elapsed_ns, uint64_t managed_pages,
    uint64_t free_pages, uint32_t active_tasks, uint32_t failed_tasks,
    const xtop_process_row_t *process_rows, uint32_t process_count,
    uint32_t process_start, uint32_t selected, xtop_sort_key_t sort_key,
    int reverse, int interactive, const char *filter, uint32_t refresh_ms,
    uint32_t layout, int serve_frame, const xtop_extras_t *extras) {
  uint32_t process_shown = 0U;
  uint32_t label_columns = 3U;
  if (cpu_total != 0U && xtop_u64_digits((uint64_t)cpu_total - 1U) > label_columns) {
    label_columns = (uint32_t)xtop_u64_digits((uint64_t)cpu_total - 1U);
  }
  uint32_t grid_columns =
      xtop_cpu_grid_columns(cpu_shown, columns, label_columns);
  uint32_t cpu_line_count = xtop_cpu_grid_rows(cpu_shown, grid_columns);
  uint32_t header_lines = grid_columns == 1U
                              ? cpu_line_count + 2U
                              : cpu_line_count + 3U;
  if (header_lines < 3U) header_lines = 3U;
  uint32_t fixed_lines = 6U;
  uint32_t process_budget = terminal_rows > header_lines + fixed_lines
                                ? terminal_rows - header_lines - fixed_lines
                                : 1U;
  uint32_t left_width = columns / 2U;
  uint32_t right_width = columns - left_width;
  uint64_t used_pages = managed_pages >= free_pages
                            ? managed_pages - free_pages
                            : 0U;
  uint64_t memory_tenths = xtop_capacity_tenths(used_pages, managed_pages);
  uint64_t used_mebibytes = used_pages / 256U;
  uint64_t managed_mebibytes = managed_pages / 256U;
  uint32_t load_average[3];
  xtop_load_average_hundredths(load_average);

  /* Per-CPU load for the cores panel and the gauge above it. */
  uint64_t cpu_tenths[64];
  uint64_t cpu_sum = 0U;
  uint32_t cpu_counted = cpu_shown > 64U ? 64U : cpu_shown;
  for (uint32_t offset = 0U; offset < cpu_counted; ++offset) {
    xaios_cpu_usage_snapshot_t usage;
    cpu_tenths[offset] = 0U;
    if (xtop_user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) ==
        XAIOS_OK) {
      uint64_t delta = usage.busy_ns >= before_cpu[offset]
                           ? usage.busy_ns - before_cpu[offset]
                           : 0U;
      cpu_tenths[offset] = xtop_capacity_tenths(delta, elapsed_ns);
    }
    cpu_sum += cpu_tenths[offset];
  }
  uint64_t cpu_all_tenths = cpu_counted != 0U ? cpu_sum / cpu_counted : 0U;
  g_last_cpu_tenths = (uint16_t)(cpu_all_tenths > 1000U ? 1000U : cpu_all_tenths);
  g_last_mem_tenths = (uint16_t)(memory_tenths > 1000U ? 1000U : memory_tenths);

  /* Geometry: an outer frame, two panels abreast twice, then the process
     list across the whole width. Rows the terminal does not have come out of
     the process list, and a short terminal loses the detail panels. */
  const uint32_t inner = columns >= 4U ? columns - 2U : 2U;
  const uint32_t left = inner / 2U;
  const uint32_t right = inner - left;
  const uint32_t left_in = left >= 2U ? left - 2U : 0U;
  const uint32_t right_in = right >= 2U ? right - 2U : 0U;
  const uint32_t list_in = inner >= 2U ? inner - 2U : 0U;
  const uint32_t gauge_rows = terminal_rows >= 30U ? 4U : 2U;
  const int detail = terminal_rows >= 20U;
  grid_columns = xtop_cpu_grid_columns(cpu_shown, left_in, label_columns);
  cpu_line_count = xtop_cpu_grid_rows(cpu_shown, grid_columns);
  uint32_t detail_rows = cpu_line_count > 4U ? cpu_line_count : 4U;
  /* The two rows after the frame belong to the application runner, which
     prints "xtop: complete" and a newline after every run. A frame the
     full height of the terminal scrolled two rows up under that trailer and
     lost its title rule; the frame is two rows short of the screen instead. */
  uint32_t used_rows = 1U + (gauge_rows + 2U) +
                       (detail != 0 ? detail_rows + 2U : 0U) + 3U + 1U +
                       (serve_frame != 0 ? 0U : 2U);
  process_budget = terminal_rows > used_rows ? terminal_rows - used_rows : 1U;
  (void)header_lines;
  (void)fixed_lines;
  (void)left_width;
  (void)right_width;

  char cpu_title[64];
  char mem_title[96];
  char figure[16];
  uint64_t used = 0U;
  cpu_title[0] = '\0';
  xtop_output_append(cpu_title, sizeof(cpu_title), &used, "CPU  ");
  xtop_output_append_u64(cpu_title, sizeof(cpu_title), &used, cpu_total);
  xtop_output_append(cpu_title, sizeof(cpu_title), &used,
                cpu_total == 1U ? " core  " : " cores  ");
  xtop_append_percent(cpu_title, sizeof(cpu_title), &used, cpu_all_tenths);
  used = 0U;
  mem_title[0] = '\0';
  xtop_output_append(mem_title, sizeof(mem_title), &used, "Mem  ");
  xtop_output_append_u64(mem_title, sizeof(mem_title), &used, used_mebibytes);
  xtop_output_append(mem_title, sizeof(mem_title), &used, "M / ");
  xtop_output_append_u64(mem_title, sizeof(mem_title), &used, managed_mebibytes);
  xtop_output_append(mem_title, sizeof(mem_title), &used, "M  (Swap 0K / 0K)  ");
  xtop_append_percent(mem_title, sizeof(mem_title), &used, memory_tenths);

  xtop_canvas_begin(cv, interactive != 0);

  /* Outer top: the title by the left corner, the tab strip by the right.
     "[Main]" stays: the network suites read it to know the screen is up. */
  xtop_draw_rule(cv, XTOP_BOX_TL, XTOP_BOX_TR,
                 "XAIOS xtop \xe2\x80\x94 sampled kernel process monitor",
                 "[Main]", columns);
  xtop_canvas_newline(cv);

  /* The first band: gauges, the machine and its AI runtime, or history,
     by layout. Every layout keeps the outer frame and the process list. */
  const char *band_left_title = cpu_title;
  const char *band_right_title = mem_title;
  char line[192];
  if (layout == 2U) {
    band_left_title = "Platform";
    band_right_title = "AI runtime";
  } else if (layout == 3U) {
    band_left_title = "CPU history";
    band_right_title = "Memory history";
  }
  xtop_draw_edge(cv);
  xtop_draw_panel_top(cv, band_left_title, left);
  xtop_draw_panel_top(cv, band_right_title, right);
  xtop_draw_edge(cv);
  xtop_canvas_newline(cv);
  for (uint32_t row = 0U; row < gauge_rows; ++row) {
    int carries = row == gauge_rows / 2U;
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    if (layout == 1U) {
      used = 0U; figure[0] = '\0';
      xtop_append_percent(figure, sizeof(figure), &used, cpu_all_tenths);
      xtop_render_gauge_row(cv, left_in, cpu_all_tenths, carries ? figure : 0);
    } else if (layout == 2U) {
      xtop_render_platform_line(extras, line, sizeof(line), row, cpu_total);
      xtop_draw_padded(cv, XTOP_STYLE_FG, line, left_in);
    } else {
      xtop_render_chart_row(cv, left_in, extras->cpu_history,
                          extras->history_count, row, gauge_rows, 1000U);
    }
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    if (layout == 1U) {
      used = 0U; figure[0] = '\0';
      xtop_append_percent(figure, sizeof(figure), &used, memory_tenths);
      xtop_render_gauge_row(cv, right_in, memory_tenths, carries ? figure : 0);
    } else if (layout == 2U) {
      xtop_render_ai_line(extras, line, sizeof(line), row);
      xtop_draw_padded(cv, XTOP_STYLE_FG, line, right_in);
    } else {
      xtop_render_chart_row(cv, right_in, extras->mem_history,
                          extras->history_count, row, gauge_rows, 1000U);
    }
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    xtop_canvas_newline(cv);
  }
  xtop_draw_edge(cv);
  xtop_draw_panel_bottom(cv, left);
  xtop_draw_panel_bottom(cv, right);
  xtop_draw_edge(cv);
  xtop_canvas_newline(cv);

  /* The second band: cores beside the system figures, or the network and
     disk figures, or a network history beside the cores. */
  if (detail != 0) {
    const char *detail_left_title = layout == 2U ? "Network & Disk"
                                    : layout == 3U ? "Network history"
                                                   : "Cores";
    const char *detail_right_title = layout == 3U ? "Cores" : "System";
    /* The largest network rate in the window, so the chart has a scale. */
    uint32_t net_scale = 1U;
    for (uint32_t i = 0U; i < extras->history_count && i < XTOP_HISTORY; ++i) {
      if (extras->net_history[i] > net_scale) net_scale = extras->net_history[i];
    }
    xtop_draw_edge(cv);
    xtop_draw_panel_top(cv, detail_left_title, left);
    xtop_draw_panel_top(cv, detail_right_title, right);
    xtop_draw_edge(cv);
    xtop_canvas_newline(cv);
    for (uint32_t line_index = 0U; line_index < detail_rows; ++line_index) {
      uint32_t line = line_index;
      xtop_draw_edge(cv);
      xtop_draw_edge(cv);
      if (layout == 2U) {
        char text[192];
        xtop_render_netdisk_line(extras, text, sizeof(text), line);
        xtop_draw_padded(cv, XTOP_STYLE_FG, text, left_in);
      } else if (layout == 3U) {
        uint16_t scaled[XTOP_HISTORY];
        for (uint32_t i = 0U; i < XTOP_HISTORY; ++i) {
          uint64_t v = (uint64_t)extras->net_history[i] * 1000U / net_scale;
          scaled[i] = (uint16_t)(v > 1000U ? 1000U : v);
        }
        xtop_render_chart_row(cv, left_in, scaled, extras->history_count,
                            line, detail_rows, 1000U);
      } else if (line < cpu_line_count) {
        uint32_t base_width = left_in / grid_columns;
        for (uint32_t column = 0U; column < grid_columns; ++column) {
          uint32_t cell_width = column + 1U == grid_columns
                                    ? left_in - base_width * column
                                    : base_width;
          uint32_t offset = column * cpu_line_count + line;
          if (offset >= cpu_counted) {
            xtop_canvas_repeat(cv, ' ', cell_width);
            continue;
          }
          char label[12];
          uint64_t label_bytes = 0U;
          label[0] = '\0';
          xtop_append_u64_width(label, sizeof(label), &label_bytes,
                                cpu_start + offset, label_columns);
          uint32_t bar_width =
              cell_width > label_columns + XTOP_METER_OVERHEAD
                  ? cell_width - label_columns - XTOP_METER_OVERHEAD
                  : 1U;
          xtop_render_meter(cv, label, label_columns, cpu_tenths[offset],
                          bar_width, cell_width);
        }
      } else {
        xtop_canvas_repeat(cv, ' ', left_in);
      }
      xtop_draw_edge(cv);
      xtop_draw_edge(cv);
      if (layout == 3U) {
        if (line < cpu_line_count) {
          uint32_t base_width = right_in / grid_columns;
          for (uint32_t column = 0U; column < grid_columns; ++column) {
            uint32_t cell_width = column + 1U == grid_columns
                                      ? right_in - base_width * column
                                      : base_width;
            uint32_t offset = column * cpu_line_count + line;
            if (offset >= cpu_counted) {
              xtop_canvas_repeat(cv, ' ', cell_width);
              continue;
            }
            char label[12];
            uint64_t label_bytes = 0U;
            label[0] = '\0';
            xtop_append_u64_width(label, sizeof(label), &label_bytes,
                                  cpu_start + offset, label_columns);
            uint32_t bar_width =
                cell_width > label_columns + XTOP_METER_OVERHEAD
                    ? cell_width - label_columns - XTOP_METER_OVERHEAD
                    : 1U;
            xtop_render_meter(cv, label, label_columns, cpu_tenths[offset],
                            bar_width, cell_width);
          }
        } else {
          xtop_canvas_repeat(cv, ' ', right_in);
        }
      } else if (line < 3U) {
        xtop_draw_info_cell(cv, line, right_in, active_tasks, failed_tasks,
                            cpu_total, load_average, after_ns);
      } else if (line == 3U) {
        char view[128];
        used = 0U; view[0] = '\0';
        xtop_output_append(view, sizeof(view), &used, "View: ");
        xtop_output_append(view, sizeof(view), &used,
                      interactive != 0 ? "live" : "snapshot");
        xtop_output_append(view, sizeof(view), &used, "  Sort: ");
        xtop_output_append(view, sizeof(view), &used, xtop_sort_name(sort_key));
        if (reverse != 0) xtop_output_append(view, sizeof(view), &used, " ascending");
        if (filter[0] != '\0') {
          xtop_output_append(view, sizeof(view), &used, "  Filter: ");
          xtop_output_append(view, sizeof(view), &used, filter);
        }
        if (cpu_start != 0U || cpu_start + cpu_shown < cpu_total) {
          xtop_output_append(view, sizeof(view), &used, "  CPU page: ");
          xtop_output_append_u64(view, sizeof(view), &used, cpu_start);
          xtop_output_append(view, sizeof(view), &used, "-");
          xtop_output_append_u64(view, sizeof(view), &used,
                            cpu_shown == 0U ? cpu_start
                                            : cpu_start + cpu_shown - 1U);
          xtop_output_append(view, sizeof(view), &used, "/");
          xtop_output_append_u64(view, sizeof(view), &used, cpu_total);
        }
        xtop_draw_padded(cv, XTOP_STYLE_FG, view, right_in);
      } else {
        xtop_canvas_repeat(cv, ' ', right_in);
      }
      xtop_draw_edge(cv);
      xtop_draw_edge(cv);
      xtop_canvas_newline(cv);
    }
    xtop_draw_edge(cv);
    xtop_draw_panel_bottom(cv, left);
    xtop_draw_panel_bottom(cv, right);
    xtop_draw_edge(cv);
    xtop_canvas_newline(cv);
  }

  /* The process list, with its header on a bar. */
  xtop_draw_edge(cv);
  xtop_draw_panel_top(
      cv,
      inner >= 70U
          ? "Process List  (\xe2\x86\x91/\xe2\x86\x93 scroll  F3 search  F4 filter  F5 tree)"
          : "Process List",
      inner);
  xtop_draw_edge(cv);
  xtop_canvas_newline(cv);
  xtop_draw_edge(cv);
  xtop_draw_edge(cv);
  xtop_draw_padded(
      cv, XTOP_STYLE_HEADER,
      list_in < 60U
          ? " PID S   CPU%   MEM% COMMAND"
          : (list_in < 100U
                 ? "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU COMMAND"
                 : "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU  SYSCALLS COMMAND"),
      list_in);
  xtop_draw_edge(cv);
  xtop_draw_edge(cv);
  xtop_canvas_newline(cv);

  uint32_t list_rows = 0U;
  for (uint32_t i = process_start;
       i < process_count && process_shown < process_budget;
       ++i) {
    if (!xtop_canvas_room(cv, ((uint64_t)columns + 96U) * 2U)) break;
    const xtop_process_row_t *row = &process_rows[i];
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    xtop_canvas_style(cv, i == selected ? XTOP_STYLE_HEADER : XTOP_STYLE_FG);
    uint32_t fixed_visible;
    if (list_in < 60U) {
      xtop_canvas_u64_width(cv, row->pid, 4U);
      xtop_canvas_text(cv, " ");
      xtop_canvas_char(cv, xtop_state_character(row->state));
      xtop_canvas_text(cv, " ");
      xtop_canvas_percent_width(cv, row->cpu_tenths);
      xtop_canvas_text(cv, " ");
      xtop_canvas_percent_width(cv, row->memory_tenths);
      xtop_canvas_text(cv, " ");
      fixed_visible = 21U;
    } else {
      xtop_canvas_u64_width(cv, row->pid, 5U);
      xtop_canvas_text(cv, " ");
      xtop_canvas_u64_width(cv, row->parent_pid, 5U);
      xtop_canvas_text(cv, " ");
      xtop_canvas_char(cv, xtop_state_character(row->state));
      xtop_canvas_text(cv, " ");
      xtop_canvas_percent_width(cv, row->cpu_tenths);
      xtop_canvas_text(cv, " ");
      xtop_canvas_percent_width(cv, row->memory_tenths);
      xtop_canvas_text(cv, " ");
      xtop_canvas_runtime(cv, row->runtime_ns);
      xtop_canvas_text(cv, " ");
      xtop_canvas_u64_width(cv, row->resident_pages * 4U, 7U);
      xtop_canvas_text(cv, " ");
      if (row->cpu_id == UINT32_MAX) {
        xtop_canvas_text(cv, "  -");
      } else {
        xtop_canvas_u64_width(cv, row->cpu_id, 3U);
      }
      xtop_canvas_text(cv, " ");
      fixed_visible = 49U;
      if (list_in >= 100U) {
        xtop_canvas_u64_width(cv, row->syscall_count, 9U);
        xtop_canvas_text(cv, " ");
        fixed_visible += 10U;
      }
    }
    uint32_t command_width = list_in > fixed_visible
                                 ? list_in - fixed_visible
                                 : 0U;
    uint32_t prefix_length = 0U;
    if (sort_key == XTOP_SORT_PARENT && row->tree_depth != 0U) {
      uint32_t indent = row->tree_depth > 8U ? 14U
                                             : (row->tree_depth - 1U) * 2U;
      prefix_length = indent + 3U;
      if (prefix_length <= command_width) {
        xtop_canvas_repeat(cv, ' ', indent);
      } else {
        prefix_length = 0U;
      }
    }
    if (prefix_length != 0U && command_width >= prefix_length) {
      xtop_canvas_text(cv, "|- ");
    }
    uint32_t name_width = command_width > prefix_length
                              ? command_width - prefix_length : 0U;
    xtop_canvas_bounded(cv, row->name, name_width);
    uint32_t command_length = (uint32_t)xtop_cstr_len(row->name);
    if (command_length < name_width) {
      xtop_canvas_repeat(cv, ' ', name_width - command_length);
    }
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    xtop_canvas_newline(cv);
    ++process_shown;
    ++list_rows;
  }
  /* The list keeps its height whatever it holds, so the frame is stable. */
  for (; list_rows < process_budget; ++list_rows) {
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    xtop_canvas_repeat(cv, ' ', list_in);
    xtop_draw_edge(cv);
    xtop_draw_edge(cv);
    xtop_canvas_newline(cv);
  }
  xtop_draw_edge(cv);
  xtop_draw_panel_bottom(cv, inner);
  xtop_draw_edge(cv);
  xtop_canvas_newline(cv);

  xtop_draw_key_bar(cv, columns, interactive, refresh_ms, layout);
  xtop_canvas_cursor(cv, interactive != 0);
  return process_shown;
}
