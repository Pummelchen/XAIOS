/*
 * The panels and the charts of the xtop dashboard: the Platform, AI runtime
 * and Network & Disk text, and the solid gauge, bar chart and meter rows they
 * and the dashboard are drawn with.  Split out of xtop.c; see xtop_render.h
 * for the state xtop.c owns and the glyph primitives this file draws through.
 */

#include "xtop_serve.h"
#include "xtop_render.h"

/* One row of a solid gauge: the filled part in the fill colour, the rest the
   field, and on the row that carries it the figure centred, drawn over
   whichever of the two it lands on. That is mactop's gauge. */
void xtop_render_gauge_row(xtop_canvas_t *cv, uint32_t width,
                           uint64_t tenths, const char *figure) {
  uint64_t fill64 = ((uint64_t)width * tenths + 999U) / 1000U;
  uint32_t fill = fill64 > width ? width : (uint32_t)fill64;
  uint32_t figure_columns = figure != 0 ? xtop_columns(figure) : 0U;
  uint32_t figure_start =
      figure_columns < width ? (width - figure_columns) / 2U : 0U;
  int filled = -1;
  uint64_t figure_index = 0U;
  for (uint32_t column = 0U; column < width; ++column) {
    int here = column < fill ? 1 : 0;
    if (here != filled) {
      if (here != 0) {
        xtop_canvas_style(cv, XTOP_STYLE_FILL_BG);
      } else {
        xtop_canvas_style(cv, XTOP_STYLE_RESET);
      }
      xtop_canvas_style(cv, XTOP_STYLE_TITLE);
      filled = here;
    }
    if (figure != 0 && column >= figure_start &&
        column < figure_start + figure_columns &&
        figure[figure_index] != '\0') {
      /* One glyph, however many bytes it is. */
      char glyph[8];
      uint32_t n = 0U;
      do {
        if (n < 7U) glyph[n++] = figure[figure_index];
        ++figure_index;
      } while (((uint8_t)figure[figure_index] & 0xc0U) == 0x80U);
      glyph[n] = '\0';
      xtop_canvas_text(cv, glyph);
    } else {
      xtop_canvas_char(cv, ' ');
    }
  }
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
}

/* A bar chart row: `rows` rows tall, newest sample at the right, each
   column a value in tenths of a percent. Whole rows are full blocks and the
   top of each bar is one of the eighth blocks, which is what makes a chart
   this small readable. */
void xtop_render_chart_row(xtop_canvas_t *cv, uint32_t width,
                           const uint16_t *history, uint32_t count,
                           uint32_t row, uint32_t rows, uint16_t scale) {
  static const char *const eighths[8] = {
      " ", "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
      "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87"};
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_style(cv, XTOP_STYLE_CHART);
  for (uint32_t column = 0U; column < width; ++column) {
    /* The last `width` samples, right-aligned. */
    uint32_t index = count + column >= width ? count + column - width : 0U;
    int have = count + column >= width && index < count;
    uint32_t value = have ? history[index] : 0U;
    if (scale == 0U) scale = 1U;
    uint32_t total_eighths = (uint32_t)(((uint64_t)value * rows * 8U + scale - 1U) / scale);
    if (total_eighths > rows * 8U) total_eighths = rows * 8U;
    /* Rows are numbered from the top; the bar fills from the bottom. */
    uint32_t below = (rows - 1U - row) * 8U;
    if (total_eighths >= below + 8U) {
      xtop_canvas_text(cv, XTOP_BAR_FULL);
    } else if (total_eighths > below) {
      xtop_canvas_text(cv, eighths[total_eighths - below]);
    } else {
      xtop_canvas_char(cv, ' ');
    }
  }
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
}

/* A figure in bytes per second, four significant characters at most. */
static void xtop_append_rate(char *output, uint64_t output_capacity,
                             uint64_t *output_bytes, uint64_t bytes_per_s) {
  const char *unit = "B/s";
  uint64_t whole = bytes_per_s;
  uint64_t tenths = 0U;
  if (bytes_per_s >= UINT64_C(1073741824)) {
    unit = "GB/s"; whole = bytes_per_s / UINT64_C(1073741824);
    tenths = (bytes_per_s % UINT64_C(1073741824)) * 10U / UINT64_C(1073741824);
  } else if (bytes_per_s >= 1048576U) {
    unit = "MB/s"; whole = bytes_per_s / 1048576U;
    tenths = (bytes_per_s % 1048576U) * 10U / 1048576U;
  } else if (bytes_per_s >= 1024U) {
    unit = "KB/s"; whole = bytes_per_s / 1024U;
    tenths = (bytes_per_s % 1024U) * 10U / 1024U;
  }
  xtop_output_append_u64(output, output_capacity, output_bytes, whole);
  if (whole < 100U && unit[0] != 'B') {
    xtop_output_append(output, output_capacity, output_bytes, ".");
    xtop_output_append_u64(output, output_capacity, output_bytes, tenths);
  }
  xtop_output_append(output, output_capacity, output_bytes, " ");
  xtop_output_append(output, output_capacity, output_bytes, unit);
}

static const char *xtop_yes_no(uint32_t value) {
  return value == 1U ? "yes" : (value == 0U ? "no" : "?");
}

/* The Platform panel: what the machine is, said as capabilities. Each
   architecture has its own line of them, because the flags that matter
   differ; the rest is common. */
void xtop_render_platform_line(const xtop_extras_t *extras, char *line,
                               uint64_t capacity, uint32_t row,
                               uint32_t cpu_total) {
  uint64_t used = 0U;
  const xaios_control_hardware_payload_user_t *hw = &extras->hardware;
  line[0] = '\0';
  if (extras->have_hardware == 0) {
    if (row == 0U) xtop_output_append(line, capacity, &used, "hardware query unavailable");
    return;
  }
  int arm = hw->architecture[0] == 'a';
  int x86 = hw->architecture[0] == 'x';
  int riscv = hw->architecture[0] == 'r';
  switch (row) {
  case 0U:
    xtop_output_append(line, capacity, &used, "Architecture: ");
    xtop_output_append(line, capacity, &used, hw->architecture);
    xtop_output_append(line, capacity, &used, "  Backend: ");
    xtop_output_append(line, capacity, &used, hw->selected_backend);
    break;
  case 1U:
    xtop_output_append(line, capacity, &used, "CPUs: ");
    xtop_output_append_u64(line, capacity, &used, cpu_total);
    xtop_output_append(line, capacity, &used, "  NUMA nodes: ");
    xtop_output_append_u64(line, capacity, &used, hw->numa_nodes);
    xtop_output_append(line, capacity, &used, "  Page: ");
    xtop_output_append_u64(line, capacity, &used, hw->page_size / 1024U);
    xtop_output_append(line, capacity, &used, " KiB");
    break;
  case 2U:
    if (arm) {
      xtop_output_append(line, capacity, &used, "SIMD: NEON ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->neon));
      xtop_output_append(line, capacity, &used, "  SVE ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->sve));
    } else if (x86) {
      xtop_output_append(line, capacity, &used, "AVX2 ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->avx2));
      xtop_output_append(line, capacity, &used, "  AVX-512 ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->avx512));
      xtop_output_append(line, capacity, &used, "  VNNI ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->vnni));
      xtop_output_append(line, capacity, &used, "  AMX ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->amx));
    } else if (riscv) {
      xtop_output_append(line, capacity, &used, "Vector (V) ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->rvv));
      xtop_output_append(line, capacity, &used, "  Sstc timer ");
      xtop_output_append(line, capacity, &used, xtop_yes_no(hw->sstc));
    } else {
      xtop_output_append(line, capacity, &used, "Features: unknown");
    }
    break;
  case 3U:
    xtop_output_append(line, capacity, &used, "Timer: ");
    xtop_output_append_u64(line, capacity, &used, hw->timer_frequency_hz / 1000000U);
    xtop_output_append(line, capacity, &used, " MHz  Memory: ");
    xtop_output_append_u64(line, capacity, &used, hw->physical_pages / 256U);
    xtop_output_append(line, capacity, &used, "M physical, ");
    xtop_output_append_u64(line, capacity, &used, hw->managed_pages / 256U);
    xtop_output_append(line, capacity, &used, "M managed");
    break;
  default:
    break;
  }
}

/* The AI runtime panel: what this machine accelerates is inference, and
   its figures stand where mactop shows the neural engine. */
void xtop_render_ai_line(const xtop_extras_t *extras, char *line,
                         uint64_t capacity, uint32_t row) {
  uint64_t used = 0U;
  const xaios_control_metrics_payload_user_t *m = &extras->metrics;
  line[0] = '\0';
  if (extras->have_metrics == 0) {
    if (row == 0U) xtop_output_append(line, capacity, &used, "metrics query unavailable");
    return;
  }
  switch (row) {
  case 0U:
    xtop_output_append(line, capacity, &used, "Inferences/s: ");
    xtop_output_append_u64(line, capacity, &used, extras->inferences_per_s);
    xtop_output_append(line, capacity, &used, "  Active: ");
    xtop_output_append_u64(line, capacity, &used, m->active_sessions);
    xtop_output_append(line, capacity, &used, "  Queue: ");
    xtop_output_append_u64(line, capacity, &used, m->queue_depth);
    break;
  case 1U:
    xtop_output_append(line, capacity, &used, "Tokens/s: prefill ");
    xtop_output_append_u64(line, capacity, &used, m->prefill_tokens_per_second);
    xtop_output_append(line, capacity, &used, "  decode ");
    xtop_output_append_u64(line, capacity, &used, m->decode_tokens_per_second);
    break;
  case 2U:
    xtop_output_append(line, capacity, &used, "First token: ");
    xtop_output_append_u64(line, capacity, &used, m->time_to_first_token_ns / 1000000U);
    xtop_output_append(line, capacity, &used, " ms  Completed: ");
    xtop_output_append_u64(line, capacity, &used, m->requests_completed);
    xtop_output_append(line, capacity, &used, "  Failed: ");
    xtop_output_append_u64(line, capacity, &used, m->requests_failed);
    break;
  case 3U:
    xtop_output_append(line, capacity, &used, "Model resident: ");
    xtop_output_append_u64(line, capacity, &used, m->model_resident_bytes / 1048576U);
    xtop_output_append(line, capacity, &used, "M  KV cache: ");
    xtop_output_append_u64(line, capacity, &used, m->kv_cache_bytes / 1048576U);
    xtop_output_append(line, capacity, &used, "M  Workers: ");
    xtop_output_append_u64(line, capacity, &used, m->worker_count);
    break;
  default:
    break;
  }
}

void xtop_render_netdisk_line(const xtop_extras_t *extras, char *line,
                              uint64_t capacity, uint32_t row) {
  uint64_t used = 0U;
  const xaios_control_metrics_payload_user_t *m = &extras->metrics;
  line[0] = '\0';
  if (extras->have_metrics == 0) {
    if (row == 0U) xtop_output_append(line, capacity, &used, "metrics query unavailable");
    return;
  }
  switch (row) {
  case 0U:
    xtop_output_append(line, capacity, &used, "Net: \xe2\x86\x91 ");
    xtop_append_rate(line, capacity, &used, extras->tx_bytes_per_s);
    xtop_output_append(line, capacity, &used, "  \xe2\x86\x93 ");
    xtop_append_rate(line, capacity, &used, extras->rx_bytes_per_s);
    break;
  case 1U:
    xtop_output_append(line, capacity, &used, "Packets: rx ");
    xtop_output_append_u64(line, capacity, &used, m->network_rx_packets);
    xtop_output_append(line, capacity, &used, "  tx ");
    xtop_output_append_u64(line, capacity, &used, m->network_tx_packets);
    xtop_output_append(line, capacity, &used, "  errors ");
    xtop_output_append_u64(line, capacity, &used, m->network_errors);
    break;
  case 2U:
    xtop_output_append(line, capacity, &used, "Disk I/O: R ");
    xtop_output_append_u64(line, capacity, &used, extras->reads_per_s);
    xtop_output_append(line, capacity, &used, "/s  W ");
    xtop_output_append_u64(line, capacity, &used, extras->writes_per_s);
    xtop_output_append(line, capacity, &used, "/s  (");
    xtop_output_append_u64(line, capacity, &used, m->storage_reads);
    xtop_output_append(line, capacity, &used, " reads, ");
    xtop_output_append_u64(line, capacity, &used, m->storage_writes);
    xtop_output_append(line, capacity, &used, " writes)");
    break;
  case 3U:
    xtop_output_append(line, capacity, &used, "Log buffer: ");
    xtop_output_append_u64(line, capacity, &used, m->log_buffer_bytes / 1024U);
    xtop_output_append(line, capacity, &used, "K  overflows ");
    xtop_output_append_u64(line, capacity, &used, m->log_overflows);
    break;
  default:
    break;
  }
}

/* A panel\'s vertical edge. */
void xtop_draw_edge(xtop_canvas_t *cv) {
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_text(cv, XTOP_BOX_V);
}

static xtop_style_t xtop_meter_style(uint64_t tenths) {
  if (tenths >= 850U) return XTOP_STYLE_HOT;
  if (tenths >= 600U) return XTOP_STYLE_WARM;
  return XTOP_STYLE_COOL;
}

void xtop_render_meter(xtop_canvas_t *cv, const char *label,
                       uint32_t label_columns, uint64_t tenths,
                       uint32_t bar_width, uint32_t cell_width) {
  /* Columns, not bytes. The block and shade glyphs are three bytes each and
     one column each, and every width below is a column count. The total is
     label + 1 + bar + 2 + 6 + 1: the percentage is six columns because
     "100.0%" is six characters, and it was budgeted as five, which made every
     meter row one column wider than the terminal. A row that is one column too
     wide wraps -- on a real terminal that is a blank line under every meter,
     and the same picture on the framebuffer console, which the local console
     comparison caught. */
  uint32_t label_width = (uint32_t)xtop_cstr_len(label);
  uint32_t visible = label_columns + bar_width + XTOP_METER_OVERHEAD;
  uint64_t filled64 = (tenths * bar_width + 999U) / 1000U;
  uint32_t filled = filled64 > bar_width ? bar_width : (uint32_t)filled64;
  xtop_canvas_style(cv, XTOP_STYLE_FG);
  if (label_width < label_columns) {
    xtop_canvas_repeat(cv, ' ', label_columns - label_width);
  }
  xtop_canvas_text(cv, label);
  xtop_canvas_text(cv, " ");
  xtop_canvas_style(cv, xtop_meter_style(tenths));
  xtop_canvas_repeat_str(cv, XTOP_BAR_FULL, filled);
  xtop_canvas_style(cv, XTOP_STYLE_EMPTY);
  xtop_canvas_repeat_str(cv, XTOP_BAR_EMPTY, bar_width - filled);
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_text(cv, "  ");
  xtop_canvas_style(cv, XTOP_STYLE_TITLE);
  xtop_canvas_percent_width(cv, tenths);
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_text(cv, " ");
  if (visible < cell_width) xtop_canvas_repeat(cv, ' ', cell_width - visible);
}
