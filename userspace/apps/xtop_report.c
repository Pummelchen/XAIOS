#include "xtop_snapshot.h"

typedef struct xaios_cpu_state {
  uint32_t online;
  uint32_t role;
} xaios_cpu_state_t;
static xaios_control_runtime_cpu_record_user_t
    g_cpu_records[XAIOS_XTOP_CPU_PAGE_MAX];
static uint32_t g_cpu_record_start;
static uint32_t g_cpu_record_count;
static uint32_t g_load_average[3];
void xtop_load_average_hundredths(uint32_t output[3]) {
  output[0] = g_load_average[0];
  output[1] = g_load_average[1];
  output[2] = g_load_average[2];
}
int xtop_user_cpu_usage_snapshot(uint32_t ordinal, uint64_t now_ns,
                                   xaios_cpu_usage_snapshot_t *usage) {
  (void)now_ns;
  if (usage == 0 || ordinal < g_cpu_record_start ||
      ordinal - g_cpu_record_start >= g_cpu_record_count)
    return XAIOS_ERR_NOT_FOUND;
  const xaios_control_runtime_cpu_record_user_t *record =
      &g_cpu_records[ordinal - g_cpu_record_start];
  usage->cpu_id = record->cpu_id;
  usage->active_pid = record->active_pid;
  usage->busy_ns = record->busy_ns;
  usage->elapsed_ns = record->elapsed_ns;
  return XAIOS_OK;
}
static const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  static xaios_cpu_state_t state;
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    if (g_cpu_records[i].cpu_id == cpu_id) {
      state.online = g_cpu_records[i].role != XAIOS_RUNTIME_CPU_OFFLINE;
      state.role = g_cpu_records[i].role;
      return &state;
    }
  }
  return 0;
}
static const char *xtop_cpu_role_name(uint32_t cpu_id) {
  const xaios_cpu_state_t *state = smp_cpu_state(cpu_id);
  if (state == 0 || state->online == 0U) {
    return "offline";
  }
  switch (state->role) {
  case XAIOS_CPU_ROLE_HOUSEKEEPING:
    return "housekeeping";
  case XAIOS_CPU_ROLE_SCHEDULING:
    return "scheduling";
  case XAIOS_CPU_ROLE_AI_HOT:
    return "ai-hot";
  default:
    return "offline";
  }
}
static xtop_extras_t g_extras;
static void history_push16(uint16_t *history, uint16_t value) {
  for (uint32_t i = 1U; i < XTOP_HISTORY; ++i) history[i - 1U] = history[i];
  history[XTOP_HISTORY - 1U] = value;
}
static void history_push32(uint32_t *history, uint32_t value) {
  for (uint32_t i = 1U; i < XTOP_HISTORY; ++i) history[i - 1U] = history[i];
  history[XTOP_HISTORY - 1U] = value;
}
/* Every few frames, the figures the frame carries besides the process
   table; rates need a previous sample, so the first frame has none. */
void xtop_serve_update_extras(uint64_t now_ns, uint64_t *last_ns,
                              xaios_control_metrics_payload_user_t *last,
                              int *have_last, uint32_t window_ms) {
  if (g_extras.have_hardware == 0) {
    g_extras.have_hardware =
        xtop_snapshot_simple_query(XAIOS_CONTROL_OP_HARDWARE,
                             XAIOS_CONTROL_PAYLOAD_HARDWARE, &g_extras.hardware,
                             sizeof(g_extras.hardware)) == 0;
  }
  if (*last_ns != 0U && now_ns - *last_ns < (uint64_t)window_ms * 1000000U) return;
  xaios_control_metrics_payload_user_t fresh;
  if (xtop_snapshot_simple_query(XAIOS_CONTROL_OP_METRICS, XAIOS_CONTROL_PAYLOAD_METRICS,
                           &fresh, sizeof(fresh)) != 0) {
    return;
  }
  g_extras.have_metrics = 1;
  g_extras.metrics = fresh;
  if (*have_last != 0 && now_ns > *last_ns) {
    uint64_t elapsed_ns = now_ns - *last_ns;
#define RATE(field) ((fresh.field >= last->field && fresh.field != UINT64_MAX) \
                         ? ((fresh.field - last->field) * UINT64_C(1000000000)) / elapsed_ns : 0U)
    g_extras.rx_bytes_per_s = RATE(network_rx_bytes);
    g_extras.tx_bytes_per_s = RATE(network_tx_bytes);
    g_extras.reads_per_s = RATE(storage_reads);
    g_extras.writes_per_s = RATE(storage_writes);
    g_extras.inferences_per_s = RATE(requests_completed);
#undef RATE
    g_extras.have_rates = 1;
    uint64_t kbps = (g_extras.rx_bytes_per_s + g_extras.tx_bytes_per_s) / 1024U;
    history_push32(g_extras.net_history, kbps > UINT32_MAX ? UINT32_MAX : (uint32_t)kbps);
  }
  *last = fresh;
  *last_ns = now_ns;
  *have_last = 1;
}
void xtop_serve_push_load_history(uint16_t cpu_tenths, uint16_t mem_tenths) {
  history_push16(g_extras.cpu_history, cpu_tenths);
  history_push16(g_extras.mem_history, mem_tenths);
  if (g_extras.history_count < XTOP_HISTORY) ++g_extras.history_count;
}
xaios_status_t xtop_handle(const char *args, char *output,
                           uint64_t output_capacity,
                           uint64_t *output_bytes) {
  static uint64_t before_runtime[XAIOS_XTOP_MAX_PROCESSES + 1U];
  static xaios_control_runtime_process_record_user_t
      process_records[XAIOS_XTOP_MAX_PROCESSES];
  static xtop_process_row_t rows[XAIOS_XTOP_MAX_PROCESSES];
  static xaios_control_runtime_cpu_record_user_t
      before_cpus[XAIOS_XTOP_CPU_PAGE_MAX];
  xaios_control_runtime_snapshot_payload_user_t before_meta;
  xaios_control_runtime_snapshot_payload_user_t after_meta;
  char option[24];
  char filter[32];
  uint64_t index = 0U;
  uint32_t before_process_count = 0U;
  uint32_t after_process_count = 0U;
  uint32_t before_cpu_count = 0U;
  uint32_t cpu_start = 0U;
  uint32_t cpu_requested = UINT32_MAX;
  uint32_t process_start = 0U;
  uint32_t selected = 0U;
  uint32_t sample_ms = 250U;
  uint32_t refresh_ms = 0U; /* the session's redraw cadence, shown only */
  uint32_t layout = 1U;
  int serve_frame = 0;      /* a frame of a serving session: no wait */
  uint32_t terminal_columns = 120U;
  uint32_t terminal_rows = 40U;
  uint32_t cpu_total;
  uint32_t cpu_shown;
  uint32_t process_count = 0U;
  uint32_t process_shown = 0U;
  int show_all = 1;
  int show_cpus = 1;
  int color_output = 0;
  int reverse = 0;
  int interactive = 0;
  xtop_sort_key_t sort_key = XTOP_SORT_CPU;

  filter[0] = '\0';
  while (xtop_token_next(args, &index, option, sizeof(option)) == XAIOS_OK) {
    if (xtop_string_equal(option, "--all")) show_all = 1;
    else if (xtop_string_equal(option, "--active")) show_all = 0;
    else if (xtop_string_equal(option, "--no-cpus")) show_cpus = 0;
    else if (xtop_string_equal(option, "--color")) color_output = 1;
    else if (xtop_string_equal(option, "--plain")) color_output = 0;
    else if (xtop_string_equal(option, "--interactive")) {
      interactive = 1;
      color_output = 1;
    } else if (xtop_string_equal(option, "--reverse")) reverse = 1;
    else if (xtop_string_equal(option, "--tree")) sort_key = XTOP_SORT_PARENT;
    else if (xtop_string_equal(option, "--sort")) {
      if (xtop_parse_sort_option(args, &index, &sort_key) != XAIOS_OK)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --sort key");
    } else if (xtop_string_equal(option, "--filter")) {
      if (xtop_token_next(args, &index, filter, sizeof(filter)) != XAIOS_OK)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --filter");
    } else if (xtop_string_equal(option, "--process-start")) {
      if (xtop_parse_u32_option(args, &index, &process_start) != XAIOS_OK)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --process-start");
    } else if (xtop_string_equal(option, "--selected")) {
      if (xtop_parse_u32_option(args, &index, &selected) != XAIOS_OK)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --selected");
    } else if (xtop_string_equal(option, "--serve-frame")) {
      serve_frame = 1;
    } else if (xtop_string_equal(option, "--layout")) {
      if (xtop_parse_u32_option(args, &index, &layout) != XAIOS_OK ||
          layout == 0U || layout > XTOP_LAYOUT_COUNT)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: --layout must be 1..3");
    } else if (xtop_string_equal(option, "--refresh-ms")) {
      if (xtop_parse_u32_option(args, &index, &refresh_ms) != XAIOS_OK ||
          refresh_ms > 60000U)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: --refresh-ms must be 0..60000");
    } else if (xtop_string_equal(option, "--columns")) {
      if (xtop_parse_u32_option(args, &index, &terminal_columns) != XAIOS_OK ||
          terminal_columns < 40U || terminal_columns > 240U)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: --columns must be 40..240");
    } else if (xtop_string_equal(option, "--rows")) {
      if (xtop_parse_u32_option(args, &index, &terminal_rows) != XAIOS_OK ||
          terminal_rows < 12U || terminal_rows > 100U)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: --rows must be 12..100");
    } else if (xtop_string_equal(option, "--cpu-start")) {
      if (xtop_parse_u32_option(args, &index, &cpu_start) != XAIOS_OK)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --cpu-start");
    } else if (xtop_string_equal(option, "--cpu-count")) {
      if (xtop_parse_u32_option(args, &index, &cpu_requested) != XAIOS_OK ||
          cpu_requested == 0U)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --cpu-count");
    } else if (xtop_string_equal(option, "--sample-ms")) {
      if (xtop_parse_u32_option(args, &index, &sample_ms) != XAIOS_OK ||
          sample_ms == 0U || sample_ms > 1000U)
        return xtop_command_fail(output, output_capacity, output_bytes,
                            "xtop: --sample-ms must be 1..1000");
    } else if (xtop_string_equal(option, "--help")) {
      xtop_output_append(output, output_capacity, output_bytes,
          "xtop [--active|--all] [--sample-ms 1..1000] [--cpu-start N] "
          "[--cpu-count N] [--no-cpus] [--color|--plain] "
          "[--columns 40..240] [--rows 12..100] "
          "[--sort cpu|mem|time|pid|state|syscalls|command|parent] "
          "[--reverse] [--tree] [--filter TEXT] [--process-start N] "
          "[--selected N]\n");
      return XAIOS_OK;
    } else {
      return xtop_command_fail(output, output_capacity, output_bytes,
                          "xtop: unsupported option; use xtop --help");
    }
  }

  if (xtop_snapshot_gather_snapshot(cpu_start, show_cpus != 0 ? cpu_requested : 0U,
                      before_cpus, XAIOS_XTOP_CPU_PAGE_MAX, &before_cpu_count,
                      process_records, XAIOS_XTOP_MAX_PROCESSES,
                      before_runtime, &before_process_count,
                      &before_meta) != 0)
    return xtop_command_fail(output, output_capacity, output_bytes,
                        "xtop: runtime snapshot unavailable");
  (void)before_process_count;
  cpu_total = before_meta.cpu_total;
  if (cpu_start > cpu_total) cpu_start = cpu_total;
  cpu_shown = cpu_total - cpu_start;
  if (cpu_shown > cpu_requested) cpu_shown = cpu_requested;
  if (cpu_shown > XAIOS_XTOP_CPU_PAGE_MAX)
    cpu_shown = XAIOS_XTOP_CPU_PAGE_MAX;
  if (color_output != 0) {
    uint32_t label_columns = 3U;
    if (cpu_total != 0U &&
        xtop_u64_digits((uint64_t)cpu_total - 1U) > label_columns)
      label_columns = (uint32_t)xtop_u64_digits((uint64_t)cpu_total - 1U);
    uint32_t visual_budget = xtop_cpu_page_capacity(
        terminal_columns, terminal_rows, label_columns);
    if (cpu_shown > visual_budget) cpu_shown = visual_budget;
  } else {
    uint32_t output_budget = output_capacity > 1024U
                                 ? (uint32_t)((output_capacity - 1024U) / 72U)
                                 : 1U;
    if (cpu_shown > output_budget) cpu_shown = output_budget;
  }
  if (show_cpus == 0) cpu_shown = 0U;
  /* The CPUs came with the processes; more of them than the page shows
     are dropped, and a page wider than one reply is fetched whole. */
  if (before_cpu_count > cpu_shown) before_cpu_count = cpu_shown;
  if (before_cpu_count < cpu_shown &&
      xtop_snapshot_gather_cpu_page(cpu_start, cpu_shown, before_cpus,
                      XAIOS_XTOP_CPU_PAGE_MAX, &before_cpu_count,
                      &before_meta) != 0)
    return xtop_command_fail(output, output_capacity, output_bytes,
                        "xtop: CPU snapshot unavailable");

  int have_retained = 0;
  if (serve_frame != 0)
    have_retained = xtop_snapshot_ring_has(
        before_meta.sampled_at_ns,
        (uint64_t)sample_ms * UINT64_C(1000000), cpu_start);
  if (have_retained != 0) {
    /* The sample just taken is this frame's "after"; the retained one is
       its "before". No wait: the window already elapsed while earlier
       frames were drawn. */
    after_meta = before_meta;
    after_process_count = before_process_count;
    g_cpu_record_count = before_cpu_count;
    xaios_memcpy(g_cpu_records, before_cpus,
                 sizeof(before_cpus[0]) * before_cpu_count);
    (void)xtop_snapshot_ring_read(
        before_meta.sampled_at_ns, (uint64_t)sample_ms * UINT64_C(1000000),
        cpu_start, &before_meta, before_runtime,
        (uint32_t)(sizeof(before_runtime) / sizeof(before_runtime[0])),
        before_cpus, XAIOS_XTOP_CPU_PAGE_MAX, &before_cpu_count);
  } else {
    if (xtop_snapshot_wait(sample_ms) != 0)
      return xtop_command_fail(output, output_capacity, output_bytes,
                               "xtop: sample wait failed");
    if (xtop_snapshot_gather_snapshot(cpu_start, cpu_shown, g_cpu_records,
                                      XAIOS_XTOP_CPU_PAGE_MAX,
                                      &g_cpu_record_count, process_records,
                                      XAIOS_XTOP_MAX_PROCESSES, 0,
                                      &after_process_count, &after_meta) != 0)
      return xtop_command_fail(output, output_capacity, output_bytes,
                               "xtop: runtime snapshot unavailable");
  }
  if (serve_frame != 0) {
    xtop_snapshot_ring_push(&after_meta, process_records, after_process_count,
                            g_cpu_records, g_cpu_record_count, cpu_start);
  }

  g_cpu_record_start = cpu_start;
  g_load_average[0] = after_meta.load_average_hundredths[0];
  g_load_average[1] = after_meta.load_average_hundredths[1];
  g_load_average[2] = after_meta.load_average_hundredths[2];
  uint64_t before_ns = before_meta.sampled_at_ns;
  uint64_t after_ns = after_meta.sampled_at_ns;
  uint64_t elapsed_ns = after_ns > before_ns ? after_ns - before_ns : 1U;
  uint64_t before_cpu_values[XAIOS_XTOP_CPU_PAGE_MAX];
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i)
    before_cpu_values[i] =
        i < before_cpu_count ? before_cpus[i].busy_ns : g_cpu_records[i].busy_ns;

  for (uint32_t i = 0U; i < after_process_count; ++i) {
    xaios_control_runtime_process_record_user_t *process = &process_records[i];
    if ((show_all == 0 && xtop_state_active(process->state) == 0) ||
        (filter[0] != '\0' && !xtop_contains_substring(process->name, filter)))
      continue;
    xtop_process_row_t *row = &rows[process_count++];
    uint64_t before =
        process->pid <= XAIOS_XTOP_MAX_PROCESSES
            ? before_runtime[process->pid]
            : process->runtime_ns;
    uint64_t delta =
        process->runtime_ns >= before ? process->runtime_ns - before : 0U;
    row->pid = process->pid;
    row->parent_pid = process->parent_pid;
    row->cpu_id = process->cpu_id;
    row->state = process->state;
    row->cpu_tenths = xtop_ratio_tenths(delta, elapsed_ns);
    row->memory_tenths =
        xtop_ratio_tenths(process->resident_pages, after_meta.physical_pages);
    row->runtime_ns = process->runtime_ns;
    row->resident_pages = process->resident_pages;
    row->syscall_count = process->syscall_count;
    row->tree_depth = 0U;
    row->name = process->name;
  }
  if (sort_key == XTOP_SORT_PARENT) {
    xtop_snapshot_sort_rows(rows, process_count, XTOP_SORT_PID, reverse);
    if (xtop_snapshot_arrange_tree(rows, process_count) != 0)
      xtop_snapshot_sort_rows(rows, process_count, XTOP_SORT_PARENT, reverse);
  } else {
    xtop_snapshot_sort_rows(rows, process_count, sort_key, reverse);
  }
  if (process_start > process_count) process_start = process_count;
  if (process_count == 0U) selected = 0U;
  else if (selected >= process_count) selected = process_count - 1U;

  if (color_output != 0) {
    /* A serving frame goes straight into the screen's cells; a one-shot
       frame goes to the caller's buffer as text. */
    xtop_canvas_t canvas;
    if (serve_frame != 0) xtop_canvas_cells_init(&canvas);
    else xtop_canvas_text_init(&canvas, output, output_capacity, output_bytes);
    (void)xtop_render_color(
        &canvas, terminal_columns, terminal_rows,
        cpu_start, g_cpu_record_count, cpu_total, before_cpu_values, after_ns,
        elapsed_ns, after_meta.managed_pages, after_meta.free_pages,
        after_meta.process_active, after_meta.process_failed, rows,
        process_count, process_start, selected, sort_key, reverse, interactive,
        filter, refresh_ms, layout, serve_frame, &g_extras);
    return XAIOS_OK;
  }

  xtop_output_append(output, output_capacity, output_bytes, "XAIOS xtop sample_ms=");
  xtop_output_append_u64(output, output_capacity, output_bytes, sample_ms);
  xtop_output_append(output, output_capacity, output_bytes, " cpus=");
  xtop_output_append_u64(output, output_capacity, output_bytes, cpu_total);
  xtop_output_append(output, output_capacity, output_bytes, " tasks_active=");
  xtop_output_append_u64(output, output_capacity, output_bytes,
                    after_meta.process_active);
  xtop_output_append(output, output_capacity, output_bytes, " failed=");
  xtop_output_append_u64(output, output_capacity, output_bytes,
                    after_meta.process_failed);
  xtop_output_append(output, output_capacity, output_bytes, " sort=");
  xtop_output_append(output, output_capacity, output_bytes, xtop_sort_name(sort_key));
  xtop_output_append(output, output_capacity, output_bytes, " reverse=");
  xtop_output_append_u64(output, output_capacity, output_bytes, reverse != 0);
  if (filter[0] != '\0') {
    xtop_output_append(output, output_capacity, output_bytes, " filter=");
    xtop_output_append(output, output_capacity, output_bytes, filter);
  }
  xtop_output_append(output, output_capacity, output_bytes, "\nCPU all=");
  uint64_t busy_delta =
      after_meta.cpu_busy_total_ns >= before_meta.cpu_busy_total_ns
          ? after_meta.cpu_busy_total_ns - before_meta.cpu_busy_total_ns
          : 0U;
  uint64_t capacity_ns =
      elapsed_ns > UINT64_MAX / (cpu_total == 0U ? 1U : cpu_total)
          ? UINT64_MAX
          : elapsed_ns * (cpu_total == 0U ? 1U : cpu_total);
  xtop_append_percent(output, output_capacity, output_bytes,
                      xtop_capacity_tenths(busy_delta, capacity_ns));
  uint64_t used_pages =
      after_meta.managed_pages >= after_meta.free_pages
          ? after_meta.managed_pages - after_meta.free_pages
          : 0U;
  xtop_output_append(output, output_capacity, output_bytes, " MEM managed=");
  xtop_append_percent(output, output_capacity, output_bytes,
                      xtop_capacity_tenths(used_pages,
                                           after_meta.managed_pages));
  xtop_output_append(output, output_capacity, output_bytes, " pages=");
  xtop_output_append_u64(output, output_capacity, output_bytes, used_pages);
  xtop_output_append(output, output_capacity, output_bytes, "/");
  xtop_output_append_u64(output, output_capacity, output_bytes,
                    after_meta.managed_pages);
  xtop_output_append(output, output_capacity, output_bytes, " physical_pages=");
  xtop_output_append_u64(output, output_capacity, output_bytes,
                    after_meta.physical_pages);
  xtop_output_append(output, output_capacity, output_bytes, "\n");

  if (show_cpus != 0) {
    xtop_output_append(output, output_capacity, output_bytes,
                  "CPU CPU% BUSY_MS IDLE_MS ACTIVE ROLE\n");
    for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
      const xaios_control_runtime_cpu_record_user_t *cpu = &g_cpu_records[i];
      uint64_t delta = cpu->busy_ns >= before_cpu_values[i]
                           ? cpu->busy_ns - before_cpu_values[i]
                           : 0U;
      xtop_output_append_u64(output, output_capacity, output_bytes, cpu->cpu_id);
      xtop_output_append(output, output_capacity, output_bytes, " ");
      xtop_append_percent(output, output_capacity, output_bytes,
                          xtop_capacity_tenths(delta, elapsed_ns));
      xtop_output_append(output, output_capacity, output_bytes, " ");
      xtop_output_append_u64(output, output_capacity, output_bytes,
                        cpu->busy_ns / UINT64_C(1000000));
      xtop_output_append(output, output_capacity, output_bytes, " ");
      xtop_output_append_u64(output, output_capacity, output_bytes,
                        (cpu->elapsed_ns >= cpu->busy_ns
                             ? cpu->elapsed_ns - cpu->busy_ns
                             : 0U) /
                            UINT64_C(1000000));
      xtop_output_append(output, output_capacity, output_bytes, " ");
      xtop_output_append_u64(output, output_capacity, output_bytes, cpu->active_pid);
      xtop_output_append(output, output_capacity, output_bytes, " ");
      xtop_output_append(output, output_capacity, output_bytes,
                    xtop_cpu_role_name(cpu->cpu_id));
      xtop_output_append(output, output_capacity, output_bytes, "\n");
    }
    xtop_output_append(output, output_capacity, output_bytes, "cpu_shown=");
    xtop_output_append_u64(output, output_capacity, output_bytes,
                      g_cpu_record_count);
    xtop_output_append(output, output_capacity, output_bytes, " cpu_total=");
    xtop_output_append_u64(output, output_capacity, output_bytes, cpu_total);
    if (cpu_start + g_cpu_record_count < cpu_total) {
      xtop_output_append(output, output_capacity, output_bytes, " next_cpu_start=");
      xtop_output_append_u64(output, output_capacity, output_bytes,
                        cpu_start + g_cpu_record_count);
    }
    xtop_output_append(output, output_capacity, output_bytes, "\n");
  }

  xtop_output_append(output, output_capacity, output_bytes,
                "PID PPID S CPU% MEM% TIME_MS RES_KIB CPU SYSCALLS COMMAND\n");
  for (uint32_t i = process_start; i < process_count; ++i) {
    if (*output_bytes + 160U >= output_capacity) break;
    const xtop_process_row_t *row = &rows[i];
    xtop_output_append_u64(output, output_capacity, output_bytes, row->pid);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_output_append_u64(output, output_capacity, output_bytes, row->parent_pid);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_output_append(output, output_capacity, output_bytes,
                  xtop_state_name(row->state));
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_append_percent(output, output_capacity, output_bytes, row->cpu_tenths);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_append_percent(output, output_capacity, output_bytes,
                        row->memory_tenths);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_output_append_u64(output, output_capacity, output_bytes,
                      row->runtime_ns / UINT64_C(1000000));
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_output_append_u64(output, output_capacity, output_bytes,
                      row->resident_pages * 4U);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    if (row->cpu_id == UINT32_MAX)
      xtop_output_append(output, output_capacity, output_bytes, "-");
    else
      xtop_output_append_u64(output, output_capacity, output_bytes, row->cpu_id);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_output_append_u64(output, output_capacity, output_bytes,
                      row->syscall_count);
    xtop_output_append(output, output_capacity, output_bytes, " ");
    xtop_output_append(output, output_capacity, output_bytes, row->name);
    xtop_output_append(output, output_capacity, output_bytes, "\n");
    ++process_shown;
  }
  xtop_output_append(output, output_capacity, output_bytes, "process_shown=");
  xtop_output_append_u64(output, output_capacity, output_bytes, process_shown);
  xtop_output_append(output, output_capacity, output_bytes, " process_total=");
  xtop_output_append_u64(output, output_capacity, output_bytes, process_count);
  xtop_output_append(output, output_capacity, output_bytes, " process_start=");
  xtop_output_append_u64(output, output_capacity, output_bytes, process_start);
  if (process_start + process_shown < process_count)
    xtop_output_append(output, output_capacity, output_bytes, " truncated=1");
  xtop_output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}
