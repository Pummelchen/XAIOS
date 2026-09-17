#include "xtop_serve.h"

static u64 g_child_channel_id;
static uint8_t g_ipc_write[SSH_CHILD_IPC_HEADER_SIZE + SSH_CHILD_IPC_PAYLOAD_MAX];
static uint8_t g_ipc_read[SSH_CHILD_IPC_HEADER_SIZE + SSH_CHILD_IPC_PAYLOAD_MAX];
static uint32_t g_ipc_read_used;
static char g_serve_frame[XAIOS_XTOP_OUTPUT_BYTES];
static char g_serve_args[512];

typedef struct xtop_serve_state {
  uint32_t columns, rows, refresh_ms, sample_ms;
  uint32_t cpu_start, cpu_count, process_start, selected, layout;
  uint32_t filter_length;
  xtop_sort_key_t sort_key;
  int reverse, show_all, show_cpus, help, filter_mode;
  char filter[32];
} xtop_serve_state_t;

static void serve_pause_ms(uint32_t ms) {
  if (ms == 0U) ms = 1U;
  (void)xaios_sleep_ns((u64)ms * UINT64_C(1000000));
}

/* Written whole, however many channel frames that takes; a full channel is
   waited out rather than treated as an error, because sshd drains it as
   fast as it can and a frame is worth a millisecond. */
static const char k_invalid_sort[] = "xtop: invalid --sort key\r\n";

static int serve_write(const void *data, uint64_t length) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t offset = 0U;
  while (offset < length) {
    uint32_t chunk = (uint32_t)(length - offset);
    if (chunk > SSH_CHILD_IPC_PAYLOAD_MAX) chunk = SSH_CHILD_IPC_PAYLOAD_MAX;
    ssh_child_ipc_header(g_ipc_write, SSH_CHILD_IPC_OUTPUT, chunk);
    xaios_memcpy(g_ipc_write + SSH_CHILD_IPC_HEADER_SIZE, bytes + offset, chunk);
    /* A full channel is flow control, not failure: the link drains it as
       fast as it can, and on a slow one that is slower than frames are
       made. So this waits, backing off to twenty milliseconds, for as long
       as the channel is alive -- giving up after a fixed count exited the
       monitor on the slower machines with a dropped connection to show for
       it. Only a channel that is no longer running ends the wait. */
    uint32_t pause_ms = 1U;
    uint32_t attempts = 0U;
    (void)attempts;
    for (;;) {
      int rc = xaios_remote_login_child_write(
          g_child_channel_id, g_ipc_write, SSH_CHILD_IPC_HEADER_SIZE + chunk);
      if (rc == 0) break;
      /* Anything but a full ring means the channel is gone. */
      if (rc != XTOP_ERR_BUSY) return -1;
      ++attempts;
      serve_pause_ms(pause_ms);
      if (pause_ms < 20U) pause_ms *= 2U;
    }
    offset += chunk;
  }
  return 0;
}

static int serve_receive(void) {
  if (g_ipc_read_used == sizeof(g_ipc_read)) return -1;
  u64 size = 0U;
  if (xaios_remote_login_child_read(
          g_child_channel_id, g_ipc_read + g_ipc_read_used,
          sizeof(g_ipc_read) - g_ipc_read_used, &size) != 0 ||
      size > sizeof(g_ipc_read) - g_ipc_read_used)
    return -1;
  g_ipc_read_used += (uint32_t)size;
  return 0;
}

static int serve_next(uint32_t *type, uint8_t *output, uint32_t capacity,
                      uint32_t *length) {
  if (g_ipc_read_used < SSH_CHILD_IPC_HEADER_SIZE) return 1;
  if (ssh_child_ipc_read_u32(g_ipc_read) != SSH_CHILD_IPC_MAGIC) return -1;
  uint32_t payload_length = ssh_child_ipc_read_u32(g_ipc_read + 8U);
  if (payload_length > SSH_CHILD_IPC_PAYLOAD_MAX || payload_length > capacity)
    return -1;
  uint32_t frame_length = SSH_CHILD_IPC_HEADER_SIZE + payload_length;
  if (g_ipc_read_used < frame_length) return 1;
  *type = ssh_child_ipc_read_u32(g_ipc_read + 4U);
  *length = payload_length;
  if (payload_length != 0U)
    xaios_memcpy(output, g_ipc_read + SSH_CHILD_IPC_HEADER_SIZE, payload_length);
  uint32_t remaining = g_ipc_read_used - frame_length;
  for (uint32_t i = 0U; i < remaining; ++i)
    g_ipc_read[i] = g_ipc_read[frame_length + i];
  g_ipc_read_used = remaining;
  return 0;
}

static void serve_append(char *buffer, uint64_t capacity, uint64_t *used,
                         const char *text) {
  xtop_output_append(buffer, capacity, used, text);
}

static void serve_append_u32(char *buffer, uint64_t capacity, uint64_t *used,
                             uint32_t value) {
  xtop_output_append_u64(buffer, capacity, used, value);
}

/* The options xtop_handle reads, from the state this session keeps. */
static void serve_build_args(const xtop_serve_state_t *st) {
  uint64_t used = 0U;
  g_serve_args[0] = '\0';
  serve_append(g_serve_args, sizeof(g_serve_args), &used,
               "--serve-frame --color --interactive --sample-ms ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->sample_ms);
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --refresh-ms ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->sample_ms);
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --columns ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->columns);
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --rows ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->rows);
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --layout ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->layout);
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --sort ");
  serve_append(g_serve_args, sizeof(g_serve_args), &used, xtop_sort_name(st->sort_key));
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --cpu-start ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->cpu_start);
  if (st->cpu_count != UINT32_MAX) {
    serve_append(g_serve_args, sizeof(g_serve_args), &used, " --cpu-count ");
    serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->cpu_count);
  }
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --process-start ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->process_start);
  serve_append(g_serve_args, sizeof(g_serve_args), &used, " --selected ");
  serve_append_u32(g_serve_args, sizeof(g_serve_args), &used, st->selected);
  serve_append(g_serve_args, sizeof(g_serve_args), &used,
               st->show_all != 0 ? " --all" : " --active");
  if (st->show_cpus == 0) serve_append(g_serve_args, sizeof(g_serve_args), &used, " --no-cpus");
  if (st->reverse != 0) serve_append(g_serve_args, sizeof(g_serve_args), &used, " --reverse");
  if (st->filter[0] != '\0') {
    serve_append(g_serve_args, sizeof(g_serve_args), &used, " --filter ");
    serve_append(g_serve_args, sizeof(g_serve_args), &used, st->filter);
  }
}

/* The process rows a frame of this size shows: the same arithmetic the
   renderer does, so paging moves by exactly one screen. */
static uint32_t serve_process_page(const xtop_serve_state_t *st) {
  uint32_t gauge_rows = st->rows >= 30U ? 4U : 2U;
  uint32_t detail_rows = st->rows >= 20U ? 6U : 0U;
  uint32_t used = 1U + gauge_rows + 2U + detail_rows + 3U + 1U;
  return st->rows > used ? st->rows - used : 1U;
}

/* ---- Sending only what changed.
 *
 * A frame is rendered whole into a buffer, as before, and then read back
 * into a grid of cells -- glyph and attributes -- and compared with the
 * grid the terminal is known to show. What goes down the channel is the
 * cells that differ, each run positioned with a cursor move and preceded by
 * its attributes only when they change. A frame that changed nothing sends
 * nothing; a tick of the clock sends the clock. Sixty frames a second is
 * then a promise about latency, not a stream of screens: sshd encrypts a
 * few hundred bytes a frame instead of twenty-four kilobytes, and the
 * console draws a few cells instead of six thousand. */
static char g_diff[XAIOS_XTOP_OUTPUT_BYTES];

static int serve_render(xtop_serve_state_t *st) {
  uint64_t frame_bytes = 0U;
  g_serve_frame[0] = '\0';
  serve_build_args(st);
  if (xtop_handle(g_serve_args, g_serve_frame, sizeof(g_serve_frame),
                  &frame_bytes) != XAIOS_OK) {
    return -1;
  }
  /* The frame was drawn into the screen's cells; present what changed. A
     present that did not fit the buffer is finished by the next. */
  (void)frame_bytes;
  for (;;) {
    uint64_t diff_bytes = xtop_screen_take_diff(g_diff, sizeof(g_diff));
    if (diff_bytes == 0U) return 0;
    if (serve_write(g_diff, diff_bytes) != 0) return -1;
    if (xtop_screen_incomplete() == 0) return 0;
  }
}

static int serve_send_help(const xtop_serve_state_t *st) {
  static const char *const lines[] = {
      "Up/Down, j/k   select process        PgUp/PgDn  move one page",
      "P/M/T/N/S/C    sort CPU/memory/time/PID/syscalls/command",
      "F6             cycle sort key        I          reverse order",
      "F3 or /        enter name filter     F4 or x    clear filter",
      "F5 or t        process-tree view     L          next layout",
      "a              active/all tasks      1          toggle CPU meters",
      "[ and ]        previous/next CPU page",
      "- and +        slower/faster refresh (16..5000 ms; 60 frames/s at 16)",
      "r              refresh now           F10/q/Ctrl-C  quit",
      "",
      "Layouts: 1 gauges and cores, 2 platform and AI runtime, 3 history.",
      "XAIOS exposes read-only process telemetry: there is no kill or nice,",
      "because no safe process-control ABI exists yet.",
      "",
      "Press F1, h, Escape or q to return.",
  };
  uint64_t used = 0U;
  char *out = g_serve_frame;
  uint32_t width = st->columns;
  xtop_canvas_t cv;
  xtop_canvas_text_init(&cv, out, sizeof(g_serve_frame), &used);
  xtop_canvas_begin(&cv, 1);
  xtop_draw_rule(&cv, XTOP_BOX_TL, XTOP_BOX_TR, "XAIOS xtop help", 0, width);
  xtop_canvas_newline(&cv);
  uint32_t body = st->rows > 3U ? st->rows - 3U : 1U;
  for (uint32_t row = 0U; row < body; ++row) {
    xtop_draw_edge(&cv);
    const char *text = row < sizeof(lines) / sizeof(lines[0]) ? lines[row] : "";
    xtop_canvas_text(&cv, " ");
    xtop_draw_padded(&cv, XTOP_STYLE_FG, text, width >= 3U ? width - 3U : 0U);
    xtop_draw_edge(&cv);
    xtop_canvas_newline(&cv);
  }
  xtop_draw_rule(&cv, XTOP_BOX_BL, XTOP_BOX_BR, 0, 0, width);
  xtop_screen_invalidate();
  return serve_write(out, used);
}

static int serve_send_filter_prompt(const xtop_serve_state_t *st) {
  uint64_t used = 0U;
  char *out = g_serve_frame;
  char line[96];
  uint64_t line_used = 0U;
  uint32_t width = st->columns;
  xtop_canvas_t cv;
  xtop_canvas_text_init(&cv, out, sizeof(g_serve_frame), &used);
  xtop_canvas_begin(&cv, 0);
  xtop_draw_rule(&cv, XTOP_BOX_TL, XTOP_BOX_TR, "Process name filter", 0, width);
  xtop_canvas_newline(&cv);
  line[0] = '\0';
  xtop_output_append(line, sizeof(line), &line_used, " Filter: ");
  xtop_output_append(line, sizeof(line), &line_used, st->filter);
  xtop_draw_edge(&cv);
  xtop_draw_padded(&cv, XTOP_STYLE_TITLE, line, width >= 2U ? width - 2U : 0U);
  xtop_draw_edge(&cv);
  xtop_canvas_newline(&cv);
  xtop_draw_edge(&cv);
  xtop_draw_padded(&cv, XTOP_STYLE_FG,
                   " Type one token. Enter applies, Backspace edits, Escape cancels.",
                   width >= 2U ? width - 2U : 0U);
  xtop_draw_edge(&cv);
  xtop_canvas_newline(&cv);
  xtop_draw_rule(&cv, XTOP_BOX_BL, XTOP_BOX_BR, 0, 0, width);
  xtop_screen_invalidate();
  return serve_write(out, used);
}

/* One key, already stripped of its escape prefix by the caller. Returns 1
   when the frame should be redrawn, 2 to quit, 0 otherwise. */
static int serve_key(xtop_serve_state_t *st, uint8_t key, int *screen_changed) {
  if (st->filter_mode != 0) {
    if (key == 27U) {
      st->filter_mode = 0;
      return 1;
    }
    if (key == '\r' || key == '\n') {
      st->filter_mode = 0;
      st->process_start = 0U;
      st->selected = 0U;
      return 1;
    }
    if (key == 8U || key == 127U) {
      if (st->filter_length != 0U) st->filter[--st->filter_length] = '\0';
      *screen_changed = 1;
      return 0;
    }
    if (st->filter_length + 1U < sizeof(st->filter) &&
        ((key >= 'a' && key <= 'z') || (key >= 'A' && key <= 'Z') ||
         (key >= '0' && key <= '9') || key == '_' || key == '-' ||
         key == '.' || key == '/')) {
      st->filter[st->filter_length++] = (char)key;
      st->filter[st->filter_length] = '\0';
      *screen_changed = 1;
    }
    return 0;
  }
  if (st->help != 0) {
    if (key == 'h' || key == 'q' || key == 27U) {
      st->help = 0;
      return 1;
    }
    return 0;
  }
  if (key == 'q' || key == 3U) return 2;
  switch (key) {
  case 'h': st->help = 1; *screen_changed = 1; return 0;
  case '/': st->filter_mode = 1; st->filter_length = 0U; st->filter[0] = '\0';
            *screen_changed = 1; return 0;
  case 'x': st->filter_length = 0U; st->filter[0] = '\0'; st->process_start = 0U;
            st->selected = 0U; return 1;
  case 'j': ++st->selected;
            if (st->selected >= st->process_start + serve_process_page(st)) ++st->process_start;
            return 1;
  case 'k': if (st->selected != 0U) --st->selected;
            if (st->selected < st->process_start) st->process_start = st->selected;
            return 1;
  case 'D': { uint32_t page = serve_process_page(st); st->selected += page; st->process_start += page; return 1; }
  case 'U': { uint32_t page = serve_process_page(st);
              st->selected = st->selected > page ? st->selected - page : 0U;
              st->process_start = st->process_start > page ? st->process_start - page : 0U; return 1; }
  case 'P': st->sort_key = XTOP_SORT_CPU; return 1;
  case 'M': st->sort_key = XTOP_SORT_MEMORY; return 1;
  case 'T': st->sort_key = XTOP_SORT_TIME; return 1;
  case 'N': st->sort_key = XTOP_SORT_PID; return 1;
  case 'S': st->sort_key = XTOP_SORT_SYSCALLS; return 1;
  case 'C': st->sort_key = XTOP_SORT_COMMAND; return 1;
  case 'F': st->sort_key = (xtop_sort_key_t)(((uint32_t)st->sort_key + 1U) % 7U); return 1;
  case 'I': st->reverse ^= 1; return 1;
  case 't': st->sort_key = st->sort_key == XTOP_SORT_PARENT ? XTOP_SORT_CPU : XTOP_SORT_PARENT; return 1;
  case 'a': st->show_all ^= 1; return 1;
  case '1': st->show_cpus ^= 1; return 1;
  case 'l': case 'L': st->layout = st->layout % XTOP_LAYOUT_COUNT + 1U; return 1;
  case '[': { uint32_t page = st->cpu_count == UINT32_MAX ? 8U : st->cpu_count;
              st->cpu_start = st->cpu_start > page ? st->cpu_start - page : 0U; return 1; }
  case ']': { uint32_t page = st->cpu_count == UINT32_MAX ? 8U : st->cpu_count;
              if (UINT32_MAX - st->cpu_start >= page) st->cpu_start += page; return 1; }
  case '+': case '=': if (st->sample_ms > 16U) { st->sample_ms /= 2U; if (st->sample_ms < 16U) st->sample_ms = 16U; } return 1;
  case '-': if (st->sample_ms < 5000U) { st->sample_ms *= 2U; if (st->sample_ms > 5000U) st->sample_ms = 5000U; } return 1;
  case 'r': return 1;
  default: return 0;
  }
}

/* Keys as the terminal sends them: bare bytes, or escape sequences for the
   arrows, paging and function keys. A sequence split across two channel
   frames is kept until the rest arrives. */
static int serve_handle_input(xtop_serve_state_t *st, const uint8_t *data,
                              uint32_t length, int *redraw, int *screen_changed) {
  uint32_t offset = 0U;
  while (offset < length) {
    xaios_key_t decoded = XAIOS_KEY_NONE;
    uint32_t code = 0U;
    uint32_t consumed = xaios_screen_read_key(data + offset, length - offset,
                                              &decoded, &code);
    uint8_t key = 0U;
    if (consumed == 0U) return 0; /* a sequence cut by the read: wait */
    offset += consumed;
    switch (decoded) {
    case XAIOS_KEY_CHAR: key = code < 0x80U ? (uint8_t)code : 0U; break;
    case XAIOS_KEY_ENTER: key = '\r'; break;
    case XAIOS_KEY_BACKSPACE: key = 127U; break;
    case XAIOS_KEY_ESCAPE: key = 27U; break;
    case XAIOS_KEY_UP: key = 'k'; break;
    case XAIOS_KEY_DOWN: key = 'j'; break;
    case XAIOS_KEY_PAGE_UP: key = 'U'; break;
    case XAIOS_KEY_PAGE_DOWN: key = 'D'; break;
    case XAIOS_KEY_FUNCTION:
      if (code == 1U) key = 'h';
      else if (code == 3U) key = '/';
      else if (code == 4U) key = 'x';
      else if (code == 5U) key = 't';
      else if (code == 6U) key = 'F';
      else if (code == 10U) return 2;
      break;
    default: break;
    }
    if (key == 0U) continue;
    int result = serve_key(st, key, screen_changed);
    if (result == 2) return 2;
    if (result == 1) *redraw = 1;
  }
  return 0;
}

int xtop_serve(u64 channel_id, const char *command) {
  static uint8_t input[SSH_CHILD_IPC_PAYLOAD_MAX];
  xtop_serve_state_t st;
  xaios_control_metrics_payload_user_t last_metrics;
  uint64_t last_metrics_ns = 0U;
  int have_last_metrics = 0;
  uint64_t next_frame_ns = 0U;
  uint64_t last_history_ns = 0U;
  char option[24];
  char sort[24];
  uint64_t index = 0U;
  g_child_channel_id = channel_id;
  xtop_bytes_zero(&st, sizeof(st));
  xtop_bytes_zero(&last_metrics, sizeof(last_metrics));
  st.columns = 80U; st.rows = 24U; st.refresh_ms = 250U; st.sample_ms = 250U;
  st.cpu_count = UINT32_MAX; st.layout = 1U; st.sort_key = XTOP_SORT_CPU;
  st.show_all = 1; st.show_cpus = 1;
  /* The command the session built: the same options a one-shot run takes,
     read once into the state this session keeps. The first token is the
     program's own name. */
  (void)xtop_token_next(command, &index, option, sizeof(option));
  while (xtop_token_next(command, &index, option, sizeof(option)) == XAIOS_OK) {
    uint32_t value = 0U;
    if (xtop_string_equal(option, "--columns")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 40U && value <= 240U) st.columns = value; }
    else if (xtop_string_equal(option, "--rows")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 12U && value <= 100U) st.rows = value; }
    else if (xtop_string_equal(option, "--refresh-ms")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 16U && value <= 5000U) { st.refresh_ms = value; st.sample_ms = value; } }
    else if (xtop_string_equal(option, "--sample-ms")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 1U && value <= 1000U) st.sample_ms = value; }
    else if (xtop_string_equal(option, "--layout")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 1U && value <= XTOP_LAYOUT_COUNT) st.layout = value; }
    else if (xtop_string_equal(option, "--cpu-start")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK) st.cpu_start = value; }
    else if (xtop_string_equal(option, "--cpu-count")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value != 0U) st.cpu_count = value; }
    else if (xtop_string_equal(option, "--sort")) {
      /* Refused, not quietly ignored.
       *
       * This was tolerant -- a key it did not recognise left the sort on CPU
       * -- so `xtop --sort invalid` opened the monitor instead of saying
       * anything, and the person who mistyped it watched a screen sorted by
       * something they had not asked for. The one-shot path has always
       * refused the same input with the same words; a session is not a
       * reason to accept it. Refused here, before the alternate screen is
       * entered, so there is nothing to hand back. */
      xtop_sort_key_t key = XTOP_SORT_CPU;
      uint64_t dummy = 0U;
      char text[48];
      uint64_t tu = 0U;
      text[0] = '\0';
      if (xtop_token_next(command, &index, sort, sizeof(sort)) != XAIOS_OK) {
        (void)serve_write(k_invalid_sort, sizeof(k_invalid_sort) - 1U);
        return 1;
      }
      xtop_output_append(text, sizeof(text), &tu, "--sort ");
      xtop_output_append(text, sizeof(text), &tu, sort);
      if (xtop_parse_sort_option(text, &dummy, &key) != XAIOS_OK) {
        (void)serve_write(k_invalid_sort, sizeof(k_invalid_sort) - 1U);
        return 1;
      }
      st.sort_key = key;
    }
    else if (xtop_string_equal(option, "--reverse")) st.reverse = 1;
    else if (xtop_string_equal(option, "--tree")) st.sort_key = XTOP_SORT_PARENT;
    else if (xtop_string_equal(option, "--active")) st.show_all = 0;
    else if (xtop_string_equal(option, "--all")) st.show_all = 1;
    else if (xtop_string_equal(option, "--no-cpus")) st.show_cpus = 0;
    else if (xtop_string_equal(option, "--filter")) { if (xtop_token_next(command, &index, st.filter, sizeof(st.filter)) == XAIOS_OK) st.filter_length = (uint32_t)xtop_cstr_len(st.filter); }
  }
  xtop_arena_reset();
  xtop_screen_open(st.rows, st.columns);
  static const char enter[] = "\033[?1049h\033[?25l";
  if (serve_write(enter, sizeof(enter) - 1U) != 0) return 1;
  for (;;) {
    uint64_t now_ns = xaios_clock_nanos();
    int redraw = 0;
    int screen_changed = 0;
    int quit = 0;
    /* Keys first, so a keystroke is never a frame late. */
    if (serve_receive() != 0) { quit = 1; }
    for (;;) {
      uint32_t type = 0U;
      uint32_t length = 0U;
      int next = serve_next(&type, input, sizeof(input), &length);
      if (next != 0) { if (next < 0) quit = 1; break; }
      if (type != SSH_CHILD_IPC_INPUT) continue;
      if (serve_handle_input(&st, input, length, &redraw, &screen_changed) == 2) { quit = 1; break; }
    }
    if (quit != 0) break;
    /* A screen that changes only on a key waits for one. */
    if (st.help != 0) {
      if (screen_changed != 0 && serve_send_help(&st) != 0) break;
      if (xaios_wait_events(UINT64_C(1000000000)) < 0) serve_pause_ms(20U);
      continue;
    }
    if (st.filter_mode != 0) {
      if (screen_changed != 0 && serve_send_filter_prompt(&st) != 0) break;
      if (xaios_wait_events(UINT64_C(1000000000)) < 0) serve_pause_ms(20U);
      continue;
    }
    /* A new sample when the sampling interval has passed, or at once when
       a key changed what is shown; between samples the process sleeps, and
       a frame that changed nothing was not sent. Sixty frames a second is
       how soon a change is on the screen, not how often the screen is
       written. */
    if (redraw != 0 || now_ns >= next_frame_ns) {
      xtop_serve_update_extras(now_ns, &last_metrics_ns, &last_metrics,
                               &have_last_metrics, st.sample_ms);
      if (serve_render(&st) != 0) break;
      if (now_ns - last_history_ns >= (uint64_t)st.sample_ms * 1000000U) {
        xtop_serve_push_load_history(xtop_last_cpu_tenths(),
                                     xtop_last_mem_tenths());
        last_history_ns = now_ns;
      }
      next_frame_ns = xaios_clock_nanos() + (uint64_t)st.sample_ms * 1000000U;
      continue;
    }
    /* Until the next sample is due, or a key arrives on the channel --
       whichever is first. Polling the channel every sixteen milliseconds
       was most of what this process cost between samples. */
    if (xaios_wait_events(next_frame_ns - now_ns) < 0) serve_pause_ms(16U);
  }
  /* Length from the string, not written out beside it.
   *
   * It said 24 for a string of 29 bytes, so the last five never left -- the
   * client saw the restore stop mid-escape at "\033[?1049l\033[0m\033[" and
   * the belt-and-braces second copy was lost. The terminal came back anyway,
   * because the cursor is shown before the alternate screen is left, which is
   * why nothing noticed. A constant beside a literal is a constant that
   * drifts when the literal changes. */
  static const char restore[] = "\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r";
  (void)serve_write(restore, sizeof(restore) - 1U);
  return 0;
}
