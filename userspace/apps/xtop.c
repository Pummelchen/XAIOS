#include <xaios_user.h>
#include <xaios/types.h>

#define XAIOS_OK 0
#define XAIOS_ERR_INVALID (-1)
#define XAIOS_ERR_NOT_FOUND (-2)
#define XAIOS_ERR_NO_MEMORY (-3)

#define XAIOS_USER_PROCESS_LOADED XAIOS_RUNTIME_PROCESS_LOADED
#define XAIOS_USER_PROCESS_RUNNABLE XAIOS_RUNTIME_PROCESS_RUNNABLE
#define XAIOS_USER_PROCESS_RUNNING XAIOS_RUNTIME_PROCESS_RUNNING
#define XAIOS_USER_PROCESS_WAITING XAIOS_RUNTIME_PROCESS_WAITING
#define XAIOS_USER_PROCESS_EXITED XAIOS_RUNTIME_PROCESS_EXITED
#define XAIOS_USER_PROCESS_FAILED XAIOS_RUNTIME_PROCESS_FAILED
#define XAIOS_CPU_ROLE_HOUSEKEEPING XAIOS_RUNTIME_CPU_HOUSEKEEPING
#define XAIOS_CPU_ROLE_SCHEDULING XAIOS_RUNTIME_CPU_SCHEDULING
#define XAIOS_CPU_ROLE_AI_HOT XAIOS_RUNTIME_CPU_AI_HOT
#define XAIOS_XTOP_MAX_PROCESSES 1024U
#define XAIOS_XTOP_CPU_PAGE_MAX 256U
#define XAIOS_XTOP_OUTPUT_BYTES 32768U
#define XAIOS_XTOP_ARENA_BYTES 131072U

typedef int xaios_status_t;

typedef struct xaios_cpu_usage_snapshot {
  uint32_t cpu_id;
  uint32_t active_pid;
  uint64_t busy_ns;
  uint64_t elapsed_ns;
} xaios_cpu_usage_snapshot_t;

typedef struct xaios_cpu_state {
  uint32_t online;
  uint32_t role;
} xaios_cpu_state_t;

static xaios_control_runtime_cpu_record_user_t
    g_cpu_records[XAIOS_XTOP_CPU_PAGE_MAX];
static uint32_t g_cpu_record_start;
static uint32_t g_cpu_record_count;
static uint32_t g_load_average[3];
static unsigned char g_arena[XAIOS_XTOP_ARENA_BYTES];
static uint64_t g_arena_used;
static uint64_t g_request_id = 1U;

static void bytes_zero(void *buffer, uint64_t size) {
  unsigned char *bytes = (unsigned char *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
  if (alignment == 0U) return value;
  uint64_t remainder = value % alignment;
  return remainder == 0U ? value : value + alignment - remainder;
}

static void *kheap_calloc(uint64_t size, uint64_t alignment) {
  uint64_t offset = align_up(g_arena_used, alignment);
  if (offset > sizeof(g_arena) || size > sizeof(g_arena) - offset) return 0;
  void *result = &g_arena[offset];
  bytes_zero(result, size);
  g_arena_used = offset + size;
  return result;
}

static void kheap_free(void *pointer) { (void)pointer; }

static uint64_t cstr_len(const char *text) {
  uint64_t size = 0U;
  if (text == 0) return 0U;
  while (text[size] != '\0') ++size;
  return size;
}

static int string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

static int contains_substring(const char *text, const char *needle) {
  uint64_t needle_size = cstr_len(needle);
  if (needle_size == 0U) return 1;
  for (uint64_t i = 0U; text != 0 && text[i] != '\0'; ++i) {
    uint64_t j = 0U;
    while (j < needle_size && text[i + j] == needle[j]) ++j;
    if (j == needle_size) return 1;
  }
  return 0;
}

static uint64_t u64_digits(uint64_t value) {
  uint64_t digits = 1U;
  while (value >= 10U) {
    value /= 10U;
    ++digits;
  }
  return digits;
}

static xaios_status_t output_append_char(char *output, uint64_t capacity,
                                         uint64_t *offset, char value) {
  if (output == 0 || offset == 0 || *offset + 1U >= capacity)
    return XAIOS_ERR_NO_MEMORY;
  output[(*offset)++] = value;
  output[*offset] = '\0';
  return XAIOS_OK;
}

static xaios_status_t output_append(char *output, uint64_t capacity,
                                    uint64_t *offset, const char *text) {
  if (text == 0) return XAIOS_ERR_INVALID;
  while (*text != '\0') {
    if (output_append_char(output, capacity, offset, *text++) != XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static xaios_status_t output_append_u64(char *output, uint64_t capacity,
                                        uint64_t *offset, uint64_t value) {
  char digits[24];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U) {
    if (output_append_char(output, capacity, offset, digits[--count]) !=
        XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static xaios_status_t command_fail(char *output, uint64_t capacity,
                                   uint64_t *offset, const char *message) {
  (void)output_append(output, capacity, offset, message);
  (void)output_append(output, capacity, offset, "\n");
  return XAIOS_ERR_INVALID;
}

static uint64_t skip_ws(const char *text, uint64_t index) {
  while (text[index] == ' ' || text[index] == '\t' ||
         text[index] == '\r' || text[index] == '\n')
    ++index;
  return index;
}

static xaios_status_t token_next(const char *text, uint64_t *index,
                                 char *token, uint64_t capacity) {
  uint64_t used = 0U;
  uint64_t i;
  char quote = '\0';
  if (text == 0 || index == 0 || token == 0 || capacity == 0U)
    return XAIOS_ERR_INVALID;
  i = skip_ws(text, *index);
  if (text[i] == '\0') return XAIOS_ERR_NOT_FOUND;
  if (text[i] == '\'' || text[i] == '"') quote = text[i++];
  while (text[i] != '\0') {
    if (quote != '\0') {
      if (text[i] == quote) {
        ++i;
        break;
      }
    } else if (text[i] == ' ' || text[i] == '\t' ||
               text[i] == '\r' || text[i] == '\n') {
      break;
    }
    if (used + 1U >= capacity) return XAIOS_ERR_NO_MEMORY;
    token[used++] = text[i++];
  }
  token[used] = '\0';
  *index = skip_ws(text, i);
  return XAIOS_OK;
}

static xaios_status_t parse_u64_token(const char *text, uint64_t *value,
                                      uint64_t *consumed) {
  uint64_t parsed = 0U;
  uint64_t index = 0U;
  if (text == 0 || value == 0 || consumed == 0 ||
      text[0] < '0' || text[0] > '9')
    return XAIOS_ERR_INVALID;
  while (text[index] >= '0' && text[index] <= '9') {
    uint64_t digit = (uint64_t)(text[index] - '0');
    if (parsed > (UINT64_MAX - digit) / 10U) return XAIOS_ERR_INVALID;
    parsed = parsed * 10U + digit;
    ++index;
  }
  *value = parsed;
  *consumed = index;
  return XAIOS_OK;
}

static void scheduler_load_average_hundredths(uint32_t output[3]) {
  output[0] = g_load_average[0];
  output[1] = g_load_average[1];
  output[2] = g_load_average[2];
}

static int user_cpu_usage_snapshot(uint32_t ordinal, uint64_t now_ns,
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

static int runtime_query(
    uint32_t cpu_start, uint32_t cpu_limit, uint32_t process_start,
    uint32_t process_limit, uint32_t wait_ms,
    xaios_control_runtime_snapshot_payload_user_t *snapshot) {
  struct {
    xaios_control_request_header_user_t header;
    xaios_control_runtime_snapshot_request_user_t payload;
  } request;
  static union {
    u64 alignment;
    unsigned char bytes[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  } response;
  u64 response_size = 0U;
  bytes_zero(&request, sizeof(request));
  request.header.magic = XAIOS_CONTROL_MAGIC;
  request.header.version = XAIOS_CONTROL_VERSION;
  request.header.header_size = (u16)sizeof(request.header);
  request.header.operation = XAIOS_CONTROL_OP_RUNTIME_SNAPSHOT;
  request.header.payload_type = XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT_REQUEST;
  request.header.request_id = g_request_id++;
  request.header.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  request.header.payload_length = sizeof(request.payload);
  request.payload.cpu_start = cpu_start;
  request.payload.cpu_limit = cpu_limit;
  request.payload.process_start = process_start;
  request.payload.process_limit = process_limit;
  request.payload.wait_ms = wait_ms;
  if (xaios_control_query(&request, sizeof(request), response.bytes,
                          sizeof(response.bytes), &response_size) != 0 ||
      response_size < sizeof(xaios_control_response_header_user_t) +
                          sizeof(*snapshot))
    return -1;
  const xaios_control_response_header_user_t *header =
      (const xaios_control_response_header_user_t *)response.bytes;
  if (header->magic != XAIOS_CONTROL_MAGIC ||
      header->version != XAIOS_CONTROL_VERSION ||
      header->status != XAIOS_CONTROL_STATUS_OK ||
      header->payload_type != XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT ||
      header->payload_length != sizeof(*snapshot))
    return -1;
  xaios_memcpy(snapshot, response.bytes + sizeof(*header), sizeof(*snapshot));
  return 0;
}

static int gather_processes(
    xaios_control_runtime_process_record_user_t *records, uint32_t capacity,
    uint64_t *runtime_by_pid, uint32_t *count,
    xaios_control_runtime_snapshot_payload_user_t *metadata) {
  uint32_t cursor = 0U;
  *count = 0U;
  if (runtime_by_pid != 0)
    for (uint32_t i = 0U; i <= XAIOS_XTOP_MAX_PROCESSES; ++i)
      runtime_by_pid[i] = 0U;
  for (;;) {
    xaios_control_runtime_snapshot_payload_user_t page;
    if (runtime_query(0U, 0U, cursor, XAIOS_CONTROL_RUNTIME_PROCESS_MAX, 0U,
                      &page) != 0)
      return -1;
    *metadata = page;
    for (uint32_t i = 0U; i < page.process_count; ++i) {
      const xaios_control_runtime_process_record_user_t *source =
          &page.processes[i];
      if (source->pid <= XAIOS_XTOP_MAX_PROCESSES && runtime_by_pid != 0)
        runtime_by_pid[source->pid] = source->runtime_ns;
      if (*count < capacity) records[(*count)++] = *source;
    }
    if (page.process_next == UINT32_MAX) break;
    if (page.process_next <= cursor) return -1;
    cursor = page.process_next;
  }
  return 0;
}

static int gather_cpu_page(
    uint32_t cpu_start, uint32_t cpu_count,
    xaios_control_runtime_cpu_record_user_t *records, uint32_t capacity,
    uint32_t *record_count,
    xaios_control_runtime_snapshot_payload_user_t *metadata) {
  uint32_t cursor = cpu_start;
  *record_count = 0U;
  while (*record_count < cpu_count && *record_count < capacity) {
    uint32_t limit = cpu_count - *record_count;
    if (limit > XAIOS_CONTROL_RUNTIME_CPU_MAX)
      limit = XAIOS_CONTROL_RUNTIME_CPU_MAX;
    xaios_control_runtime_snapshot_payload_user_t page;
    if (runtime_query(cursor, limit, 0U, 0U, 0U, &page) != 0) return -1;
    *metadata = page;
    for (uint32_t i = 0U; i < page.cpu_count && *record_count < capacity; ++i)
      records[(*record_count)++] = page.cpus[i];
    if (page.cpu_next == UINT32_MAX || page.cpu_next <= cursor) break;
    cursor = page.cpu_next;
  }
  return 0;
}

static const char *xtop_state_name(uint32_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_LOADED:
    return "loaded";
  case XAIOS_USER_PROCESS_RUNNABLE:
    return "runnable";
  case XAIOS_USER_PROCESS_RUNNING:
    return "running";
  case XAIOS_USER_PROCESS_WAITING:
    return "waiting";
  case XAIOS_USER_PROCESS_EXITED:
    return "exited";
  case XAIOS_USER_PROCESS_FAILED:
    return "failed";
  default:
    return "unknown";
  }
}

static int xtop_state_active(uint32_t state) {
  return state == XAIOS_USER_PROCESS_LOADED ||
         state == XAIOS_USER_PROCESS_RUNNABLE ||
         state == XAIOS_USER_PROCESS_RUNNING ||
         state == XAIOS_USER_PROCESS_WAITING;
}

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

typedef enum xtop_sort_key {
  XTOP_SORT_CPU = 0,
  XTOP_SORT_MEMORY,
  XTOP_SORT_TIME,
  XTOP_SORT_PID,
  XTOP_SORT_STATE,
  XTOP_SORT_SYSCALLS,
  XTOP_SORT_COMMAND,
  XTOP_SORT_PARENT
} xtop_sort_key_t;

static const char *xtop_sort_name(xtop_sort_key_t key) {
  switch (key) {
  case XTOP_SORT_MEMORY:
    return "mem";
  case XTOP_SORT_TIME:
    return "time";
  case XTOP_SORT_PID:
    return "pid";
  case XTOP_SORT_STATE:
    return "state";
  case XTOP_SORT_SYSCALLS:
    return "syscalls";
  case XTOP_SORT_COMMAND:
    return "command";
  case XTOP_SORT_PARENT:
    return "parent";
  default:
    return "cpu";
  }
}

static int xtop_name_compare(const char *lhs, const char *rhs) {
  uint32_t index = 0U;
  while (lhs[index] != '\0' && rhs[index] != '\0' &&
         lhs[index] == rhs[index]) {
    ++index;
  }
  return (int)(uint8_t)lhs[index] - (int)(uint8_t)rhs[index];
}

static uint64_t xtop_ratio_tenths(uint64_t numerator,
                                  uint64_t denominator) {
  if (denominator == 0U || numerator == 0U) {
    return 0U;
  }
  if (numerator > UINT64_MAX / UINT64_C(1000)) {
    numerator /= UINT64_C(1000);
    denominator /= UINT64_C(1000);
    if (denominator == 0U) {
      return UINT64_C(1000);
    }
  }
  return (numerator * UINT64_C(1000)) / denominator;
}

static uint64_t xtop_capacity_tenths(uint64_t numerator,
                                     uint64_t denominator) {
  uint64_t tenths = xtop_ratio_tenths(numerator, denominator);
  return tenths > UINT64_C(1000) ? UINT64_C(1000) : tenths;
}

static void xtop_append_percent(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint64_t tenths) {
  output_append_u64(output, output_capacity, output_bytes, tenths / 10U);
  output_append(output, output_capacity, output_bytes, ".");
  output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  output_append(output, output_capacity, output_bytes, "%");
}

static void xtop_append_repeat(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes, char value,
                               uint32_t count) {
  for (uint32_t i = 0U; i < count; ++i) {
    if (output_append_char(output, output_capacity, output_bytes, value) !=
        XAIOS_OK) {
      return;
    }
  }
}

static void xtop_append_u64_width(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, uint64_t value,
                                  uint32_t width) {
  uint64_t digits = u64_digits(value);
  if (digits < width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - (uint32_t)digits);
  }
  output_append_u64(output, output_capacity, output_bytes, value);
}

static void xtop_append_percent_width(char *output, uint64_t output_capacity,
                                      uint64_t *output_bytes,
                                      uint64_t tenths) {
  uint64_t whole = tenths / 10U;
  uint64_t digits = u64_digits(whole);
  if (digits < 3U) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       3U - (uint32_t)digits);
  }
  output_append_u64(output, output_capacity, output_bytes, whole);
  output_append(output, output_capacity, output_bytes, ".");
  output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  output_append(output, output_capacity, output_bytes, "%");
}

static void xtop_append_bounded(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, const char *text,
                                uint32_t width) {
  uint32_t used = 0U;
  while (text[used] != '\0' && used < width) {
    if (output_append_char(output, output_capacity, output_bytes, text[used]) !=
        XAIOS_OK) {
      return;
    }
    ++used;
  }
}

static void xtop_append_ansi_line(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, const char *style,
                                  const char *text, uint32_t columns) {
  uint32_t visible = (uint32_t)cstr_len(text);
  if (visible > columns) visible = columns;
  output_append(output, output_capacity, output_bytes, style);
  xtop_append_bounded(output, output_capacity, output_bytes, text, columns);
  if (visible < columns) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       columns - visible);
  }
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
}

/* The box-drawing and block glyphs the panels are built from.
 *
 * UTF-8, deliberately. xtop is reached over SSH, where the client's terminal
 * draws these; the local framebuffer console has a sixty-four glyph
 * uppercase-only font and is a boot and status display rather than somewhere
 * a process monitor is read. Bending the design to that font would cost the
 * look everywhere to gain nothing anywhere. */
#define XTOP_BAR_FULL "\xe2\x96\x88"  /* U+2588 FULL BLOCK */
#define XTOP_BAR_EMPTY "\xe2\x96\x91" /* U+2591 LIGHT SHADE */
#define XTOP_BOX_H "\xe2\x94\x80"     /* U+2500 */
#define XTOP_BOX_V "\xe2\x94\x82"     /* U+2502 */
#define XTOP_BOX_TL "\xe2\x94\x8c"    /* U+250C */
#define XTOP_BOX_TR "\xe2\x94\x90"    /* U+2510 */
#define XTOP_BOX_BL "\xe2\x94\x94"    /* U+2514 */
#define XTOP_BOX_BR "\xe2\x94\x98"    /* U+2518 */

/* Repeat a string rather than a byte: a glyph here is three bytes wide and
   one column wide, and the layout arithmetic counts columns. */
static void xtop_append_repeat_str(char *output, uint64_t output_capacity,
                                   uint64_t *output_bytes, const char *glyph,
                                   uint32_t count) {
  for (uint32_t i = 0U; i < count; ++i) {
    output_append(output, output_capacity, output_bytes, glyph);
  }
}

/* One panel edge, with its name set into the top rule. */
static void xtop_append_panel_top(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, const char *title,
                                  uint32_t width) {
  uint32_t title_columns = (uint32_t)cstr_len(title);
  uint32_t used = 5U + title_columns; /* two corners, a rule, and two spaces */
  output_append(output, output_capacity, output_bytes, "\033[38;5;38m");
  output_append(output, output_capacity, output_bytes, XTOP_BOX_TL);
  output_append(output, output_capacity, output_bytes, XTOP_BOX_H);
  output_append(output, output_capacity, output_bytes, " \033[1;97m");
  output_append(output, output_capacity, output_bytes, title);
  output_append(output, output_capacity, output_bytes, "\033[0;38;5;38m ");
  if (width > used) {
    xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BOX_H,
                           width - used);
  }
  output_append(output, output_capacity, output_bytes, XTOP_BOX_TR);
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
}

static void xtop_append_panel_bottom(char *output, uint64_t output_capacity,
                                     uint64_t *output_bytes, uint32_t width) {
  output_append(output, output_capacity, output_bytes, "\033[38;5;38m");
  output_append(output, output_capacity, output_bytes, XTOP_BOX_BL);
  if (width > 2U) {
    xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BOX_H,
                           width - 2U);
  }
  output_append(output, output_capacity, output_bytes, XTOP_BOX_BR);
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
}

static const char *xtop_meter_color(uint64_t tenths) {
  if (tenths >= 850U) return "\033[38;5;203m";
  if (tenths >= 600U) return "\033[38;5;215m";
  return "\033[38;5;79m";
}

static void xtop_append_meter(char *output, uint64_t output_capacity,
                              uint64_t *output_bytes, const char *label,
                              uint32_t label_columns, uint64_t tenths,
                              uint32_t bar_width, uint32_t cell_width) {
  /* Columns, not bytes. The block and shade glyphs are three bytes each and
     one column each, and every width below is a column count. The total is
     label + 1 + bar + 2 + 5, which is the same as the bracketed meter this
     replaced -- so the surrounding grid arithmetic is untouched. */
  uint32_t label_width = (uint32_t)cstr_len(label);
  uint32_t visible = label_columns + bar_width + 9U;
  uint64_t filled64 = (tenths * bar_width + 999U) / 1000U;
  uint32_t filled = filled64 > bar_width ? bar_width : (uint32_t)filled64;
  output_append(output, output_capacity, output_bytes, "\033[38;5;45m");
  if (label_width < label_columns) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       label_columns - label_width);
  }
  output_append(output, output_capacity, output_bytes, label);
  output_append(output, output_capacity, output_bytes, " ");
  output_append(output, output_capacity, output_bytes,
                xtop_meter_color(tenths));
  xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BAR_FULL,
                         filled);
  output_append(output, output_capacity, output_bytes, "\033[38;5;238m");
  xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BAR_EMPTY,
                         bar_width - filled);
  output_append(output, output_capacity, output_bytes, "\033[0m  \033[1;97m");
  xtop_append_percent_width(output, output_capacity, output_bytes, tenths);
  output_append(output, output_capacity, output_bytes, "\033[0m ");
  if (visible < cell_width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       cell_width - visible);
  }
}

static void xtop_append_footer_segment(char *output, uint64_t output_capacity,
                                       uint64_t *output_bytes,
                                       uint32_t *visible, const char *key,
                                       const char *label) {
  output_append(output, output_capacity, output_bytes, "\033[30;46m");
  output_append(output, output_capacity, output_bytes, key);
  output_append(output, output_capacity, output_bytes, "\033[42;30m");
  output_append(output, output_capacity, output_bytes, label);
  output_append_char(output, output_capacity, output_bytes, ' ');
  *visible += (uint32_t)cstr_len(key) + (uint32_t)cstr_len(label) + 1U;
}

static void xtop_append_footer(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes, uint32_t columns,
                               int interactive) {
  uint32_t visible = 0U;
  output_append(output, output_capacity, output_bytes, "\033[42;30m");
  if (interactive != 0) {
    xtop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F1", "Help");
    xtop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F3", "Search");
    xtop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F4", "Filter");
    xtop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F5", "Tree");
    if (columns >= 80U) {
      xtop_append_footer_segment(output, output_capacity, output_bytes,
                                 &visible, "F6", "Sort");
      xtop_append_footer_segment(output, output_capacity, output_bytes,
                                 &visible, "I", "Reverse");
      xtop_append_footer_segment(output, output_capacity, output_bytes,
                                 &visible, "[/]", "CPUs");
    }
    xtop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F10", "Quit");
  } else {
    const char *text = columns < 60U
                           ? " --active --all --sort KEY --plain"
                           : " --active  --all  --sort KEY  --filter TEXT  --cpu-start N  --plain";
    output_append(output, output_capacity, output_bytes, text);
    visible = (uint32_t)cstr_len(text);
  }
  if (visible < columns) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       columns - visible);
  }
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
}

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

static void xtop_append_runtime(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint64_t runtime_ns) {
  uint64_t seconds = runtime_ns / UINT64_C(1000000000);
  uint64_t hours = seconds / 3600U;
  uint64_t minutes = (seconds / 60U) % 60U;
  seconds %= 60U;
  xtop_append_u64_width(output, output_capacity, output_bytes, hours, 2U);
  output_append(output, output_capacity, output_bytes, ":");
  if (minutes < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, minutes);
  output_append(output, output_capacity, output_bytes, ":");
  if (seconds < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, seconds);
}

static uint32_t xtop_append_uptime(char *output, uint64_t output_capacity,
                                   uint64_t *output_bytes, uint64_t now_ns) {
  uint64_t seconds = now_ns / UINT64_C(1000000000);
  uint64_t days = seconds / 86400U;
  uint64_t hours = (seconds / 3600U) % 24U;
  uint64_t minutes = (seconds / 60U) % 60U;
  seconds %= 60U;
  output_append_u64(output, output_capacity, output_bytes, days);
  output_append(output, output_capacity, output_bytes, " days, ");
  if (hours < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, hours);
  output_append(output, output_capacity, output_bytes, ":");
  if (minutes < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, minutes);
  output_append(output, output_capacity, output_bytes, ":");
  if (seconds < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, seconds);
  return (uint32_t)u64_digits(days) + 15U;
}

static void xtop_append_hundredths(char *output, uint64_t output_capacity,
                                   uint64_t *output_bytes, uint32_t value) {
  output_append_u64(output, output_capacity, output_bytes, value / 100U);
  output_append(output, output_capacity, output_bytes, ".");
  if (value % 100U < 10U) {
    output_append(output, output_capacity, output_bytes, "0");
  }
  output_append_u64(output, output_capacity, output_bytes, value % 100U);
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

static uint32_t xtop_cpu_page_capacity(uint32_t terminal_columns,
                                       uint32_t terminal_rows,
                                       uint32_t label_columns) {
  uint32_t rows = terminal_rows > 10U ? terminal_rows - 10U : 1U;
  if (rows > 8U) rows = 8U;
  uint32_t columns = xtop_cpu_max_columns(terminal_columns, label_columns);
  return rows > UINT32_MAX / columns ? UINT32_MAX : rows * columns;
}

static void xtop_append_info_cell(
    char *output, uint64_t output_capacity, uint64_t *output_bytes,
    uint32_t row, uint32_t width, uint32_t active_tasks,
    uint32_t failed_tasks, uint32_t cpu_total,
    const uint32_t load_average[3], uint64_t now_ns) {
  uint32_t visible = 0U;
  if (row == 0U) {
    output_append(output, output_capacity, output_bytes,
                  "\033[36mTasks: \033[32m");
    output_append_u64(output, output_capacity, output_bytes, active_tasks);
    visible = 7U + (uint32_t)u64_digits(active_tasks);
    if (width >= 40U) {
      output_append(output, output_capacity, output_bytes,
                    "\033[36m active, \033[31m");
      output_append_u64(output, output_capacity, output_bytes, failed_tasks);
      output_append(output, output_capacity, output_bytes,
                    "\033[36m failed; CPUs: \033[32m");
      output_append_u64(output, output_capacity, output_bytes, cpu_total);
      visible += 24U + (uint32_t)u64_digits(failed_tasks) +
                 (uint32_t)u64_digits(cpu_total);
    } else {
      output_append(output, output_capacity, output_bytes,
                    "\033[36m  Fail: \033[31m");
      output_append_u64(output, output_capacity, output_bytes, failed_tasks);
      visible += 8U + (uint32_t)u64_digits(failed_tasks);
    }
  } else if (row == 1U) {
    const char *caption = width >= 32U ? "Load average: " : "Load: ";
    output_append(output, output_capacity, output_bytes, "\033[36m");
    output_append(output, output_capacity, output_bytes, caption);
    output_append(output, output_capacity, output_bytes, "\033[32m");
    visible = (uint32_t)cstr_len(caption);
    uint32_t values = width >= 24U ? 3U : 2U;
    for (uint32_t i = 0U; i < values; ++i) {
      if (i != 0U) {
        output_append(output, output_capacity, output_bytes, " ");
        ++visible;
      }
      xtop_append_hundredths(output, output_capacity, output_bytes,
                             load_average[i]);
      visible += (uint32_t)u64_digits(load_average[i] / 100U) + 3U;
    }
  } else {
    uint64_t seconds = now_ns / UINT64_C(1000000000);
    if (width >= 24U) {
      output_append(output, output_capacity, output_bytes,
                    "\033[36mUptime: \033[32m");
      visible = 8U + xtop_append_uptime(output, output_capacity, output_bytes,
                                        now_ns);
    } else {
      uint64_t days = seconds / 86400U;
      uint64_t hours = (seconds / 3600U) % 24U;
      uint64_t minutes = (seconds / 60U) % 60U;
      seconds %= 60U;
      output_append(output, output_capacity, output_bytes,
                    "\033[36mUptime: \033[32m");
      output_append_u64(output, output_capacity, output_bytes, days);
      output_append(output, output_capacity, output_bytes, "d ");
      if (hours < 10U) output_append(output, output_capacity, output_bytes, "0");
      output_append_u64(output, output_capacity, output_bytes, hours);
      output_append(output, output_capacity, output_bytes, ":");
      if (minutes < 10U) output_append(output, output_capacity, output_bytes, "0");
      output_append_u64(output, output_capacity, output_bytes, minutes);
      output_append(output, output_capacity, output_bytes, ":");
      if (seconds < 10U) output_append(output, output_capacity, output_bytes, "0");
      output_append_u64(output, output_capacity, output_bytes, seconds);
      visible = 18U + (uint32_t)u64_digits(days);
    }
  }
  output_append(output, output_capacity, output_bytes, "\033[0m");
  if (visible < width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - visible);
  }
}

static void xtop_append_system_meter_cell(
    char *output, uint64_t output_capacity, uint64_t *output_bytes,
    const char *label, uint32_t label_columns, uint64_t tenths,
    uint32_t cell_width, uint64_t used_mebibytes,
    uint64_t managed_mebibytes) {
  uint32_t value_width = string_equal(label, "Mem") == 1
                             ? (uint32_t)u64_digits(used_mebibytes) +
                                   (uint32_t)u64_digits(managed_mebibytes) + 3U
                             : 5U;
  uint32_t suffix_width = value_width > 5U ? value_width + 1U : 6U;
  if (suffix_width < 14U) suffix_width = 14U;
  uint32_t minimum_meter_columns = label_columns + 10U;
  if (cell_width <= minimum_meter_columns ||
      suffix_width > cell_width - minimum_meter_columns) {
    suffix_width = 0U;
  }
  uint32_t meter_columns = cell_width - suffix_width;
  uint32_t meter_overhead = label_columns + 9U;
  uint32_t bar_width = meter_columns > meter_overhead
                           ? meter_columns - meter_overhead
                           : 1U;
  xtop_append_meter(output, output_capacity, output_bytes, label,
                    label_columns, tenths, bar_width, meter_columns);
  if (suffix_width == 0U) return;
  output_append(output, output_capacity, output_bytes,
                string_equal(label, "Mem") == 1 ? "\033[33m" : "\033[36m");
  xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                     suffix_width - value_width);
  if (string_equal(label, "Mem") == 1) {
    output_append_u64(output, output_capacity, output_bytes, used_mebibytes);
    output_append(output, output_capacity, output_bytes, "M/");
    output_append_u64(output, output_capacity, output_bytes,
                      managed_mebibytes);
    output_append(output, output_capacity, output_bytes, "M");
  } else {
    output_append(output, output_capacity, output_bytes, "0K/0K");
  }
  output_append(output, output_capacity, output_bytes, "\033[0m");
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

static int xtop_row_precedes(const xtop_process_row_t *lhs,
                             const xtop_process_row_t *rhs,
                             xtop_sort_key_t key, int reverse) {
  int precedes = 0;
  int differs = 1;
  switch (key) {
  case XTOP_SORT_MEMORY:
    precedes = lhs->resident_pages > rhs->resident_pages;
    differs = lhs->resident_pages != rhs->resident_pages;
    break;
  case XTOP_SORT_TIME:
    precedes = lhs->runtime_ns > rhs->runtime_ns;
    differs = lhs->runtime_ns != rhs->runtime_ns;
    break;
  case XTOP_SORT_PID:
    precedes = lhs->pid < rhs->pid;
    differs = lhs->pid != rhs->pid;
    break;
  case XTOP_SORT_STATE:
    precedes = lhs->state < rhs->state;
    differs = lhs->state != rhs->state;
    break;
  case XTOP_SORT_SYSCALLS:
    precedes = lhs->syscall_count > rhs->syscall_count;
    differs = lhs->syscall_count != rhs->syscall_count;
    break;
  case XTOP_SORT_COMMAND: {
    int comparison = xtop_name_compare(lhs->name, rhs->name);
    precedes = comparison < 0;
    differs = comparison != 0;
    break;
  }
  case XTOP_SORT_PARENT:
    if (lhs->parent_pid != rhs->parent_pid) {
      precedes = lhs->parent_pid < rhs->parent_pid;
    } else {
      precedes = lhs->pid < rhs->pid;
    }
    differs = lhs->parent_pid != rhs->parent_pid || lhs->pid != rhs->pid;
    break;
  default:
    precedes = lhs->cpu_tenths > rhs->cpu_tenths;
    differs = lhs->cpu_tenths != rhs->cpu_tenths;
    break;
  }
  if (differs == 0) return lhs->pid < rhs->pid;
  return reverse != 0 ? !precedes : precedes;
}

static void xtop_sort_rows(xtop_process_row_t *rows, uint32_t count,
                           xtop_sort_key_t key, int reverse) {
  for (uint32_t i = 1U; i < count; ++i) {
    xtop_process_row_t value = rows[i];
    uint32_t position = i;
    while (position > 0U &&
           xtop_row_precedes(&value, &rows[position - 1U], key, reverse)) {
      rows[position] = rows[position - 1U];
      --position;
    }
    rows[position] = value;
  }
}

static int xtop_tree_parent_present(const xtop_process_row_t *rows,
                                    uint32_t count, uint32_t parent_pid) {
  if (parent_pid == 0U) return 0;
  for (uint32_t i = 0U; i < count; ++i) {
    if (rows[i].pid == parent_pid) return 1;
  }
  return 0;
}

static int xtop_arrange_tree(xtop_process_row_t *rows, uint32_t count) {
  xtop_process_row_t *ordered;
  uint32_t *stack_index;
  uint32_t *stack_depth;
  uint8_t *emitted;
  uint32_t output_count = 0U;
  if (count == 0U) return 0;
  ordered = (xtop_process_row_t *)kheap_calloc(
      (uint64_t)count * sizeof(*ordered), 16U);
  stack_index = (uint32_t *)kheap_calloc(
      (uint64_t)count * sizeof(*stack_index), 16U);
  stack_depth = (uint32_t *)kheap_calloc(
      (uint64_t)count * sizeof(*stack_depth), 16U);
  emitted = (uint8_t *)kheap_calloc(count, 16U);
  if (ordered == 0 || stack_index == 0 || stack_depth == 0 || emitted == 0) {
    kheap_free(ordered);
    kheap_free(stack_index);
    kheap_free(stack_depth);
    kheap_free(emitted);
    return -1;
  }

  for (uint32_t root_pass = 0U; root_pass < 2U; ++root_pass) {
    for (uint32_t root = 0U; root < count; ++root) {
      int natural_root = rows[root].parent_pid == 0U ||
                         xtop_tree_parent_present(rows, count,
                                                  rows[root].parent_pid) == 0;
      if (emitted[root] != 0U ||
          (root_pass == 0U && natural_root == 0) ||
          (root_pass != 0U && natural_root != 0)) {
        continue;
      }
      uint32_t stack_count = 0U;
      stack_index[stack_count] = root;
      stack_depth[stack_count++] = 0U;
      while (stack_count != 0U) {
        --stack_count;
        uint32_t index = stack_index[stack_count];
        uint32_t depth = stack_depth[stack_count];
        if (emitted[index] != 0U) continue;
        emitted[index] = 1U;
        ordered[output_count] = rows[index];
        ordered[output_count++].tree_depth = depth;
        for (uint32_t child = count; child != 0U; --child) {
          uint32_t child_index = child - 1U;
          if (emitted[child_index] == 0U &&
              rows[child_index].parent_pid == rows[index].pid &&
              stack_count < count) {
            stack_index[stack_count] = child_index;
            stack_depth[stack_count++] =
                depth == UINT32_MAX ? UINT32_MAX : depth + 1U;
          }
        }
      }
    }
  }
  for (uint32_t i = 0U; i < output_count; ++i) rows[i] = ordered[i];
  kheap_free(ordered);
  kheap_free(stack_index);
  kheap_free(stack_depth);
  kheap_free(emitted);
  return output_count == count ? 0 : -1;
}

static uint32_t xtop_render_color(
    char *output, uint64_t output_capacity, uint64_t *output_bytes,
    uint32_t columns, uint32_t terminal_rows, uint32_t cpu_start,
    uint32_t cpu_shown, uint32_t cpu_total, const uint64_t *before_cpu,
    uint64_t after_ns, uint64_t elapsed_ns, uint64_t managed_pages,
    uint64_t free_pages, uint32_t active_tasks, uint32_t failed_tasks,
    const xtop_process_row_t *process_rows, uint32_t process_count,
    uint32_t process_start, uint32_t selected, xtop_sort_key_t sort_key,
    int reverse, int interactive, const char *filter) {
  uint32_t process_shown = 0U;
  uint32_t label_columns = 3U;
  if (cpu_total != 0U && u64_digits((uint64_t)cpu_total - 1U) > label_columns) {
    label_columns = (uint32_t)u64_digits((uint64_t)cpu_total - 1U);
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
  scheduler_load_average_hundredths(load_average);

  output_append(output, output_capacity, output_bytes,
                interactive != 0 ? "\033[2J\033[H\033[?25l"
                                 : "\033[2J\033[H\033[?25h");
  xtop_append_ansi_line(output, output_capacity, output_bytes,
                        "\033[48;5;24;97m",
                        " XAIOS xtop \xe2\x80\x94 sampled kernel process monitor",
                        columns);
  xtop_append_panel_top(output, output_capacity, output_bytes, "CPU", columns);

  for (uint32_t line = 0U; line < header_lines; ++line) {
    if (grid_columns > 1U && line < cpu_line_count) {
      uint32_t base_width = columns / grid_columns;
      for (uint32_t column = 0U; column < grid_columns; ++column) {
        uint32_t cell_width = column + 1U == grid_columns
                                  ? columns - base_width * column
                                  : base_width;
        uint32_t offset = column * cpu_line_count + line;
        if (offset >= cpu_shown) {
          xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                             cell_width);
          continue;
        }
        xaios_cpu_usage_snapshot_t usage;
        uint64_t tenths = 0U;
        if (user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) ==
            XAIOS_OK) {
          uint64_t delta = usage.busy_ns >= before_cpu[offset]
                               ? usage.busy_ns - before_cpu[offset]
                               : 0U;
          tenths = xtop_capacity_tenths(delta, elapsed_ns);
        }
        char label[12];
        uint64_t label_bytes = 0U;
        label[0] = '\0';
        xtop_append_u64_width(label, sizeof(label), &label_bytes,
                              cpu_start + offset, label_columns);
        uint32_t bar_width = cell_width > label_columns + 9U
                                 ? cell_width - label_columns - 9U
                                 : 1U;
        xtop_append_meter(output, output_capacity, output_bytes, label,
                          label_columns, tenths, bar_width, cell_width);
      }
      output_append(output, output_capacity, output_bytes, "\r\n");
      continue;
    }

    uint32_t system_row = line >= cpu_line_count
                              ? line - cpu_line_count
                              : UINT32_MAX;
    if (grid_columns == 1U && line < cpu_line_count) {
      uint32_t offset = line;
      xaios_cpu_usage_snapshot_t usage;
      uint64_t tenths = 0U;
      if (user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) ==
          XAIOS_OK) {
        uint64_t delta = usage.busy_ns >= before_cpu[offset]
                             ? usage.busy_ns - before_cpu[offset]
                             : 0U;
        tenths = xtop_capacity_tenths(delta, elapsed_ns);
      }
      char label[12];
      uint64_t label_bytes = 0U;
      label[0] = '\0';
      xtop_append_u64_width(label, sizeof(label), &label_bytes,
                            cpu_start + offset, label_columns);
      uint32_t bar_width = left_width > label_columns + 9U
                               ? left_width - label_columns - 9U
                               : 1U;
      xtop_append_meter(output, output_capacity, output_bytes, label,
                        label_columns, tenths, bar_width, left_width);
    } else if (system_row == 0U) {
      xtop_append_system_meter_cell(
          output, output_capacity, output_bytes, "Mem", label_columns,
          memory_tenths, left_width, used_mebibytes, managed_mebibytes);
    } else if (system_row == 1U) {
      xtop_append_system_meter_cell(
          output, output_capacity, output_bytes, "Swp", label_columns, 0U,
          left_width, used_mebibytes, managed_mebibytes);
    } else {
      xtop_append_repeat(output, output_capacity, output_bytes, ' ', left_width);
    }

    uint32_t info_row = grid_columns == 1U ? line : system_row;
    if (info_row < 3U) {
      xtop_append_info_cell(output, output_capacity, output_bytes, info_row,
                            right_width, active_tasks, failed_tasks, cpu_total,
                            load_average, after_ns);
    } else {
      xtop_append_repeat(output, output_capacity, output_bytes, ' ', right_width);
    }
    output_append(output, output_capacity, output_bytes, "\r\n");
  }

  output_append(output, output_capacity, output_bytes,
                "\033[36mView: \033[32m");
  output_append(output, output_capacity, output_bytes,
                interactive != 0 ? "live" : "snapshot");
  output_append(output, output_capacity, output_bytes,
                "\033[36m  Sort: \033[32m");
  output_append(output, output_capacity, output_bytes, xtop_sort_name(sort_key));
  if (reverse != 0) {
    output_append(output, output_capacity, output_bytes, " ascending");
  }
  if (filter[0] != '\0') {
    output_append(output, output_capacity, output_bytes,
                  "\033[36m  Filter: \033[33m");
    xtop_append_bounded(output, output_capacity, output_bytes, filter,
                        columns > 40U ? columns - 40U : 1U);
  }
  if (cpu_start != 0U || cpu_start + cpu_shown < cpu_total) {
    output_append(output, output_capacity, output_bytes,
                  "\033[36m  CPU page: \033[32m");
    output_append_u64(output, output_capacity, output_bytes, cpu_start);
    output_append(output, output_capacity, output_bytes, "-");
    output_append_u64(output, output_capacity, output_bytes,
                      cpu_shown == 0U ? cpu_start
                                      : cpu_start + cpu_shown - 1U);
    output_append(output, output_capacity, output_bytes, "/");
    output_append_u64(output, output_capacity, output_bytes, cpu_total);
  }
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
  xtop_append_panel_bottom(output, output_capacity, output_bytes, columns);
  output_append(output, output_capacity, output_bytes, "\r\n");

  /* "[Main]" stays: it is the tab strip, and the network suites read it to
     know the screen has been drawn. Restyled, not removed. */
  xtop_append_ansi_line(output, output_capacity, output_bytes,
                        "\033[48;5;24;97m", "[Main]", columns);
  xtop_append_panel_top(output, output_capacity, output_bytes, "Processes",
                        columns);
  xtop_append_ansi_line(output, output_capacity, output_bytes,
                        "\033[48;5;238;97m",
                        columns < 60U
                            ? " PID S   CPU%   MEM% COMMAND"
                            : (columns < 100U
                                   ? "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU COMMAND"
                                   : "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU  SYSCALLS COMMAND"),
                        columns);

  for (uint32_t i = process_start;
       i < process_count && process_shown < process_budget;
       ++i) {
    uint64_t row_and_footer = ((uint64_t)columns + 64U) * 2U;
    if (*output_bytes >= output_capacity ||
        row_and_footer >= output_capacity - *output_bytes) {
      break;
    }
    const xtop_process_row_t *row = &process_rows[i];
    if (i == selected) output_append(output, output_capacity, output_bytes,
                                    "\033[46;30m");
    else output_append(output, output_capacity, output_bytes, "\033[36m");
    uint32_t fixed_visible;
    if (columns < 60U) {
      xtop_append_u64_width(output, output_capacity, output_bytes, row->pid,
                            4U);
      output_append(output, output_capacity, output_bytes, " ");
      output_append_char(output, output_capacity, output_bytes,
                         xtop_state_character(row->state));
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_percent_width(output, output_capacity, output_bytes,
                                row->cpu_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_percent_width(output, output_capacity, output_bytes,
                                row->memory_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      fixed_visible = 21U;
    } else {
      xtop_append_u64_width(output, output_capacity, output_bytes, row->pid,
                            5U);
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_u64_width(output, output_capacity, output_bytes,
                            row->parent_pid, 5U);
      output_append(output, output_capacity, output_bytes, " ");
      output_append_char(output, output_capacity, output_bytes,
                         xtop_state_character(row->state));
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_percent_width(output, output_capacity, output_bytes,
                                row->cpu_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_percent_width(output, output_capacity, output_bytes,
                                row->memory_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_runtime(output, output_capacity, output_bytes,
                          row->runtime_ns);
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_u64_width(output, output_capacity, output_bytes,
                            row->resident_pages * 4U, 7U);
      output_append(output, output_capacity, output_bytes, " ");
      if (row->cpu_id == UINT32_MAX) {
        output_append(output, output_capacity, output_bytes, "  -");
      } else {
        xtop_append_u64_width(output, output_capacity, output_bytes,
                              row->cpu_id, 3U);
      }
      output_append(output, output_capacity, output_bytes, " ");
      fixed_visible = 49U;
      if (columns >= 100U) {
        xtop_append_u64_width(output, output_capacity, output_bytes,
                              row->syscall_count, 9U);
        output_append(output, output_capacity, output_bytes, " ");
        fixed_visible += 10U;
      }
    }
    uint32_t command_width = columns > fixed_visible
                                 ? columns - fixed_visible
                                 : 0U;
    uint32_t prefix_length = 0U;
    if (sort_key == XTOP_SORT_PARENT && row->tree_depth != 0U) {
      uint32_t indent = row->tree_depth > 8U ? 14U
                                             : (row->tree_depth - 1U) * 2U;
      prefix_length = indent + 3U;
      if (prefix_length <= command_width) {
        xtop_append_repeat(output, output_capacity, output_bytes, ' ', indent);
      } else {
        prefix_length = 0U;
      }
    }
    if (prefix_length != 0U && command_width >= prefix_length) {
      output_append(output, output_capacity, output_bytes, "|- ");
    }
    uint32_t name_width = command_width > prefix_length
                              ? command_width - prefix_length : 0U;
    xtop_append_bounded(output, output_capacity, output_bytes, row->name,
                        name_width);
    uint32_t command_length = (uint32_t)cstr_len(row->name);
    if (command_length < name_width) {
      xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                         name_width - command_length);
    }
    output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
    ++process_shown;
  }

  if (interactive != 0) {
    xtop_append_footer(output, output_capacity, output_bytes, columns, 1);
    output_append(output, output_capacity, output_bytes, "\033[0m\033[?25l");
  } else {
    xtop_append_footer(output, output_capacity, output_bytes, columns, 0);
    output_append(output, output_capacity, output_bytes, "\033[0m\033[?25h");
  }
  return process_shown;
}

static xaios_status_t xtop_parse_u32_option(const char *args, uint64_t *index,
                                            uint32_t *value) {
  char token[24];
  uint64_t parsed = 0U;
  uint64_t consumed = 0U;
  if (token_next(args, index, token, sizeof(token)) != XAIOS_OK ||
      parse_u64_token(token, &parsed, &consumed) != XAIOS_OK ||
      consumed != cstr_len(token) || parsed > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  *value = (uint32_t)parsed;
  return XAIOS_OK;
}

static xaios_status_t xtop_parse_sort_option(const char *args, uint64_t *index,
                                             xtop_sort_key_t *key) {
  char value[24];
  if (token_next(args, index, value, sizeof(value)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (string_equal(value, "cpu") == 1U) *key = XTOP_SORT_CPU;
  else if (string_equal(value, "mem") == 1U) *key = XTOP_SORT_MEMORY;
  else if (string_equal(value, "time") == 1U) *key = XTOP_SORT_TIME;
  else if (string_equal(value, "pid") == 1U) *key = XTOP_SORT_PID;
  else if (string_equal(value, "state") == 1U) *key = XTOP_SORT_STATE;
  else if (string_equal(value, "syscalls") == 1U) *key = XTOP_SORT_SYSCALLS;
  else if (string_equal(value, "command") == 1U) *key = XTOP_SORT_COMMAND;
  else if (string_equal(value, "parent") == 1U) *key = XTOP_SORT_PARENT;
  else return XAIOS_ERR_INVALID;
  return XAIOS_OK;
}


static xaios_status_t handle_xtop(const char *args, char *output,
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
  while (token_next(args, &index, option, sizeof(option)) == XAIOS_OK) {
    if (string_equal(option, "--all")) show_all = 1;
    else if (string_equal(option, "--active")) show_all = 0;
    else if (string_equal(option, "--no-cpus")) show_cpus = 0;
    else if (string_equal(option, "--color")) color_output = 1;
    else if (string_equal(option, "--plain")) color_output = 0;
    else if (string_equal(option, "--interactive")) {
      interactive = 1;
      color_output = 1;
    } else if (string_equal(option, "--reverse")) reverse = 1;
    else if (string_equal(option, "--tree")) sort_key = XTOP_SORT_PARENT;
    else if (string_equal(option, "--sort")) {
      if (xtop_parse_sort_option(args, &index, &sort_key) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --sort key");
    } else if (string_equal(option, "--filter")) {
      if (token_next(args, &index, filter, sizeof(filter)) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --filter");
    } else if (string_equal(option, "--process-start")) {
      if (xtop_parse_u32_option(args, &index, &process_start) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --process-start");
    } else if (string_equal(option, "--selected")) {
      if (xtop_parse_u32_option(args, &index, &selected) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --selected");
    } else if (string_equal(option, "--columns")) {
      if (xtop_parse_u32_option(args, &index, &terminal_columns) != XAIOS_OK ||
          terminal_columns < 40U || terminal_columns > 240U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --columns must be 40..240");
    } else if (string_equal(option, "--rows")) {
      if (xtop_parse_u32_option(args, &index, &terminal_rows) != XAIOS_OK ||
          terminal_rows < 12U || terminal_rows > 100U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --rows must be 12..100");
    } else if (string_equal(option, "--cpu-start")) {
      if (xtop_parse_u32_option(args, &index, &cpu_start) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --cpu-start");
    } else if (string_equal(option, "--cpu-count")) {
      if (xtop_parse_u32_option(args, &index, &cpu_requested) != XAIOS_OK ||
          cpu_requested == 0U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --cpu-count");
    } else if (string_equal(option, "--sample-ms")) {
      if (xtop_parse_u32_option(args, &index, &sample_ms) != XAIOS_OK ||
          sample_ms == 0U || sample_ms > 1000U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --sample-ms must be 1..1000");
    } else if (string_equal(option, "--help")) {
      output_append(output, output_capacity, output_bytes,
          "xtop [--active|--all] [--sample-ms 1..1000] [--cpu-start N] "
          "[--cpu-count N] [--no-cpus] [--color|--plain] "
          "[--columns 40..240] [--rows 12..100] "
          "[--sort cpu|mem|time|pid|state|syscalls|command|parent] "
          "[--reverse] [--tree] [--filter TEXT] [--process-start N] "
          "[--selected N]\n");
      return XAIOS_OK;
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          "xtop: unsupported option; use xtop --help");
    }
  }

  if (gather_processes(process_records, XAIOS_XTOP_MAX_PROCESSES,
                       before_runtime, &before_process_count,
                       &before_meta) != 0)
    return command_fail(output, output_capacity, output_bytes,
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
        u64_digits((uint64_t)cpu_total - 1U) > label_columns)
      label_columns = (uint32_t)u64_digits((uint64_t)cpu_total - 1U);
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
  if (gather_cpu_page(cpu_start, cpu_shown, before_cpus,
                      XAIOS_XTOP_CPU_PAGE_MAX, &before_cpu_count,
                      &before_meta) != 0)
    return command_fail(output, output_capacity, output_bytes,
                        "xtop: CPU snapshot unavailable");

  xaios_control_runtime_snapshot_payload_user_t wait_result;
  if (runtime_query(0U, 0U, 0U, 0U, sample_ms, &wait_result) != 0)
    return command_fail(output, output_capacity, output_bytes,
                        "xtop: sample wait failed");
  if (gather_processes(process_records, XAIOS_XTOP_MAX_PROCESSES, 0,
                       &after_process_count, &after_meta) != 0)
    return command_fail(output, output_capacity, output_bytes,
                        "xtop: runtime snapshot unavailable");
  if (gather_cpu_page(cpu_start, cpu_shown, g_cpu_records,
                      XAIOS_XTOP_CPU_PAGE_MAX, &g_cpu_record_count,
                      &after_meta) != 0)
    return command_fail(output, output_capacity, output_bytes,
                        "xtop: CPU snapshot unavailable");

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
        (filter[0] != '\0' && !contains_substring(process->name, filter)))
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
    xtop_sort_rows(rows, process_count, XTOP_SORT_PID, reverse);
    if (xtop_arrange_tree(rows, process_count) != 0)
      xtop_sort_rows(rows, process_count, XTOP_SORT_PARENT, reverse);
  } else {
    xtop_sort_rows(rows, process_count, sort_key, reverse);
  }
  if (process_start > process_count) process_start = process_count;
  if (process_count == 0U) selected = 0U;
  else if (selected >= process_count) selected = process_count - 1U;

  if (color_output != 0) {
    (void)xtop_render_color(
        output, output_capacity, output_bytes, terminal_columns, terminal_rows,
        cpu_start, g_cpu_record_count, cpu_total, before_cpu_values, after_ns,
        elapsed_ns, after_meta.managed_pages, after_meta.free_pages,
        after_meta.process_active, after_meta.process_failed, rows,
        process_count, process_start, selected, sort_key, reverse, interactive,
        filter);
    return XAIOS_OK;
  }

  output_append(output, output_capacity, output_bytes, "XAIOS xtop sample_ms=");
  output_append_u64(output, output_capacity, output_bytes, sample_ms);
  output_append(output, output_capacity, output_bytes, " cpus=");
  output_append_u64(output, output_capacity, output_bytes, cpu_total);
  output_append(output, output_capacity, output_bytes, " tasks_active=");
  output_append_u64(output, output_capacity, output_bytes,
                    after_meta.process_active);
  output_append(output, output_capacity, output_bytes, " failed=");
  output_append_u64(output, output_capacity, output_bytes,
                    after_meta.process_failed);
  output_append(output, output_capacity, output_bytes, " sort=");
  output_append(output, output_capacity, output_bytes, xtop_sort_name(sort_key));
  output_append(output, output_capacity, output_bytes, " reverse=");
  output_append_u64(output, output_capacity, output_bytes, reverse != 0);
  if (filter[0] != '\0') {
    output_append(output, output_capacity, output_bytes, " filter=");
    output_append(output, output_capacity, output_bytes, filter);
  }
  output_append(output, output_capacity, output_bytes, "\nCPU all=");
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
  output_append(output, output_capacity, output_bytes, " MEM managed=");
  xtop_append_percent(output, output_capacity, output_bytes,
                      xtop_capacity_tenths(used_pages,
                                           after_meta.managed_pages));
  output_append(output, output_capacity, output_bytes, " pages=");
  output_append_u64(output, output_capacity, output_bytes, used_pages);
  output_append(output, output_capacity, output_bytes, "/");
  output_append_u64(output, output_capacity, output_bytes,
                    after_meta.managed_pages);
  output_append(output, output_capacity, output_bytes, " physical_pages=");
  output_append_u64(output, output_capacity, output_bytes,
                    after_meta.physical_pages);
  output_append(output, output_capacity, output_bytes, "\n");

  if (show_cpus != 0) {
    output_append(output, output_capacity, output_bytes,
                  "CPU CPU% BUSY_MS IDLE_MS ACTIVE ROLE\n");
    for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
      const xaios_control_runtime_cpu_record_user_t *cpu = &g_cpu_records[i];
      uint64_t delta = cpu->busy_ns >= before_cpu_values[i]
                           ? cpu->busy_ns - before_cpu_values[i]
                           : 0U;
      output_append_u64(output, output_capacity, output_bytes, cpu->cpu_id);
      output_append(output, output_capacity, output_bytes, " ");
      xtop_append_percent(output, output_capacity, output_bytes,
                          xtop_capacity_tenths(delta, elapsed_ns));
      output_append(output, output_capacity, output_bytes, " ");
      output_append_u64(output, output_capacity, output_bytes,
                        cpu->busy_ns / UINT64_C(1000000));
      output_append(output, output_capacity, output_bytes, " ");
      output_append_u64(output, output_capacity, output_bytes,
                        (cpu->elapsed_ns >= cpu->busy_ns
                             ? cpu->elapsed_ns - cpu->busy_ns
                             : 0U) /
                            UINT64_C(1000000));
      output_append(output, output_capacity, output_bytes, " ");
      output_append_u64(output, output_capacity, output_bytes, cpu->active_pid);
      output_append(output, output_capacity, output_bytes, " ");
      output_append(output, output_capacity, output_bytes,
                    xtop_cpu_role_name(cpu->cpu_id));
      output_append(output, output_capacity, output_bytes, "\n");
    }
    output_append(output, output_capacity, output_bytes, "cpu_shown=");
    output_append_u64(output, output_capacity, output_bytes,
                      g_cpu_record_count);
    output_append(output, output_capacity, output_bytes, " cpu_total=");
    output_append_u64(output, output_capacity, output_bytes, cpu_total);
    if (cpu_start + g_cpu_record_count < cpu_total) {
      output_append(output, output_capacity, output_bytes, " next_cpu_start=");
      output_append_u64(output, output_capacity, output_bytes,
                        cpu_start + g_cpu_record_count);
    }
    output_append(output, output_capacity, output_bytes, "\n");
  }

  output_append(output, output_capacity, output_bytes,
                "PID PPID S CPU% MEM% TIME_MS RES_KIB CPU SYSCALLS COMMAND\n");
  for (uint32_t i = process_start; i < process_count; ++i) {
    if (*output_bytes + 160U >= output_capacity) break;
    const xtop_process_row_t *row = &rows[i];
    output_append_u64(output, output_capacity, output_bytes, row->pid);
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes, row->parent_pid);
    output_append(output, output_capacity, output_bytes, " ");
    output_append(output, output_capacity, output_bytes,
                  xtop_state_name(row->state));
    output_append(output, output_capacity, output_bytes, " ");
    xtop_append_percent(output, output_capacity, output_bytes, row->cpu_tenths);
    output_append(output, output_capacity, output_bytes, " ");
    xtop_append_percent(output, output_capacity, output_bytes,
                        row->memory_tenths);
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes,
                      row->runtime_ns / UINT64_C(1000000));
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes,
                      row->resident_pages * 4U);
    output_append(output, output_capacity, output_bytes, " ");
    if (row->cpu_id == UINT32_MAX)
      output_append(output, output_capacity, output_bytes, "-");
    else
      output_append_u64(output, output_capacity, output_bytes, row->cpu_id);
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes,
                      row->syscall_count);
    output_append(output, output_capacity, output_bytes, " ");
    output_append(output, output_capacity, output_bytes, row->name);
    output_append(output, output_capacity, output_bytes, "\n");
    ++process_shown;
  }
  output_append(output, output_capacity, output_bytes, "process_shown=");
  output_append_u64(output, output_capacity, output_bytes, process_shown);
  output_append(output, output_capacity, output_bytes, " process_total=");
  output_append_u64(output, output_capacity, output_bytes, process_count);
  output_append(output, output_capacity, output_bytes, " process_start=");
  output_append_u64(output, output_capacity, output_bytes, process_start);
  if (process_start + process_shown < process_count)
    output_append(output, output_capacity, output_bytes, " truncated=1");
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

int main(int argc, char **argv) {
  static char output[XAIOS_XTOP_OUTPUT_BYTES];
  uint64_t output_size = 0U;
  const char *args = "";
  g_arena_used = 0U;
  output[0] = '\0';
  if (argc > 2) return 2;
  if (argc == 2) args = argv[1];
  int status = handle_xtop(args, output, sizeof(output), &output_size);
  if (output_size != 0U)
    (void)xaios_console_write(output, output_size);
  return status == XAIOS_OK ? 0 : 1;
}
