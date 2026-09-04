#include <xaios_user.h>
#include <xaios/types.h>
#include "ssh_child_ipc.h"

#define XAIOS_OK 0
#define XAIOS_ERR_INVALID (-1)
#define XAIOS_ERR_NOT_FOUND (-2)
#define XAIOS_ERR_NO_MEMORY (-3)
#define XTOP_ERR_BUSY (-5) /* XAIOS_ERR_BUSY, as the kernel returns it */

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

/* One query with no request payload, answered with a typed one. The
   hardware, metrics and status operations are all of this shape. */
static int control_simple_query(uint32_t operation, uint32_t payload_type,
                                void *payload, uint64_t payload_size) {
  xaios_control_request_header_user_t request;
  static union {
    u64 alignment;
    unsigned char bytes[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  } response;
  u64 response_size = 0U;
  bytes_zero(&request, sizeof(request));
  request.magic = XAIOS_CONTROL_MAGIC;
  request.version = XAIOS_CONTROL_VERSION;
  request.header_size = (u16)sizeof(request);
  request.operation = operation;
  request.payload_type = XAIOS_CONTROL_PAYLOAD_NONE;
  request.request_id = g_request_id++;
  request.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  request.payload_length = 0U;
  if (xaios_control_query(&request, sizeof(request), response.bytes,
                          sizeof(response.bytes), &response_size) != 0 ||
      response_size < sizeof(xaios_control_response_header_user_t) +
                          payload_size)
    return -1;
  const xaios_control_response_header_user_t *header =
      (const xaios_control_response_header_user_t *)response.bytes;
  if (header->magic != XAIOS_CONTROL_MAGIC ||
      header->version != XAIOS_CONTROL_VERSION ||
      header->status != XAIOS_CONTROL_STATUS_OK ||
      header->payload_type != payload_type ||
      header->payload_length != payload_size)
    return -1;
  xaios_memcpy(payload, response.bytes + sizeof(*header), payload_size);
  return 0;
}

/* What the frame shows beyond the process table: the machine, the AI
   runtime, the network and disk rates, and a short history. Filled by the
   serving loop before each frame; a one-shot run fills what it can and has
   no rates, because a rate needs two samples. */
#define XTOP_HISTORY 96U
#define XTOP_LAYOUT_COUNT 3U
typedef struct xtop_extras {
  int have_hardware;
  xaios_control_hardware_payload_user_t hardware;
  int have_metrics;
  xaios_control_metrics_payload_user_t metrics;
  int have_rates;
  uint64_t rx_bytes_per_s;
  uint64_t tx_bytes_per_s;
  uint64_t reads_per_s;
  uint64_t writes_per_s;
  uint64_t inferences_per_s;
  uint32_t layout;
  uint16_t cpu_history[XTOP_HISTORY];
  uint16_t mem_history[XTOP_HISTORY];
  uint32_t net_history[XTOP_HISTORY]; /* KB/s, rx + tx */
  uint32_t history_count;
} xtop_extras_t;
static xtop_extras_t g_extras;
static uint16_t g_last_cpu_tenths;
static uint16_t g_last_mem_tenths;

static void history_push16(uint16_t *history, uint16_t value) {
  for (uint32_t i = 1U; i < XTOP_HISTORY; ++i) history[i - 1U] = history[i];
  history[XTOP_HISTORY - 1U] = value;
}
static void history_push32(uint32_t *history, uint32_t value) {
  for (uint32_t i = 1U; i < XTOP_HISTORY; ++i) history[i - 1U] = history[i];
  history[XTOP_HISTORY - 1U] = value;
}

/* Retained samples, so a frame drawn sixty times a second still reports
   load over a quarter-second window: the "before" of every frame is the
   newest retained sample at least that old, not the previous frame. */
#define XTOP_RING 8U
typedef struct xtop_sample {
  int valid;
  uint32_t cpu_start;
  uint32_t cpu_count;
  xaios_control_runtime_snapshot_payload_user_t meta;
  uint64_t runtime[XAIOS_XTOP_MAX_PROCESSES + 1U];
  xaios_control_runtime_cpu_record_user_t cpus[XAIOS_XTOP_CPU_PAGE_MAX];
} xtop_sample_t;
static xtop_sample_t g_ring[XTOP_RING];
static uint32_t g_ring_next;

static const xtop_sample_t *ring_before(uint64_t now_ns, uint64_t window_ns,
                                        uint32_t cpu_start) {
  const xtop_sample_t *newest_old_enough = 0;
  const xtop_sample_t *oldest = 0;
  for (uint32_t i = 0U; i < XTOP_RING; ++i) {
    const xtop_sample_t *sample = &g_ring[i];
    if (sample->valid == 0 || sample->cpu_start != cpu_start) continue;
    if (oldest == 0 || sample->meta.sampled_at_ns < oldest->meta.sampled_at_ns)
      oldest = sample;
    if (now_ns >= sample->meta.sampled_at_ns &&
        now_ns - sample->meta.sampled_at_ns >= window_ns &&
        (newest_old_enough == 0 ||
         sample->meta.sampled_at_ns > newest_old_enough->meta.sampled_at_ns))
      newest_old_enough = sample;
  }
  return newest_old_enough != 0 ? newest_old_enough : oldest;
}

static void ring_push(
    const xaios_control_runtime_snapshot_payload_user_t *meta,
    const xaios_control_runtime_process_record_user_t *processes,
    uint32_t process_count,
    const xaios_control_runtime_cpu_record_user_t *cpus, uint32_t cpu_count,
    uint32_t cpu_start) {
  xtop_sample_t *slot = &g_ring[g_ring_next];
  g_ring_next = (g_ring_next + 1U) % XTOP_RING;
  bytes_zero(slot->runtime, sizeof(slot->runtime));
  for (uint32_t i = 0U; i < process_count; ++i) {
    if (processes[i].pid <= XAIOS_XTOP_MAX_PROCESSES)
      slot->runtime[processes[i].pid] = processes[i].runtime_ns;
  }
  if (cpu_count > XAIOS_XTOP_CPU_PAGE_MAX) cpu_count = XAIOS_XTOP_CPU_PAGE_MAX;
  xaios_memcpy(slot->cpus, cpus, sizeof(cpus[0]) * cpu_count);
  slot->cpu_count = cpu_count;
  slot->cpu_start = cpu_start;
  slot->meta = *meta;
  slot->valid = 1;
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

/* Terminal columns in a UTF-8 string: every byte that does not continue a
   sequence starts one glyph, and every glyph this program prints is one
   column wide. Measuring in bytes instead padded the title two columns short,
   because the em dash in it is three bytes. */
static uint32_t xtop_columns(const char *text) {
  uint32_t columns = 0U;
  for (uint64_t i = 0U; text[i] != '\0'; ++i) {
    if (((uint8_t)text[i] & 0xc0U) != 0x80U) ++columns;
  }
  return columns;
}

static void xtop_append_bounded(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, const char *text,
                                uint32_t width) {
  uint32_t used = 0U;
  uint32_t columns = 0U;
  while (text[used] != '\0') {
    if (((uint8_t)text[used] & 0xc0U) != 0x80U) {
      if (columns == width) break;
      ++columns;
    }
    if (output_append_char(output, output_capacity, output_bytes, text[used]) !=
        XAIOS_OK) {
      return;
    }
    ++used;
  }
}

/* The look is mactop's: a blue field, green rules with panel names set into
 * them, tall solid gauges with the figure centred, a green header bar over
 * the process list, and the keys in the bottom rule. Every line is padded to
 * the full width in the field colour, so nothing depends on what a terminal
 * does with an erase.
 *
 * UTF-8 for the rules and blocks, drawn identically by an SSH client and by
 * the local framebuffer console, which carries these glyphs and parses the
 * 256-colour escapes -- `make qemu-console-xtop-gate` reads the screen back
 * as pixels to hold it to that. Nothing here emits a bare reset: the reset
 * used everywhere re-asserts the field and text colours, or the blue would
 * have holes wherever an attribute ended. */
#define XTOP_BG "\033[48;5;68m"
#define XTOP_FG "\033[38;5;120m"
#define XTOP_RESET "\033[0;48;5;68;38;5;120m"
#define XTOP_TITLE "\033[1;97m"
#define XTOP_FILL_BG "\033[48;5;70m"
#define XTOP_HEADER "\033[48;5;70;30m"
#define XTOP_SELECTED "\033[48;5;70;30m"
#define XTOP_BAR_FULL "\xe2\x96\x88"  /* U+2588 FULL BLOCK */
#define XTOP_BAR_EMPTY "\xe2\x96\x91" /* U+2591 LIGHT SHADE */
/* Columns a meter uses around its bar: a space after the label, two before
   the percentage, the six-column percentage, and a gutter after it. */
#define XTOP_METER_OVERHEAD 10U
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

/* A rule with an optional name set into it by the left corner and an
   optional note by the right: exactly `width` columns and no line ending, so
   two can share a screen row. */
static void xtop_append_rule(char *output, uint64_t output_capacity,
                             uint64_t *output_bytes, const char *left_corner,
                             const char *right_corner, const char *title,
                             const char *note, uint32_t width) {
  if (width < 2U) return;
  uint32_t inner = width - 2U;
  uint32_t title_columns = title != 0 ? xtop_columns(title) + 3U : 0U;
  uint32_t note_columns = note != 0 ? xtop_columns(note) + 3U : 0U;
  if (title_columns + note_columns > inner) note_columns = 0U;
  if (title_columns > inner) title_columns = 0U;
  output_append(output, output_capacity, output_bytes, XTOP_RESET);
  output_append(output, output_capacity, output_bytes, left_corner);
  if (title_columns != 0U) {
    output_append(output, output_capacity, output_bytes,
                  XTOP_BOX_H " " XTOP_TITLE);
    output_append(output, output_capacity, output_bytes, title);
    output_append(output, output_capacity, output_bytes, XTOP_RESET " ");
  }
  if (inner > title_columns + note_columns) {
    xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BOX_H,
                           inner - title_columns - note_columns);
  }
  if (note_columns != 0U) {
    output_append(output, output_capacity, output_bytes, " " XTOP_TITLE);
    output_append(output, output_capacity, output_bytes, note);
    output_append(output, output_capacity, output_bytes,
                  XTOP_RESET " " XTOP_BOX_H);
  }
  output_append(output, output_capacity, output_bytes, right_corner);
}

static void xtop_append_panel_top(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, const char *title,
                                  uint32_t width) {
  xtop_append_rule(output, output_capacity, output_bytes, XTOP_BOX_TL,
                   XTOP_BOX_TR, title, 0, width);
}

static void xtop_append_panel_bottom(char *output, uint64_t output_capacity,
                                     uint64_t *output_bytes, uint32_t width) {
  xtop_append_rule(output, output_capacity, output_bytes, XTOP_BOX_BL,
                   XTOP_BOX_BR, 0, 0, width);
}

/* Text in a style, padded with the field to exactly `width` columns. */
static void xtop_append_padded(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes, const char *style,
                               const char *text, uint32_t width) {
  uint32_t visible = xtop_columns(text);
  if (visible > width) visible = width;
  output_append(output, output_capacity, output_bytes, style);
  xtop_append_bounded(output, output_capacity, output_bytes, text, width);
  if (visible < width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - visible);
  }
  output_append(output, output_capacity, output_bytes, XTOP_RESET);
}

/* One row of a solid gauge: the filled part in the fill colour, the rest the
   field, and on the row that carries it the figure centred, drawn over
   whichever of the two it lands on. That is mactop's gauge. */
static void xtop_append_gauge_row(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, uint32_t width,
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
      output_append(output, output_capacity, output_bytes,
                    here != 0 ? XTOP_FILL_BG XTOP_TITLE
                              : XTOP_RESET XTOP_TITLE);
      filled = here;
    }
    if (figure != 0 && column >= figure_start &&
        column < figure_start + figure_columns &&
        figure[figure_index] != '\0') {
      /* One glyph, however many bytes it is. */
      do {
        output_append_char(output, output_capacity, output_bytes,
                           figure[figure_index++]);
      } while (((uint8_t)figure[figure_index] & 0xc0U) == 0x80U);
    } else {
      output_append_char(output, output_capacity, output_bytes, ' ');
    }
  }
  output_append(output, output_capacity, output_bytes, XTOP_RESET);
}

/* A bar chart row: `rows` rows tall, newest sample at the right, each
   column a value in tenths of a percent. Whole rows are full blocks and the
   top of each bar is one of the eighth blocks, which is what makes a chart
   this small readable. */
static void xtop_append_chart_row(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, uint32_t width,
                                  const uint16_t *history, uint32_t count,
                                  uint32_t row, uint32_t rows,
                                  uint16_t scale) {
  static const char *const eighths[8] = {
      " ", "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
      "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87"};
  output_append(output, output_capacity, output_bytes, XTOP_RESET "\033[38;5;70m");
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
      output_append(output, output_capacity, output_bytes, XTOP_BAR_FULL);
    } else if (total_eighths > below) {
      output_append(output, output_capacity, output_bytes,
                    eighths[total_eighths - below]);
    } else {
      output_append_char(output, output_capacity, output_bytes, ' ');
    }
  }
  output_append(output, output_capacity, output_bytes, XTOP_RESET);
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
  output_append_u64(output, output_capacity, output_bytes, whole);
  if (whole < 100U && unit[0] != 'B') {
    output_append(output, output_capacity, output_bytes, ".");
    output_append_u64(output, output_capacity, output_bytes, tenths);
  }
  output_append(output, output_capacity, output_bytes, " ");
  output_append(output, output_capacity, output_bytes, unit);
}

static const char *xtop_yes_no(uint32_t value) {
  return value == 1U ? "yes" : (value == 0U ? "no" : "?");
}

/* The Platform panel: what the machine is, said as capabilities. Each
   architecture has its own line of them, because the flags that matter
   differ; the rest is common. */
static void xtop_platform_line(char *line, uint64_t capacity, uint32_t row,
                               uint32_t cpu_total) {
  uint64_t used = 0U;
  const xaios_control_hardware_payload_user_t *hw = &g_extras.hardware;
  line[0] = '\0';
  if (g_extras.have_hardware == 0) {
    if (row == 0U) output_append(line, capacity, &used, "hardware query unavailable");
    return;
  }
  int arm = hw->architecture[0] == 'a';
  int x86 = hw->architecture[0] == 'x';
  int riscv = hw->architecture[0] == 'r';
  switch (row) {
  case 0U:
    output_append(line, capacity, &used, "Architecture: ");
    output_append(line, capacity, &used, hw->architecture);
    output_append(line, capacity, &used, "  Backend: ");
    output_append(line, capacity, &used, hw->selected_backend);
    break;
  case 1U:
    output_append(line, capacity, &used, "CPUs: ");
    output_append_u64(line, capacity, &used, cpu_total);
    output_append(line, capacity, &used, "  NUMA nodes: ");
    output_append_u64(line, capacity, &used, hw->numa_nodes);
    output_append(line, capacity, &used, "  Page: ");
    output_append_u64(line, capacity, &used, hw->page_size / 1024U);
    output_append(line, capacity, &used, " KiB");
    break;
  case 2U:
    if (arm) {
      output_append(line, capacity, &used, "SIMD: NEON ");
      output_append(line, capacity, &used, xtop_yes_no(hw->neon));
      output_append(line, capacity, &used, "  SVE ");
      output_append(line, capacity, &used, xtop_yes_no(hw->sve));
    } else if (x86) {
      output_append(line, capacity, &used, "AVX2 ");
      output_append(line, capacity, &used, xtop_yes_no(hw->avx2));
      output_append(line, capacity, &used, "  AVX-512 ");
      output_append(line, capacity, &used, xtop_yes_no(hw->avx512));
      output_append(line, capacity, &used, "  VNNI ");
      output_append(line, capacity, &used, xtop_yes_no(hw->vnni));
      output_append(line, capacity, &used, "  AMX ");
      output_append(line, capacity, &used, xtop_yes_no(hw->amx));
    } else if (riscv) {
      output_append(line, capacity, &used, "Vector (V) ");
      output_append(line, capacity, &used, xtop_yes_no(hw->rvv));
      output_append(line, capacity, &used, "  Sstc timer ");
      output_append(line, capacity, &used, xtop_yes_no(hw->sstc));
    } else {
      output_append(line, capacity, &used, "Features: unknown");
    }
    break;
  case 3U:
    output_append(line, capacity, &used, "Timer: ");
    output_append_u64(line, capacity, &used, hw->timer_frequency_hz / 1000000U);
    output_append(line, capacity, &used, " MHz  Memory: ");
    output_append_u64(line, capacity, &used, hw->physical_pages / 256U);
    output_append(line, capacity, &used, "M physical, ");
    output_append_u64(line, capacity, &used, hw->managed_pages / 256U);
    output_append(line, capacity, &used, "M managed");
    break;
  default:
    break;
  }
}

/* The AI runtime panel: what this machine accelerates is inference, and
   its figures stand where mactop shows the neural engine. */
static void xtop_ai_line(char *line, uint64_t capacity, uint32_t row) {
  uint64_t used = 0U;
  const xaios_control_metrics_payload_user_t *m = &g_extras.metrics;
  line[0] = '\0';
  if (g_extras.have_metrics == 0) {
    if (row == 0U) output_append(line, capacity, &used, "metrics query unavailable");
    return;
  }
  switch (row) {
  case 0U:
    output_append(line, capacity, &used, "Inferences/s: ");
    output_append_u64(line, capacity, &used, g_extras.inferences_per_s);
    output_append(line, capacity, &used, "  Active: ");
    output_append_u64(line, capacity, &used, m->active_sessions);
    output_append(line, capacity, &used, "  Queue: ");
    output_append_u64(line, capacity, &used, m->queue_depth);
    break;
  case 1U:
    output_append(line, capacity, &used, "Tokens/s: prefill ");
    output_append_u64(line, capacity, &used, m->prefill_tokens_per_second);
    output_append(line, capacity, &used, "  decode ");
    output_append_u64(line, capacity, &used, m->decode_tokens_per_second);
    break;
  case 2U:
    output_append(line, capacity, &used, "First token: ");
    output_append_u64(line, capacity, &used, m->time_to_first_token_ns / 1000000U);
    output_append(line, capacity, &used, " ms  Completed: ");
    output_append_u64(line, capacity, &used, m->requests_completed);
    output_append(line, capacity, &used, "  Failed: ");
    output_append_u64(line, capacity, &used, m->requests_failed);
    break;
  case 3U:
    output_append(line, capacity, &used, "Model resident: ");
    output_append_u64(line, capacity, &used, m->model_resident_bytes / 1048576U);
    output_append(line, capacity, &used, "M  KV cache: ");
    output_append_u64(line, capacity, &used, m->kv_cache_bytes / 1048576U);
    output_append(line, capacity, &used, "M  Workers: ");
    output_append_u64(line, capacity, &used, m->worker_count);
    break;
  default:
    break;
  }
}

static void xtop_netdisk_line(char *line, uint64_t capacity, uint32_t row) {
  uint64_t used = 0U;
  const xaios_control_metrics_payload_user_t *m = &g_extras.metrics;
  line[0] = '\0';
  if (g_extras.have_metrics == 0) {
    if (row == 0U) output_append(line, capacity, &used, "metrics query unavailable");
    return;
  }
  switch (row) {
  case 0U:
    output_append(line, capacity, &used, "Net: \xe2\x86\x91 ");
    xtop_append_rate(line, capacity, &used, g_extras.tx_bytes_per_s);
    output_append(line, capacity, &used, "  \xe2\x86\x93 ");
    xtop_append_rate(line, capacity, &used, g_extras.rx_bytes_per_s);
    break;
  case 1U:
    output_append(line, capacity, &used, "Packets: rx ");
    output_append_u64(line, capacity, &used, m->network_rx_packets);
    output_append(line, capacity, &used, "  tx ");
    output_append_u64(line, capacity, &used, m->network_tx_packets);
    output_append(line, capacity, &used, "  errors ");
    output_append_u64(line, capacity, &used, m->network_errors);
    break;
  case 2U:
    output_append(line, capacity, &used, "Disk I/O: R ");
    output_append_u64(line, capacity, &used, g_extras.reads_per_s);
    output_append(line, capacity, &used, "/s  W ");
    output_append_u64(line, capacity, &used, g_extras.writes_per_s);
    output_append(line, capacity, &used, "/s  (");
    output_append_u64(line, capacity, &used, m->storage_reads);
    output_append(line, capacity, &used, " reads, ");
    output_append_u64(line, capacity, &used, m->storage_writes);
    output_append(line, capacity, &used, " writes)");
    break;
  case 3U:
    output_append(line, capacity, &used, "Log buffer: ");
    output_append_u64(line, capacity, &used, m->log_buffer_bytes / 1024U);
    output_append(line, capacity, &used, "K  overflows ");
    output_append_u64(line, capacity, &used, m->log_overflows);
    break;
  default:
    break;
  }
}

/* A panel\'s vertical edge. */
static void xtop_append_edge(char *output, uint64_t output_capacity,
                             uint64_t *output_bytes) {
  output_append(output, output_capacity, output_bytes,
                XTOP_RESET XTOP_BOX_V);
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
     label + 1 + bar + 2 + 6 + 1: the percentage is six columns because
     "100.0%" is six characters, and it was budgeted as five, which made every
     meter row one column wider than the terminal. A row that is one column too
     wide wraps -- on a real terminal that is a blank line under every meter,
     and the same picture on the framebuffer console, which the local console
     comparison caught. */
  uint32_t label_width = (uint32_t)cstr_len(label);
  uint32_t visible = label_columns + bar_width + XTOP_METER_OVERHEAD;
  uint64_t filled64 = (tenths * bar_width + 999U) / 1000U;
  uint32_t filled = filled64 > bar_width ? bar_width : (uint32_t)filled64;
  output_append(output, output_capacity, output_bytes, XTOP_FG);
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
  output_append(output, output_capacity, output_bytes, "\033[38;5;75m");
  xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BAR_EMPTY,
                         bar_width - filled);
  output_append(output, output_capacity, output_bytes, XTOP_RESET "  \033[1;97m");
  xtop_append_percent_width(output, output_capacity, output_bytes, tenths);
  output_append(output, output_capacity, output_bytes, XTOP_RESET " ");
  if (visible < cell_width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       cell_width - visible);
  }
}

static void xtop_append_key(char *output, uint64_t output_capacity,
                            uint64_t *output_bytes, uint32_t *visible,
                            const char *key, const char *label) {
  output_append(output, output_capacity, output_bytes, XTOP_TITLE);
  output_append(output, output_capacity, output_bytes, key);
  output_append(output, output_capacity, output_bytes, XTOP_RESET);
  output_append(output, output_capacity, output_bytes, label);
  output_append_char(output, output_capacity, output_bytes, ' ');
  *visible += (uint32_t)cstr_len(key) + (uint32_t)cstr_len(label) + 1U;
}

/* The screen's bottom rule, with the keys set into it the way mactop sets
   its own: a corner, a rule, the keys, and the rule out to the far corner. */
static void xtop_append_key_bar(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint32_t columns,
                                int interactive, uint32_t refresh_ms,
                                uint32_t layout) {
  uint32_t visible = 3U;
  /* The redraw cadence by the right corner, the way mactop shows its own
     -/+ interval; nothing when the caller did not say. */
  char cadence[32];
  uint64_t cadence_used = 0U;
  cadence[0] = '\0';
  if (interactive != 0 && refresh_ms != 0U) {
    output_append(cadence, sizeof(cadence), &cadence_used, "-/+ ");
    output_append_u64(cadence, sizeof(cadence), &cadence_used, refresh_ms);
    output_append(cadence, sizeof(cadence), &cadence_used, "ms");
  }
  uint32_t cadence_columns = cadence[0] != '\0' ? xtop_columns(cadence) + 3U : 0U;
  output_append(output, output_capacity, output_bytes,
                XTOP_RESET XTOP_BOX_BL XTOP_BOX_H " ");
  if (interactive != 0) {
    /* "1/3 layout" by the left corner, as mactop counts its own. */
    output_append(output, output_capacity, output_bytes, XTOP_TITLE);
    output_append_u64(output, output_capacity, output_bytes, layout);
    output_append(output, output_capacity, output_bytes, "/");
    output_append_u64(output, output_capacity, output_bytes, XTOP_LAYOUT_COUNT);
    output_append(output, output_capacity, output_bytes, XTOP_RESET " layout  ");
    visible += 2U + (uint32_t)u64_digits(layout) + (uint32_t)u64_digits(XTOP_LAYOUT_COUNT) + 8U;
    xtop_append_key(output, output_capacity, output_bytes, &visible, "L", "Layout");
    xtop_append_key(output, output_capacity, output_bytes, &visible, "F1", "Help");
    xtop_append_key(output, output_capacity, output_bytes, &visible, "F3", "Search");
    xtop_append_key(output, output_capacity, output_bytes, &visible, "F4", "Filter");
    xtop_append_key(output, output_capacity, output_bytes, &visible, "F5", "Tree");
    if (columns >= 80U) {
      xtop_append_key(output, output_capacity, output_bytes, &visible, "F6", "Sort");
      xtop_append_key(output, output_capacity, output_bytes, &visible, "I", "Reverse");
      xtop_append_key(output, output_capacity, output_bytes, &visible, "[/]", "CPUs");
    }
    xtop_append_key(output, output_capacity, output_bytes, &visible, "F10", "Quit");
  } else {
    const char *text = columns < 60U
                           ? "--active --all --sort KEY --plain "
                           : "--active  --all  --sort KEY  --filter TEXT  --cpu-start N  --plain ";
    output_append(output, output_capacity, output_bytes, text);
    visible += (uint32_t)cstr_len(text);
  }
  if (columns < visible + cadence_columns + 1U) cadence_columns = 0U;
  if (columns > visible + cadence_columns + 1U) {
    xtop_append_repeat_str(output, output_capacity, output_bytes, XTOP_BOX_H,
                           columns - visible - cadence_columns - 1U);
  }
  if (cadence_columns != 0U) {
    output_append(output, output_capacity, output_bytes, " " XTOP_TITLE);
    output_append(output, output_capacity, output_bytes, cadence);
    output_append(output, output_capacity, output_bytes, XTOP_RESET " " XTOP_BOX_H);
  }
  output_append(output, output_capacity, output_bytes, XTOP_BOX_BR XTOP_RESET);
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
                  XTOP_FG "Tasks: \033[1;97m");
    output_append_u64(output, output_capacity, output_bytes, active_tasks);
    visible = 7U + (uint32_t)u64_digits(active_tasks);
    if (width >= 40U) {
      output_append(output, output_capacity, output_bytes, XTOP_FG " active, ");
    /* Failures are the one figure that should shout, and only when there
       are any. */
    output_append(output, output_capacity, output_bytes,
                  failed_tasks != 0U ? "\033[1;91m" : XTOP_TITLE);
      output_append_u64(output, output_capacity, output_bytes, failed_tasks);
      output_append(output, output_capacity, output_bytes,
                    XTOP_FG " failed; CPUs: \033[1;97m");
      output_append_u64(output, output_capacity, output_bytes, cpu_total);
      visible += 24U + (uint32_t)u64_digits(failed_tasks) +
                 (uint32_t)u64_digits(cpu_total);
    } else {
      output_append(output, output_capacity, output_bytes, XTOP_FG "  Fail: ");
    output_append(output, output_capacity, output_bytes,
                  failed_tasks != 0U ? "\033[1;91m" : XTOP_TITLE);
      output_append_u64(output, output_capacity, output_bytes, failed_tasks);
      visible += 8U + (uint32_t)u64_digits(failed_tasks);
    }
  } else if (row == 1U) {
    const char *caption = width >= 32U ? "Load average: " : "Load: ";
    output_append(output, output_capacity, output_bytes, XTOP_FG "");
    output_append(output, output_capacity, output_bytes, caption);
    output_append(output, output_capacity, output_bytes, XTOP_TITLE "");
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
                    XTOP_FG "Uptime: \033[1;97m");
      visible = 8U + xtop_append_uptime(output, output_capacity, output_bytes,
                                        now_ns);
    } else {
      uint64_t days = seconds / 86400U;
      uint64_t hours = (seconds / 3600U) % 24U;
      uint64_t minutes = (seconds / 60U) % 60U;
      seconds %= 60U;
      output_append(output, output_capacity, output_bytes,
                    XTOP_FG "Uptime: \033[1;97m");
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
  output_append(output, output_capacity, output_bytes, XTOP_RESET);
  if (visible < width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - visible);
  }
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
    int reverse, int interactive, const char *filter, uint32_t refresh_ms,
    uint32_t layout, int serve_frame) {
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

  /* Per-CPU load for the cores panel and the gauge above it. */
  uint64_t cpu_tenths[64];
  uint64_t cpu_sum = 0U;
  uint32_t cpu_counted = cpu_shown > 64U ? 64U : cpu_shown;
  for (uint32_t offset = 0U; offset < cpu_counted; ++offset) {
    xaios_cpu_usage_snapshot_t usage;
    cpu_tenths[offset] = 0U;
    if (user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) ==
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
  output_append(cpu_title, sizeof(cpu_title), &used, "CPU  ");
  output_append_u64(cpu_title, sizeof(cpu_title), &used, cpu_total);
  output_append(cpu_title, sizeof(cpu_title), &used,
                cpu_total == 1U ? " core  " : " cores  ");
  xtop_append_percent(cpu_title, sizeof(cpu_title), &used, cpu_all_tenths);
  used = 0U;
  mem_title[0] = '\0';
  output_append(mem_title, sizeof(mem_title), &used, "Mem  ");
  output_append_u64(mem_title, sizeof(mem_title), &used, used_mebibytes);
  output_append(mem_title, sizeof(mem_title), &used, "M / ");
  output_append_u64(mem_title, sizeof(mem_title), &used, managed_mebibytes);
  output_append(mem_title, sizeof(mem_title), &used, "M  (Swap 0K / 0K)  ");
  xtop_append_percent(mem_title, sizeof(mem_title), &used, memory_tenths);

  output_append(output, output_capacity, output_bytes, XTOP_RESET "\033[2J\033[H");
  output_append(output, output_capacity, output_bytes,
                interactive != 0 ? "\033[?25l" : "\033[?25h");

  /* Outer top: the title by the left corner, the tab strip by the right.
     "[Main]" stays: the network suites read it to know the screen is up. */
  xtop_append_rule(output, output_capacity, output_bytes, XTOP_BOX_TL,
                   XTOP_BOX_TR,
                   "XAIOS xtop \xe2\x80\x94 sampled kernel process monitor",
                   "[Main]", columns);
  output_append(output, output_capacity, output_bytes, "\r\n");

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
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_panel_top(output, output_capacity, output_bytes, band_left_title,
                        left);
  xtop_append_panel_top(output, output_capacity, output_bytes,
                        band_right_title, right);
  xtop_append_edge(output, output_capacity, output_bytes);
  output_append(output, output_capacity, output_bytes, "\r\n");
  for (uint32_t row = 0U; row < gauge_rows; ++row) {
    int carries = row == gauge_rows / 2U;
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    if (layout == 1U) {
      used = 0U; figure[0] = '\0';
      xtop_append_percent(figure, sizeof(figure), &used, cpu_all_tenths);
      xtop_append_gauge_row(output, output_capacity, output_bytes, left_in,
                            cpu_all_tenths, carries ? figure : 0);
    } else if (layout == 2U) {
      xtop_platform_line(line, sizeof(line), row, cpu_total);
      xtop_append_padded(output, output_capacity, output_bytes, XTOP_FG, line,
                         left_in);
    } else {
      xtop_append_chart_row(output, output_capacity, output_bytes, left_in,
                            g_extras.cpu_history, g_extras.history_count, row,
                            gauge_rows, 1000U);
    }
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    if (layout == 1U) {
      used = 0U; figure[0] = '\0';
      xtop_append_percent(figure, sizeof(figure), &used, memory_tenths);
      xtop_append_gauge_row(output, output_capacity, output_bytes, right_in,
                            memory_tenths, carries ? figure : 0);
    } else if (layout == 2U) {
      xtop_ai_line(line, sizeof(line), row);
      xtop_append_padded(output, output_capacity, output_bytes, XTOP_FG, line,
                         right_in);
    } else {
      xtop_append_chart_row(output, output_capacity, output_bytes, right_in,
                            g_extras.mem_history, g_extras.history_count, row,
                            gauge_rows, 1000U);
    }
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    output_append(output, output_capacity, output_bytes, "\r\n");
  }
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_panel_bottom(output, output_capacity, output_bytes, left);
  xtop_append_panel_bottom(output, output_capacity, output_bytes, right);
  xtop_append_edge(output, output_capacity, output_bytes);
  output_append(output, output_capacity, output_bytes, "\r\n");

  /* The second band: cores beside the system figures, or the network and
     disk figures, or a network history beside the cores. */
  if (detail != 0) {
    const char *detail_left_title = layout == 2U ? "Network & Disk"
                                    : layout == 3U ? "Network history"
                                                   : "Cores";
    const char *detail_right_title = layout == 3U ? "Cores" : "System";
    /* The largest network rate in the window, so the chart has a scale. */
    uint32_t net_scale = 1U;
    for (uint32_t i = 0U; i < g_extras.history_count && i < XTOP_HISTORY; ++i) {
      if (g_extras.net_history[i] > net_scale) net_scale = g_extras.net_history[i];
    }
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_panel_top(output, output_capacity, output_bytes,
                          detail_left_title, left);
    xtop_append_panel_top(output, output_capacity, output_bytes,
                          detail_right_title, right);
    xtop_append_edge(output, output_capacity, output_bytes);
    output_append(output, output_capacity, output_bytes, "\r\n");
    for (uint32_t line_index = 0U; line_index < detail_rows; ++line_index) {
      uint32_t line = line_index;
      xtop_append_edge(output, output_capacity, output_bytes);
      xtop_append_edge(output, output_capacity, output_bytes);
      if (layout == 2U) {
        char text[192];
        xtop_netdisk_line(text, sizeof(text), line);
        xtop_append_padded(output, output_capacity, output_bytes, XTOP_FG,
                           text, left_in);
      } else if (layout == 3U) {
        uint16_t scaled[XTOP_HISTORY];
        for (uint32_t i = 0U; i < XTOP_HISTORY; ++i) {
          uint64_t v = (uint64_t)g_extras.net_history[i] * 1000U / net_scale;
          scaled[i] = (uint16_t)(v > 1000U ? 1000U : v);
        }
        xtop_append_chart_row(output, output_capacity, output_bytes, left_in,
                              scaled, g_extras.history_count, line,
                              detail_rows, 1000U);
      } else if (line < cpu_line_count) {
        uint32_t base_width = left_in / grid_columns;
        for (uint32_t column = 0U; column < grid_columns; ++column) {
          uint32_t cell_width = column + 1U == grid_columns
                                    ? left_in - base_width * column
                                    : base_width;
          uint32_t offset = column * cpu_line_count + line;
          if (offset >= cpu_counted) {
            xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                               cell_width);
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
          xtop_append_meter(output, output_capacity, output_bytes, label,
                            label_columns, cpu_tenths[offset], bar_width,
                            cell_width);
        }
      } else {
        xtop_append_repeat(output, output_capacity, output_bytes, ' ', left_in);
      }
      xtop_append_edge(output, output_capacity, output_bytes);
      xtop_append_edge(output, output_capacity, output_bytes);
      if (layout == 3U) {
        if (line < cpu_line_count) {
          uint32_t base_width = right_in / grid_columns;
          for (uint32_t column = 0U; column < grid_columns; ++column) {
            uint32_t cell_width = column + 1U == grid_columns
                                      ? right_in - base_width * column
                                      : base_width;
            uint32_t offset = column * cpu_line_count + line;
            if (offset >= cpu_counted) {
              xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                                 cell_width);
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
            xtop_append_meter(output, output_capacity, output_bytes, label,
                              label_columns, cpu_tenths[offset], bar_width,
                              cell_width);
          }
        } else {
          xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                             right_in);
        }
      } else if (line < 3U) {
        xtop_append_info_cell(output, output_capacity, output_bytes, line,
                              right_in, active_tasks, failed_tasks, cpu_total,
                              load_average, after_ns);
      } else if (line == 3U) {
        char view[128];
        used = 0U; view[0] = '\0';
        output_append(view, sizeof(view), &used, "View: ");
        output_append(view, sizeof(view), &used,
                      interactive != 0 ? "live" : "snapshot");
        output_append(view, sizeof(view), &used, "  Sort: ");
        output_append(view, sizeof(view), &used, xtop_sort_name(sort_key));
        if (reverse != 0) output_append(view, sizeof(view), &used, " ascending");
        if (filter[0] != '\0') {
          output_append(view, sizeof(view), &used, "  Filter: ");
          output_append(view, sizeof(view), &used, filter);
        }
        if (cpu_start != 0U || cpu_start + cpu_shown < cpu_total) {
          output_append(view, sizeof(view), &used, "  CPU page: ");
          output_append_u64(view, sizeof(view), &used, cpu_start);
          output_append(view, sizeof(view), &used, "-");
          output_append_u64(view, sizeof(view), &used,
                            cpu_shown == 0U ? cpu_start
                                            : cpu_start + cpu_shown - 1U);
          output_append(view, sizeof(view), &used, "/");
          output_append_u64(view, sizeof(view), &used, cpu_total);
        }
        xtop_append_padded(output, output_capacity, output_bytes, XTOP_FG,
                           view, right_in);
      } else {
        xtop_append_repeat(output, output_capacity, output_bytes, ' ', right_in);
      }
      xtop_append_edge(output, output_capacity, output_bytes);
      xtop_append_edge(output, output_capacity, output_bytes);
      output_append(output, output_capacity, output_bytes, "\r\n");
    }
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_panel_bottom(output, output_capacity, output_bytes, left);
    xtop_append_panel_bottom(output, output_capacity, output_bytes, right);
    xtop_append_edge(output, output_capacity, output_bytes);
    output_append(output, output_capacity, output_bytes, "\r\n");
  }

  /* The process list, with its header on a bar. */
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_panel_top(
      output, output_capacity, output_bytes,
      inner >= 70U
          ? "Process List  (\xe2\x86\x91/\xe2\x86\x93 scroll  F3 search  F4 filter  F5 tree)"
          : "Process List",
      inner);
  xtop_append_edge(output, output_capacity, output_bytes);
  output_append(output, output_capacity, output_bytes, "\r\n");
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_padded(
      output, output_capacity, output_bytes, XTOP_HEADER,
      list_in < 60U
          ? " PID S   CPU%   MEM% COMMAND"
          : (list_in < 100U
                 ? "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU COMMAND"
                 : "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU  SYSCALLS COMMAND"),
      list_in);
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_edge(output, output_capacity, output_bytes);
  output_append(output, output_capacity, output_bytes, "\r\n");

  uint32_t list_rows = 0U;
  for (uint32_t i = process_start;
       i < process_count && process_shown < process_budget;
       ++i) {
    uint64_t row_and_footer = ((uint64_t)columns + 96U) * 2U;
    if (*output_bytes >= output_capacity ||
        row_and_footer >= output_capacity - *output_bytes) {
      break;
    }
    const xtop_process_row_t *row = &process_rows[i];
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    output_append(output, output_capacity, output_bytes,
                  i == selected ? XTOP_SELECTED : XTOP_FG);
    uint32_t fixed_visible;
    if (list_in < 60U) {
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
      if (list_in >= 100U) {
        xtop_append_u64_width(output, output_capacity, output_bytes,
                              row->syscall_count, 9U);
        output_append(output, output_capacity, output_bytes, " ");
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
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    output_append(output, output_capacity, output_bytes, "\r\n");
    ++process_shown;
    ++list_rows;
  }
  /* The list keeps its height whatever it holds, so the frame is stable. */
  for (; list_rows < process_budget; ++list_rows) {
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_repeat(output, output_capacity, output_bytes, ' ', list_in);
    xtop_append_edge(output, output_capacity, output_bytes);
    xtop_append_edge(output, output_capacity, output_bytes);
    output_append(output, output_capacity, output_bytes, "\r\n");
  }
  xtop_append_edge(output, output_capacity, output_bytes);
  xtop_append_panel_bottom(output, output_capacity, output_bytes, inner);
  xtop_append_edge(output, output_capacity, output_bytes);
  output_append(output, output_capacity, output_bytes, "\r\n");

  xtop_append_key_bar(output, output_capacity, output_bytes, columns,
                      interactive, refresh_ms, layout);
  output_append(output, output_capacity, output_bytes,
                interactive != 0 ? "\033[?25l" : "\033[?25h");
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
    } else if (string_equal(option, "--serve-frame")) {
      serve_frame = 1;
    } else if (string_equal(option, "--layout")) {
      if (xtop_parse_u32_option(args, &index, &layout) != XAIOS_OK ||
          layout == 0U || layout > XTOP_LAYOUT_COUNT)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --layout must be 1..3");
    } else if (string_equal(option, "--refresh-ms")) {
      if (xtop_parse_u32_option(args, &index, &refresh_ms) != XAIOS_OK ||
          refresh_ms > 60000U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --refresh-ms must be 0..60000");
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

  const xtop_sample_t *retained =
      serve_frame != 0
          ? ring_before(before_meta.sampled_at_ns,
                        (uint64_t)sample_ms * UINT64_C(1000000), cpu_start)
          : 0;
  if (retained != 0) {
    /* The sample just taken is this frame's "after"; the retained one is
       its "before". No wait: the window already elapsed while earlier
       frames were drawn. */
    after_meta = before_meta;
    after_process_count = before_process_count;
    g_cpu_record_count = before_cpu_count;
    xaios_memcpy(g_cpu_records, before_cpus,
                 sizeof(before_cpus[0]) * before_cpu_count);
    before_meta = retained->meta;
    xaios_memcpy(before_runtime, retained->runtime, sizeof(before_runtime));
    before_cpu_count = retained->cpu_count;
    xaios_memcpy(before_cpus, retained->cpus,
                 sizeof(before_cpus[0]) * retained->cpu_count);
  } else {
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
  }
  if (serve_frame != 0) {
    ring_push(&after_meta, process_records, after_process_count,
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
        filter, refresh_ms, layout, serve_frame);
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

/* ---- A serving session: one process, frames for as long as it lasts.
 *
 * sshd used to launch this program once per frame and keep the session's
 * state -- sort key, filter, selection -- on its own side. That put a
 * process launch under every frame, which caps a monitor at a few frames a
 * second whatever the terminal could show. Here the process is started once
 * as a child of the session, keeps its own state, reads keys from the child
 * channel, and writes frames into it at up to sixty a second; the kernel
 * snapshots it draws from are cheap, and the load figures come from the
 * retained-sample ring above rather than from the previous frame. */
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
  output_append(buffer, capacity, used, text);
}

static void serve_append_u32(char *buffer, uint64_t capacity, uint64_t *used,
                             uint32_t value) {
  output_append_u64(buffer, capacity, used, value);
}

/* The options handle_xtop reads, from the state this session keeps. */
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

/* Every few frames, the figures the frame carries besides the process
   table; rates need a previous sample, so the first frame has none. */
static void serve_update_extras(uint64_t now_ns, uint64_t *last_ns,
                                xaios_control_metrics_payload_user_t *last,
                                int *have_last, uint32_t window_ms) {
  if (g_extras.have_hardware == 0) {
    g_extras.have_hardware =
        control_simple_query(XAIOS_CONTROL_OP_HARDWARE,
                             XAIOS_CONTROL_PAYLOAD_HARDWARE, &g_extras.hardware,
                             sizeof(g_extras.hardware)) == 0;
  }
  if (*last_ns != 0U && now_ns - *last_ns < (uint64_t)window_ms * 1000000U) return;
  xaios_control_metrics_payload_user_t fresh;
  if (control_simple_query(XAIOS_CONTROL_OP_METRICS, XAIOS_CONTROL_PAYLOAD_METRICS,
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

static void serve_push_load_history(uint16_t cpu_tenths, uint16_t mem_tenths) {
  history_push16(g_extras.cpu_history, cpu_tenths);
  history_push16(g_extras.mem_history, mem_tenths);
  if (g_extras.history_count < XTOP_HISTORY) ++g_extras.history_count;
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
#define XTOP_GRID_COLUMNS 240U
#define XTOP_GRID_ROWS 100U
#define XTOP_ATTR_DEFAULT 256U
typedef struct xtop_cell {
  uint8_t glyph[4]; /* UTF-8, unused bytes zero */
  uint16_t fg;      /* palette index, or XTOP_ATTR_DEFAULT */
  uint16_t bg;
  uint8_t bold;
  uint8_t pad[3];
} xtop_cell_t;
static xtop_cell_t g_shown[XTOP_GRID_ROWS][XTOP_GRID_COLUMNS];
static xtop_cell_t g_next[XTOP_GRID_ROWS][XTOP_GRID_COLUMNS];
static int g_shown_valid;
static char g_diff[XAIOS_XTOP_OUTPUT_BYTES];

static int cell_equal(const xtop_cell_t *a, const xtop_cell_t *b) {
  return a->glyph[0] == b->glyph[0] && a->glyph[1] == b->glyph[1] &&
         a->glyph[2] == b->glyph[2] && a->glyph[3] == b->glyph[3] &&
         a->fg == b->fg && a->bg == b->bg && a->bold == b->bold;
}

static void grid_clear(xtop_cell_t grid[XTOP_GRID_ROWS][XTOP_GRID_COLUMNS],
                       uint16_t bg, uint32_t rows, uint32_t columns) {
  for (uint32_t r = 0U; r < rows && r < XTOP_GRID_ROWS; ++r) {
    for (uint32_t c = 0U; c < columns && c < XTOP_GRID_COLUMNS; ++c) {
      xtop_cell_t *cell = &grid[r][c];
      cell->glyph[0] = ' '; cell->glyph[1] = 0U; cell->glyph[2] = 0U;
      cell->glyph[3] = 0U;
      cell->fg = XTOP_ATTR_DEFAULT; cell->bg = bg; cell->bold = 0U;
    }
  }
}

/* Read a rendered frame into the grid: the escapes this program itself
   emits, and no others. */
static void grid_from_frame(const char *frame, uint64_t length, uint32_t rows,
                            uint32_t columns) {
  uint16_t fg = XTOP_ATTR_DEFAULT, bg = XTOP_ATTR_DEFAULT;
  uint8_t bold = 0U;
  uint32_t row = 0U, column = 0U;
  grid_clear(g_next, XTOP_ATTR_DEFAULT, rows, columns);
  for (uint64_t i = 0U; i < length;) {
    uint8_t byte = (uint8_t)frame[i];
    if (byte == 0x1bU) {
      if (i + 1U < length && frame[i + 1U] == '[') {
        uint64_t j = i + 2U;
        uint32_t params[8]; uint32_t count = 0U; uint32_t value = 0U;
        int have = 0;
        while (j < length && ((frame[j] >= '0' && frame[j] <= '9') ||
                              frame[j] == ';' || frame[j] == '?')) {
          if (frame[j] == ';') {
            if (count < 8U) params[count++] = value;
            value = 0U; have = 0;
          } else if (frame[j] != '?') {
            value = value * 10U + (uint32_t)(frame[j] - '0'); have = 1;
          }
          ++j;
        }
        if (have && count < 8U) params[count++] = value;
        char final = j < length ? frame[j] : '\0';
        if (final == 'm') {
          if (count == 0U) { fg = XTOP_ATTR_DEFAULT; bg = XTOP_ATTR_DEFAULT; bold = 0U; }
          for (uint32_t k = 0U; k < count; ++k) {
            uint32_t v = params[k];
            if (v == 0U) { fg = XTOP_ATTR_DEFAULT; bg = XTOP_ATTR_DEFAULT; bold = 0U; }
            else if (v == 1U) bold = 1U;
            else if (v >= 30U && v <= 37U) fg = (uint16_t)(v - 30U);
            else if (v >= 90U && v <= 97U) fg = (uint16_t)(v - 90U + 8U);
            else if (v >= 40U && v <= 47U) bg = (uint16_t)(v - 40U);
            else if (v >= 100U && v <= 107U) bg = (uint16_t)(v - 100U + 8U);
            else if ((v == 38U || v == 48U) && k + 2U < count && params[k + 1U] == 5U) {
              if (v == 38U) fg = (uint16_t)params[k + 2U]; else bg = (uint16_t)params[k + 2U];
              k += 2U;
            } else if (v == 39U) fg = XTOP_ATTR_DEFAULT;
            else if (v == 49U) bg = XTOP_ATTR_DEFAULT;
          }
        } else if (final == 'H') {
          row = count >= 1U && params[0] != 0U ? params[0] - 1U : 0U;
          column = count >= 2U && params[1] != 0U ? params[1] - 1U : 0U;
        } else if (final == 'J') {
          grid_clear(g_next, bg, rows, columns);
        }
        i = j < length ? j + 1U : length;
        continue;
      }
      ++i;
      continue;
    }
    ++i;
    if (byte == '\r') { column = 0U; continue; }
    if (byte == '\n') { ++row; column = 0U; continue; }
    if (byte < 0x20U) continue;
    uint32_t glyph_bytes = byte < 0x80U ? 1U : (byte & 0xe0U) == 0xc0U ? 2U
                           : (byte & 0xf0U) == 0xe0U ? 3U : 4U;
    if (column >= columns) { ++row; column = 0U; }
    if (row < rows && row < XTOP_GRID_ROWS && column < XTOP_GRID_COLUMNS) {
      xtop_cell_t *cell = &g_next[row][column];
      for (uint32_t k = 0U; k < 4U; ++k) {
        cell->glyph[k] = k < glyph_bytes && i - 1U + k < length
                             ? (uint8_t)frame[i - 1U + k] : 0U;
      }
      cell->fg = fg; cell->bg = bg; cell->bold = bold;
    }
    ++column;
    i += glyph_bytes - 1U;
  }
}

static void diff_append_attrs(uint64_t *used, const xtop_cell_t *cell) {
  output_append(g_diff, sizeof(g_diff), used, "\033[0");
  if (cell->bold) output_append(g_diff, sizeof(g_diff), used, ";1");
  if (cell->fg != XTOP_ATTR_DEFAULT) {
    output_append(g_diff, sizeof(g_diff), used, ";38;5;");
    output_append_u64(g_diff, sizeof(g_diff), used, cell->fg);
  }
  if (cell->bg != XTOP_ATTR_DEFAULT) {
    output_append(g_diff, sizeof(g_diff), used, ";48;5;");
    output_append_u64(g_diff, sizeof(g_diff), used, cell->bg);
  }
  output_append(g_diff, sizeof(g_diff), used, "m");
}

/* The bytes that turn what the terminal shows into the next grid. Returns
   the length, zero when nothing changed. `full` sends everything, for the
   first frame and after anything that invalidates the terminal. */
static uint64_t diff_build(uint32_t rows, uint32_t columns, int full) {
  uint64_t used = 0U;
  int attrs_known = 0;
  xtop_cell_t current;
  g_diff[0] = '\0';
  bytes_zero(&current, sizeof(current));
  if (full) {
    output_append(g_diff, sizeof(g_diff), &used, "\033[0;48;5;68m\033[2J\033[H\033[?25l");
    grid_clear(g_shown, 68U, rows, columns);
  }
  for (uint32_t r = 0U; r < rows && r < XTOP_GRID_ROWS; ++r) {
    uint32_t c = 0U;
    while (c < columns && c < XTOP_GRID_COLUMNS) {
      if (cell_equal(&g_next[r][c], &g_shown[r][c])) { ++c; continue; }
      /* A run of changed cells, allowing up to two unchanged cells inside
         it: a cursor move costs more than two glyphs. */
      uint32_t end = c;
      uint32_t last_changed = c;
      while (end < columns && end < XTOP_GRID_COLUMNS) {
        if (!cell_equal(&g_next[r][end], &g_shown[r][end])) last_changed = end;
        else if (end - last_changed > 2U) break;
        ++end;
      }
      end = last_changed + 1U;
      output_append(g_diff, sizeof(g_diff), &used, "\033[");
      output_append_u64(g_diff, sizeof(g_diff), &used, r + 1U);
      output_append(g_diff, sizeof(g_diff), &used, ";");
      output_append_u64(g_diff, sizeof(g_diff), &used, c + 1U);
      output_append(g_diff, sizeof(g_diff), &used, "H");
      for (uint32_t k = c; k < end; ++k) {
        const xtop_cell_t *cell = &g_next[r][k];
        if (!attrs_known || cell->fg != current.fg || cell->bg != current.bg ||
            cell->bold != current.bold) {
          diff_append_attrs(&used, cell);
          current = *cell; attrs_known = 1;
        }
        for (uint32_t b = 0U; b < 4U && cell->glyph[b] != 0U; ++b) {
          output_append_char(g_diff, sizeof(g_diff), &used, (char)cell->glyph[b]);
        }
        g_shown[r][k] = *cell;
      }
      c = end;
    }
  }
  if (used != 0U) {
    output_append(g_diff, sizeof(g_diff), &used, "\033[0;48;5;68;38;5;120m\033[?25l");
  }
  g_shown_valid = 1;
  return used;
}

static int serve_render(xtop_serve_state_t *st) {
  uint64_t frame_bytes = 0U;
  g_serve_frame[0] = '\0';
  serve_build_args(st);
  if (handle_xtop(g_serve_args, g_serve_frame, sizeof(g_serve_frame),
                  &frame_bytes) != XAIOS_OK) {
    return -1;
  }
  grid_from_frame(g_serve_frame, frame_bytes, st->rows, st->columns);
  uint64_t diff_bytes = diff_build(st->rows, st->columns, g_shown_valid == 0);
  if (diff_bytes == 0U) return 0;
  return serve_write(g_diff, diff_bytes);
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
  uint64_t cap = sizeof(g_serve_frame);
  uint32_t width = st->columns;
  output_append(out, cap, &used, XTOP_RESET "\033[2J\033[H\033[?25l");
  xtop_append_rule(out, cap, &used, XTOP_BOX_TL, XTOP_BOX_TR, "XAIOS xtop help",
                   0, width);
  output_append(out, cap, &used, "\r\n");
  uint32_t body = st->rows > 3U ? st->rows - 3U : 1U;
  for (uint32_t row = 0U; row < body; ++row) {
    xtop_append_edge(out, cap, &used);
    const char *text = row < sizeof(lines) / sizeof(lines[0]) ? lines[row] : "";
    output_append(out, cap, &used, " ");
    xtop_append_padded(out, cap, &used, XTOP_FG, text, width >= 3U ? width - 3U : 0U);
    xtop_append_edge(out, cap, &used);
    output_append(out, cap, &used, "\r\n");
  }
  xtop_append_rule(out, cap, &used, XTOP_BOX_BL, XTOP_BOX_BR, 0, 0, width);
  g_shown_valid = 0;
  return serve_write(out, used);
}

static int serve_send_filter_prompt(const xtop_serve_state_t *st) {
  uint64_t used = 0U;
  char *out = g_serve_frame;
  uint64_t cap = sizeof(g_serve_frame);
  char line[96];
  uint64_t line_used = 0U;
  uint32_t width = st->columns;
  output_append(out, cap, &used, XTOP_RESET "\033[2J\033[H\033[?25h");
  xtop_append_rule(out, cap, &used, XTOP_BOX_TL, XTOP_BOX_TR,
                   "Process name filter", 0, width);
  output_append(out, cap, &used, "\r\n");
  line[0] = '\0';
  output_append(line, sizeof(line), &line_used, " Filter: ");
  output_append(line, sizeof(line), &line_used, st->filter);
  xtop_append_edge(out, cap, &used);
  xtop_append_padded(out, cap, &used, XTOP_TITLE, line, width >= 2U ? width - 2U : 0U);
  xtop_append_edge(out, cap, &used);
  output_append(out, cap, &used, "\r\n");
  xtop_append_edge(out, cap, &used);
  xtop_append_padded(out, cap, &used, XTOP_FG,
                     " Type one token. Enter applies, Backspace edits, Escape cancels.",
                     width >= 2U ? width - 2U : 0U);
  xtop_append_edge(out, cap, &used);
  output_append(out, cap, &used, "\r\n");
  xtop_append_rule(out, cap, &used, XTOP_BOX_BL, XTOP_BOX_BR, 0, 0, width);
  g_shown_valid = 0;
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
  for (uint32_t i = 0U; i < length; ++i) {
    uint8_t key = data[i];
    if (key == 27U && i + 1U < length && data[i + 1U] == '[') {
      if (i + 2U >= length) return 0;
      uint8_t code = data[i + 2U];
      uint32_t consumed = 3U;
      if (code == 'A') key = 'k';
      else if (code == 'B') key = 'j';
      else if (code == '5' && i + 3U < length && data[i + 3U] == '~') { key = 'U'; consumed = 4U; }
      else if (code == '6' && i + 3U < length && data[i + 3U] == '~') { key = 'D'; consumed = 4U; }
      else if (code == '1' && i + 3U < length) {
        uint8_t function = data[i + 3U];
        consumed = 4U;
        if (function == '1') key = 'h';
        else if (function == '3') key = '/';
        else if (function == '4') key = 'x';
        else if (function == '5') key = 't';
        else if (function == '7') key = 'F';
        else key = 0U;
        if (i + 4U < length && data[i + 4U] == '~') consumed = 5U;
      } else if (code == '2' && i + 4U < length && data[i + 3U] == '1' &&
                 data[i + 4U] == '~') {
        return 2;
      } else {
        key = 0U;
      }
      i += consumed - 1U;
    } else if (key == 27U && i + 2U < length && data[i + 1U] == 'O' &&
               data[i + 2U] == 'P') {
      key = 'h';
      i += 2U;
    }
    if (key == 0U) continue;
    int result = serve_key(st, key, screen_changed);
    if (result == 2) return 2;
    if (result == 1) *redraw = 1;
  }
  return 0;
}

static int xtop_serve(u64 channel_id, const char *command) {
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
  bytes_zero(&st, sizeof(st));
  bytes_zero(&last_metrics, sizeof(last_metrics));
  st.columns = 80U; st.rows = 24U; st.refresh_ms = 250U; st.sample_ms = 250U;
  st.cpu_count = UINT32_MAX; st.layout = 1U; st.sort_key = XTOP_SORT_CPU;
  st.show_all = 1; st.show_cpus = 1;
  /* The command the session built: the same options a one-shot run takes,
     read once into the state this session keeps. The first token is the
     program's own name. */
  (void)token_next(command, &index, option, sizeof(option));
  while (token_next(command, &index, option, sizeof(option)) == XAIOS_OK) {
    uint32_t value = 0U;
    if (string_equal(option, "--columns")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 40U && value <= 240U) st.columns = value; }
    else if (string_equal(option, "--rows")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 12U && value <= 100U) st.rows = value; }
    else if (string_equal(option, "--refresh-ms")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 16U && value <= 5000U) { st.refresh_ms = value; st.sample_ms = value; } }
    else if (string_equal(option, "--sample-ms")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 1U && value <= 1000U) st.sample_ms = value; }
    else if (string_equal(option, "--layout")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value >= 1U && value <= XTOP_LAYOUT_COUNT) st.layout = value; }
    else if (string_equal(option, "--cpu-start")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK) st.cpu_start = value; }
    else if (string_equal(option, "--cpu-count")) { if (xtop_parse_u32_option(command, &index, &value) == XAIOS_OK && value != 0U) st.cpu_count = value; }
    else if (string_equal(option, "--sort")) { if (token_next(command, &index, sort, sizeof(sort)) == XAIOS_OK) { xtop_sort_key_t key; uint64_t dummy = 0U; char text[48]; uint64_t tu = 0U; text[0] = '\0'; output_append(text, sizeof(text), &tu, "--sort "); output_append(text, sizeof(text), &tu, sort); (void)xtop_parse_sort_option(text, &dummy, &key); /* tolerant: a bad key leaves cpu */ st.sort_key = key; } }
    else if (string_equal(option, "--reverse")) st.reverse = 1;
    else if (string_equal(option, "--tree")) st.sort_key = XTOP_SORT_PARENT;
    else if (string_equal(option, "--active")) st.show_all = 0;
    else if (string_equal(option, "--all")) st.show_all = 1;
    else if (string_equal(option, "--no-cpus")) st.show_cpus = 0;
    else if (string_equal(option, "--filter")) { if (token_next(command, &index, st.filter, sizeof(st.filter)) == XAIOS_OK) st.filter_length = (uint32_t)cstr_len(st.filter); }
  }
  g_arena_used = 0U;
  g_shown_valid = 0;
  if (serve_write("\033[?1049h\033[?25l", 14U) != 0) return 1;
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
    if (st.help != 0) {
      if (screen_changed != 0 && serve_send_help(&st) != 0) break;
      serve_pause_ms(20U);
      continue;
    }
    if (st.filter_mode != 0) {
      if (screen_changed != 0 && serve_send_filter_prompt(&st) != 0) break;
      serve_pause_ms(20U);
      continue;
    }
    /* A new sample when the sampling interval has passed, or at once when
       a key changed what is shown; between samples the process sleeps, and
       a frame that changed nothing was not sent. Sixty frames a second is
       how soon a change is on the screen, not how often the screen is
       written. */
    if (redraw != 0 || now_ns >= next_frame_ns) {
      serve_update_extras(now_ns, &last_metrics_ns, &last_metrics,
                          &have_last_metrics, st.sample_ms);
      if (serve_render(&st) != 0) break;
      if (now_ns - last_history_ns >= (uint64_t)st.sample_ms * 1000000U) {
        serve_push_load_history(g_last_cpu_tenths, g_last_mem_tenths);
        last_history_ns = now_ns;
      }
      next_frame_ns = xaios_clock_nanos() + (uint64_t)st.sample_ms * 1000000U;
      continue;
    }
    uint64_t wait_ns = next_frame_ns - now_ns;
    uint32_t wait_ms = (uint32_t)(wait_ns / 1000000U);
    serve_pause_ms(wait_ms > 16U ? 16U : (wait_ms == 0U ? 1U : wait_ms));
  }
  (void)serve_write("\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r", 24U);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4) {
    /* Started as a session's child: argv[1] is the channel, argv[3] the
       command the session built. */
    u64 channel = 0U;
    const char *text = argv[1];
    for (uint32_t i = 0U; text[i] != '\0'; ++i) {
      if (text[i] < '0' || text[i] > '9') { channel = 0U; break; }
      channel = channel * 10U + (u64)(text[i] - '0');
    }
    if (channel != 0U) return xtop_serve(channel, argv[3]);
  }
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
