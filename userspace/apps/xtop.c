#include <xaios_user.h>
#include <xaios_screen.h>
#include <xaios/types.h>
#include "ssh_child_ipc.h"
#include "xtop_serve.h"
#include "xtop_render.h"
#include "xtop_glyph.h"
#include "xtop_draw.h"

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
#define XAIOS_XTOP_ARENA_BYTES 131072U

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

/* The render arena is the renderer's; the session only clears it. */
void xtop_arena_reset(void) { g_arena_used = 0U; }

void xtop_bytes_zero(void *buffer, uint64_t size) {
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
  xtop_bytes_zero(result, size);
  g_arena_used = offset + size;
  return result;
}

static void kheap_free(void *pointer) { (void)pointer; }

uint64_t xtop_cstr_len(const char *text) {
  uint64_t size = 0U;
  if (text == 0) return 0U;
  while (text[size] != '\0') ++size;
  return size;
}

int xtop_string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

static int contains_substring(const char *text, const char *needle) {
  uint64_t needle_size = xtop_cstr_len(needle);
  if (needle_size == 0U) return 1;
  for (uint64_t i = 0U; text != 0 && text[i] != '\0'; ++i) {
    uint64_t j = 0U;
    while (j < needle_size && text[i + j] == needle[j]) ++j;
    if (j == needle_size) return 1;
  }
  return 0;
}

static xaios_status_t output_append_char(char *output, uint64_t capacity,
                                         uint64_t *offset, char value) {
  if (output == 0 || offset == 0 || *offset + 1U >= capacity)
    return XAIOS_ERR_NO_MEMORY;
  output[(*offset)++] = value;
  output[*offset] = '\0';
  return XAIOS_OK;
}

xaios_status_t xtop_output_append(char *output, uint64_t capacity,
                                  uint64_t *offset, const char *text) {
  if (text == 0) return XAIOS_ERR_INVALID;
  while (*text != '\0') {
    if (output_append_char(output, capacity, offset, *text++) != XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

xaios_status_t xtop_output_append_u64(char *output, uint64_t capacity,
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
  (void)xtop_output_append(output, capacity, offset, message);
  (void)xtop_output_append(output, capacity, offset, "\n");
  return XAIOS_ERR_INVALID;
}

static uint64_t skip_ws(const char *text, uint64_t index) {
  while (text[index] == ' ' || text[index] == '\t' ||
         text[index] == '\r' || text[index] == '\n')
    ++index;
  return index;
}

xaios_status_t xtop_token_next(const char *text, uint64_t *index,
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
  xtop_bytes_zero(&request, sizeof(request));
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
  xtop_bytes_zero(&request, sizeof(request));
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

static xtop_extras_t g_extras;

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
  xtop_bytes_zero(slot->runtime, sizeof(slot->runtime));
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

/* One snapshot for both pages: the kernel fills CPU and process records in
   the same reply, and a frame that asked twice paid for the snapshot twice
   -- most of what the monitor cost, under emulation. Pages beyond the first
   are fetched only when there are more CPUs or processes than one reply
   carries. */
static int gather_snapshot(
    uint32_t cpu_start, uint32_t cpu_want,
    xaios_control_runtime_cpu_record_user_t *cpus, uint32_t cpu_capacity,
    uint32_t *cpu_count,
    xaios_control_runtime_process_record_user_t *records, uint32_t capacity,
    uint64_t *runtime_by_pid, uint32_t *count,
    xaios_control_runtime_snapshot_payload_user_t *metadata) {
  xaios_control_runtime_snapshot_payload_user_t page;
  uint32_t cpu_limit = cpu_want > XAIOS_CONTROL_RUNTIME_CPU_MAX
                           ? XAIOS_CONTROL_RUNTIME_CPU_MAX : cpu_want;
  *cpu_count = 0U;
  *count = 0U;
  if (runtime_by_pid != 0)
    for (uint32_t i = 0U; i <= XAIOS_XTOP_MAX_PROCESSES; ++i)
      runtime_by_pid[i] = 0U;
  if (runtime_query(cpu_start, cpu_limit, 0U,
                    XAIOS_CONTROL_RUNTIME_PROCESS_MAX, 0U, &page) != 0)
    return -1;
  *metadata = page;
  for (uint32_t i = 0U; i < page.cpu_count && *cpu_count < cpu_capacity; ++i)
    cpus[(*cpu_count)++] = page.cpus[i];
  for (uint32_t i = 0U; i < page.process_count; ++i) {
    const xaios_control_runtime_process_record_user_t *source =
        &page.processes[i];
    if (source->pid <= XAIOS_XTOP_MAX_PROCESSES && runtime_by_pid != 0)
      runtime_by_pid[source->pid] = source->runtime_ns;
    if (*count < capacity) records[(*count)++] = *source;
  }
  uint32_t cursor = page.process_next;
  while (cursor != UINT32_MAX) {
    xaios_control_runtime_snapshot_payload_user_t more;
    if (runtime_query(0U, 0U, cursor, XAIOS_CONTROL_RUNTIME_PROCESS_MAX, 0U,
                      &more) != 0)
      return -1;
    for (uint32_t i = 0U; i < more.process_count; ++i) {
      const xaios_control_runtime_process_record_user_t *source =
          &more.processes[i];
      if (source->pid <= XAIOS_XTOP_MAX_PROCESSES && runtime_by_pid != 0)
        runtime_by_pid[source->pid] = source->runtime_ns;
      if (*count < capacity) records[(*count)++] = *source;
    }
    if (more.process_next == UINT32_MAX || more.process_next <= cursor) break;
    cursor = more.process_next;
  }
  uint32_t cpu_cursor = page.cpu_next;
  while (*cpu_count < cpu_want && *cpu_count < cpu_capacity &&
         cpu_cursor != UINT32_MAX) {
    xaios_control_runtime_snapshot_payload_user_t more;
    uint32_t limit = cpu_want - *cpu_count;
    if (limit > XAIOS_CONTROL_RUNTIME_CPU_MAX)
      limit = XAIOS_CONTROL_RUNTIME_CPU_MAX;
    if (runtime_query(cpu_cursor, limit, 0U, 0U, 0U, &more) != 0) return -1;
    for (uint32_t i = 0U; i < more.cpu_count && *cpu_count < cpu_capacity; ++i)
      cpus[(*cpu_count)++] = more.cpus[i];
    if (more.cpu_next == UINT32_MAX || more.cpu_next <= cpu_cursor) break;
    cpu_cursor = more.cpu_next;
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

const char *xtop_sort_name(xtop_sort_key_t key) {
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

uint64_t xtop_capacity_tenths(uint64_t numerator,
                                     uint64_t denominator) {
  uint64_t tenths = xtop_ratio_tenths(numerator, denominator);
  return tenths > UINT64_C(1000) ? UINT64_C(1000) : tenths;
}

void xtop_append_percent(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint64_t tenths) {
  xtop_output_append_u64(output, output_capacity, output_bytes, tenths / 10U);
  xtop_output_append(output, output_capacity, output_bytes, ".");
  xtop_output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  xtop_output_append(output, output_capacity, output_bytes, "%");
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

void xtop_append_u64_width(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, uint64_t value,
                                  uint32_t width) {
  uint64_t digits = xtop_u64_digits(value);
  if (digits < width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - (uint32_t)digits);
  }
  xtop_output_append_u64(output, output_capacity, output_bytes, value);
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

xaios_status_t xtop_parse_u32_option(const char *args, uint64_t *index,
                                     uint32_t *value) {
  char token[24];
  uint64_t parsed = 0U;
  uint64_t consumed = 0U;
  if (xtop_token_next(args, index, token, sizeof(token)) != XAIOS_OK ||
      parse_u64_token(token, &parsed, &consumed) != XAIOS_OK ||
      consumed != xtop_cstr_len(token) || parsed > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  *value = (uint32_t)parsed;
  return XAIOS_OK;
}

xaios_status_t xtop_parse_sort_option(const char *args, uint64_t *index,
                                      xtop_sort_key_t *key) {
  char value[24];
  if (xtop_token_next(args, index, value, sizeof(value)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (xtop_string_equal(value, "cpu") == 1U) *key = XTOP_SORT_CPU;
  else if (xtop_string_equal(value, "mem") == 1U) *key = XTOP_SORT_MEMORY;
  else if (xtop_string_equal(value, "time") == 1U) *key = XTOP_SORT_TIME;
  else if (xtop_string_equal(value, "pid") == 1U) *key = XTOP_SORT_PID;
  else if (xtop_string_equal(value, "state") == 1U) *key = XTOP_SORT_STATE;
  else if (xtop_string_equal(value, "syscalls") == 1U) *key = XTOP_SORT_SYSCALLS;
  else if (xtop_string_equal(value, "command") == 1U) *key = XTOP_SORT_COMMAND;
  else if (xtop_string_equal(value, "parent") == 1U) *key = XTOP_SORT_PARENT;
  else return XAIOS_ERR_INVALID;
  return XAIOS_OK;
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
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --sort key");
    } else if (xtop_string_equal(option, "--filter")) {
      if (xtop_token_next(args, &index, filter, sizeof(filter)) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --filter");
    } else if (xtop_string_equal(option, "--process-start")) {
      if (xtop_parse_u32_option(args, &index, &process_start) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --process-start");
    } else if (xtop_string_equal(option, "--selected")) {
      if (xtop_parse_u32_option(args, &index, &selected) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --selected");
    } else if (xtop_string_equal(option, "--serve-frame")) {
      serve_frame = 1;
    } else if (xtop_string_equal(option, "--layout")) {
      if (xtop_parse_u32_option(args, &index, &layout) != XAIOS_OK ||
          layout == 0U || layout > XTOP_LAYOUT_COUNT)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --layout must be 1..3");
    } else if (xtop_string_equal(option, "--refresh-ms")) {
      if (xtop_parse_u32_option(args, &index, &refresh_ms) != XAIOS_OK ||
          refresh_ms > 60000U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --refresh-ms must be 0..60000");
    } else if (xtop_string_equal(option, "--columns")) {
      if (xtop_parse_u32_option(args, &index, &terminal_columns) != XAIOS_OK ||
          terminal_columns < 40U || terminal_columns > 240U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --columns must be 40..240");
    } else if (xtop_string_equal(option, "--rows")) {
      if (xtop_parse_u32_option(args, &index, &terminal_rows) != XAIOS_OK ||
          terminal_rows < 12U || terminal_rows > 100U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: --rows must be 12..100");
    } else if (xtop_string_equal(option, "--cpu-start")) {
      if (xtop_parse_u32_option(args, &index, &cpu_start) != XAIOS_OK)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --cpu-start");
    } else if (xtop_string_equal(option, "--cpu-count")) {
      if (xtop_parse_u32_option(args, &index, &cpu_requested) != XAIOS_OK ||
          cpu_requested == 0U)
        return command_fail(output, output_capacity, output_bytes,
                            "xtop: invalid --cpu-count");
    } else if (xtop_string_equal(option, "--sample-ms")) {
      if (xtop_parse_u32_option(args, &index, &sample_ms) != XAIOS_OK ||
          sample_ms == 0U || sample_ms > 1000U)
        return command_fail(output, output_capacity, output_bytes,
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
      return command_fail(output, output_capacity, output_bytes,
                          "xtop: unsupported option; use xtop --help");
    }
  }

  if (gather_snapshot(cpu_start, show_cpus != 0 ? cpu_requested : 0U,
                      before_cpus, XAIOS_XTOP_CPU_PAGE_MAX, &before_cpu_count,
                      process_records, XAIOS_XTOP_MAX_PROCESSES,
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
      gather_cpu_page(cpu_start, cpu_shown, before_cpus,
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
    if (gather_snapshot(cpu_start, cpu_shown, g_cpu_records,
                        XAIOS_XTOP_CPU_PAGE_MAX, &g_cpu_record_count,
                        process_records, XAIOS_XTOP_MAX_PROCESSES, 0,
                        &after_process_count, &after_meta) != 0)
      return command_fail(output, output_capacity, output_bytes,
                          "xtop: runtime snapshot unavailable");
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

/* Every few frames, the figures the frame carries besides the process
   table; rates need a previous sample, so the first frame has none. */
void xtop_serve_update_extras(uint64_t now_ns, uint64_t *last_ns,
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

void xtop_serve_push_load_history(uint16_t cpu_tenths, uint16_t mem_tenths) {
  history_push16(g_extras.cpu_history, cpu_tenths);
  history_push16(g_extras.mem_history, mem_tenths);
  if (g_extras.history_count < XTOP_HISTORY) ++g_extras.history_count;
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
  int status = xtop_handle(args, output, sizeof(output), &output_size);
  if (output_size != 0U)
    (void)xaios_console_write(output, output_size);
  return status == XAIOS_OK ? 0 : 1;
}
