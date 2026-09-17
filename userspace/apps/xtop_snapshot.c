#include "xtop_snapshot.h"

static uint64_t g_request_id = 1U;
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
int xtop_snapshot_simple_query(uint32_t operation, uint32_t payload_type,
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

void xtop_snapshot_ring_push(
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
int xtop_snapshot_gather_cpu_page(
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
int xtop_snapshot_gather_snapshot(
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
static int xtop_name_compare(const char *lhs, const char *rhs) {
  uint32_t index = 0U;
  while (lhs[index] != '\0' && rhs[index] != '\0' &&
         lhs[index] == rhs[index]) {
    ++index;
  }
  return (int)(uint8_t)lhs[index] - (int)(uint8_t)rhs[index];
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
void xtop_snapshot_sort_rows(xtop_process_row_t *rows, uint32_t count,
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
int xtop_snapshot_arrange_tree(xtop_process_row_t *rows, uint32_t count) {
  xtop_process_row_t *ordered;
  uint32_t *stack_index;
  uint32_t *stack_depth;
  uint8_t *emitted;
  uint32_t output_count = 0U;
  if (count == 0U) return 0;
  ordered = (xtop_process_row_t *)xtop_arena_alloc(
      (uint64_t)count * sizeof(*ordered), 16U);
  stack_index = (uint32_t *)xtop_arena_alloc(
      (uint64_t)count * sizeof(*stack_index), 16U);
  stack_depth = (uint32_t *)xtop_arena_alloc(
      (uint64_t)count * sizeof(*stack_depth), 16U);
  emitted = (uint8_t *)xtop_arena_alloc(count, 16U);
  if (ordered == 0 || stack_index == 0 || stack_depth == 0 || emitted == 0) {
    xtop_arena_free(ordered);
    xtop_arena_free(stack_index);
    xtop_arena_free(stack_depth);
    xtop_arena_free(emitted);
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
  xtop_arena_free(ordered);
  xtop_arena_free(stack_index);
  xtop_arena_free(stack_depth);
  xtop_arena_free(emitted);
  return output_count == count ? 0 : -1;
}

/* The wait half of a sample: the kernel delays the reply by wait_ms and the
   payload is discarded because the caller samples again for its "after". */
int xtop_snapshot_wait(uint32_t wait_ms) {
  xaios_control_runtime_snapshot_payload_user_t result;
  return runtime_query(0U, 0U, 0U, 0U, wait_ms, &result);
}

/* The retained sample a frame draws its "before" from.  `has` only decides;
   `read` copies the same sample into caller-owned buffers, so no pointer
   into the ring leaves this file. */
int xtop_snapshot_ring_has(uint64_t now_ns, uint64_t window_ns,
                           uint32_t cpu_start) {
  return ring_before(now_ns, window_ns, cpu_start) != 0;
}

int xtop_snapshot_ring_read(
    uint64_t now_ns, uint64_t window_ns, uint32_t cpu_start,
    xaios_control_runtime_snapshot_payload_user_t *meta,
    uint64_t *runtime_by_pid, uint32_t runtime_capacity,
    xaios_control_runtime_cpu_record_user_t *cpus, uint32_t cpu_capacity,
    uint32_t *cpu_count) {
  const xtop_sample_t *sample = ring_before(now_ns, window_ns, cpu_start);
  if (sample == 0) return 0;
  *meta = sample->meta;
  if (runtime_by_pid != 0) {
    for (uint32_t i = 0U;
         i < runtime_capacity && i <= XAIOS_XTOP_MAX_PROCESSES; ++i)
      runtime_by_pid[i] = sample->runtime[i];
  }
  *cpu_count = sample->cpu_count < cpu_capacity ? sample->cpu_count
                                                : cpu_capacity;
  xaios_memcpy(cpus, sample->cpus, sizeof(cpus[0]) * *cpu_count);
  return 1;
}
