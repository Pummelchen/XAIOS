/* Read-only report operations and their text helpers.
 *
 * Split out of control_protocol.c so no source file exceeds 500 lines. This
 * file carries the block-device list/show pair, the paged runtime-snapshot
 * filler, and the string/log-record formatting helpers they, control_ops.c's
 * handle_logs and control_protocol_self_test share. The self-test stays in
 * control_protocol.c and reaches these helpers through the prefixed exports
 * control_protocol_internal.h declares. The bodies below were written against
 * control_protocol.c's file-local helper names; the aliases bind them to the
 * prefixed exports the private header declares.
 */

#include "control_protocol_internal.h"

#include <xaios/admin_control.h>
#include <xaios/block_device.h>
#include <xaios/pmm.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/user.h>

#define bytes_zero control_protocol_bytes_zero
#define bytes_copy control_protocol_bytes_copy
#define write_response control_protocol_write_response
#define write_error control_protocol_write_error
#define fixed_string_valid control_protocol_fixed_string_valid

static uint64_t string_length(const char *text) {
  uint64_t length = 0;
  if (text == 0) {
    return 0;
  }
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

static int string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint64_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

static void string_copy(char *dst, uint64_t capacity, const char *src) {
  uint64_t offset = 0;
  if (dst == 0 || capacity == 0) {
    return;
  }
  while (src != 0 && src[offset] != '\0' && offset + 1U < capacity) {
    dst[offset] = src[offset];
    ++offset;
  }
  dst[offset] = '\0';
}

static char ascii_lower(char value) {
  if (value >= 'A' && value <= 'Z') {
    return (char)(value + ('a' - 'A'));
  }
  return value;
}

static int line_contains_case_insensitive(const char *line, uint64_t line_size,
                                          const char *needle) {
  uint64_t needle_size = string_length(needle);
  if (line == 0 || needle_size == 0U || needle_size > line_size) {
    return 0;
  }
  for (uint64_t i = 0; i + needle_size <= line_size; ++i) {
    uint64_t j = 0;
    while (j < needle_size &&
           ascii_lower(line[i + j]) == ascii_lower(needle[j])) {
      ++j;
    }
    if (j == needle_size) {
      return 1;
    }
  }
  return 0;
}

static int log_line_sensitive(const char *line, uint64_t line_size) {
  static const char *patterns[] = {
      "password", "passwd", "secret", "authorization", "bearer ",
      "private key", "private_key", "access_token", "api_key"};
  for (uint32_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
    if (line_contains_case_insensitive(line, line_size, patterns[i])) {
      return 1;
    }
  }
  return 0;
}

static xaios_status_t append_text(char *output, uint64_t capacity,
                                  uint64_t *offset, const char *text) {
  if (output == 0 || offset == 0 || text == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    if (*offset >= capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    output[*offset] = text[i];
    ++(*offset);
  }
  return XAIOS_OK;
}

static xaios_status_t append_u64(char *output, uint64_t capacity,
                                 uint64_t *offset, uint64_t value) {
  char digits[24];
  uint64_t count = 0;
  if (value == 0U) {
    return append_text(output, capacity, offset, "0");
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  while (count != 0U) {
    if (*offset >= capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    output[*offset] = digits[--count];
    ++(*offset);
  }
  return XAIOS_OK;
}

static xaios_status_t append_log_record(
    char *output, uint64_t capacity, uint64_t *offset, uint64_t sequence,
    const char *component, const char *level, const char *line,
    uint64_t line_size, int redact) {
  if (append_text(output, capacity, offset, "seq=") != XAIOS_OK ||
      append_u64(output, capacity, offset, sequence) != XAIOS_OK ||
      append_text(output, capacity, offset,
                  " time=unknown level=") != XAIOS_OK ||
      append_text(output, capacity, offset, level) != XAIOS_OK ||
      append_text(output, capacity, offset, " component=") != XAIOS_OK ||
      append_text(output, capacity, offset, component) != XAIOS_OK ||
      append_text(output, capacity, offset,
                  " request_id=unknown message=") != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (redact != 0) {
    if (append_text(output, capacity, offset, "[redacted]") != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  } else {
    for (uint64_t i = 0; i < line_size; ++i) {
      char value = line[i];
      if ((uint8_t)value < UINT8_C(32) && value != '\t') {
        value = '?';
      }
      if (*offset >= capacity) {
        return XAIOS_ERR_NO_MEMORY;
      }
      output[*offset] = value;
      ++(*offset);
    }
  }
  return append_text(output, capacity, offset, "\n");
}

int control_protocol_string_equal(const char *lhs, const char *rhs) {
  return string_equal(lhs, rhs);
}

/* The log helpers the self-test exercises live here now; control_ops.c and
   control_protocol.c reach them through the private header so handle_logs,
   log_level and the self-test read as they always did. */
void control_protocol_string_copy(char *dst, uint64_t capacity,
                                  const char *src) {
  string_copy(dst, capacity, src);
}
int control_protocol_line_contains_case_insensitive(const char *line,
                                                    uint64_t line_size,
                                                    const char *needle) {
  return line_contains_case_insensitive(line, line_size, needle);
}
int control_protocol_log_line_sensitive(const char *line, uint64_t line_size) {
  return log_line_sensitive(line, line_size);
}
xaios_status_t control_protocol_append_log_record(
    char *output, uint64_t capacity, uint64_t *offset, uint64_t sequence,
    const char *component, const char *level, const char *line,
    uint64_t line_size, int redact) {
  return append_log_record(output, capacity, offset, sequence, component,
                           level, line, line_size, redact);
}

static xaios_control_status_t storage_control_status(xaios_status_t status) {
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_CONTROL_STATUS_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_CONTROL_STATUS_CONFLICT;
  }
  if (status == XAIOS_ERR_INVALID) return XAIOS_CONTROL_STATUS_INVALID_REQUEST;
  return XAIOS_CONTROL_STATUS_INTERNAL;
}

static xaios_admin_result_t storage_admin_result(xaios_status_t status) {
  if (status == XAIOS_OK) return XAIOS_ADMIN_RESULT_OK;
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_ADMIN_RESULT_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_ADMIN_RESULT_CONFLICT;
  }
  if (status == XAIOS_ERR_IO) return XAIOS_ADMIN_RESULT_IO;
  return XAIOS_ADMIN_RESULT_INVALID;
}

xaios_control_status_t control_protocol_storage_status(xaios_status_t status) {
  return storage_control_status(status);
}
xaios_admin_result_t control_protocol_storage_admin_result(
    xaios_status_t status) {
  return storage_admin_result(status);
}

static void storage_device_record(
    xaios_control_storage_device_record_t *record,
    const xaios_block_device_info_t *info) {
  bytes_zero(record, sizeof(*record));
  string_copy(record->identifier, sizeof(record->identifier), info->identifier);
  string_copy(record->backend, sizeof(record->backend), info->backend);
  record->capacity_bytes = info->capacity_bytes;
  record->capacity_logical_sectors = info->capacity_logical_sectors;
  record->logical_sector_size = info->logical_sector_size;
  record->physical_block_size = info->physical_block_size;
  record->max_transfer_bytes = info->max_transfer_bytes;
  record->discard_granularity = info->discard_granularity;
  record->max_discard_bytes = info->max_discard_bytes;
  record->read_bytes = info->read_bytes;
  record->write_bytes = info->write_bytes;
  record->discarded_bytes = info->discarded_bytes;
  record->io_errors = info->io_errors;
  record->read_only = info->read_only;
  record->flush_supported = info->flush_supported;
  record->discard_supported = info->discard_supported;
  record->write_zeroes_supported = info->write_zeroes_supported;
}

xaios_status_t control_protocol_handle_storage_devices(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes) {
  struct storage_device_response {
    xaios_control_storage_devices_payload_t metadata;
    xaios_control_storage_device_record_t
        records[XAIOS_CONTROL_STORAGE_MAX_DEVICES];
  } value;
  xaios_block_device_info_t infos[XAIOS_CONTROL_STORAGE_MAX_DEVICES];
  bytes_zero(&value, sizeof(value));
  bytes_zero(infos, sizeof(infos));

  if (request->operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST) {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    uint64_t total = 0U;
    xaios_status_t status = block_device_list(
        infos, XAIOS_CONTROL_STORAGE_MAX_DEVICES, &total);
    if (status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    value.metadata.total_count =
        total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
    value.metadata.record_count =
        total > XAIOS_CONTROL_STORAGE_MAX_DEVICES
            ? XAIOS_CONTROL_STORAGE_MAX_DEVICES
            : (uint32_t)total;
    value.metadata.truncated =
        total > XAIOS_CONTROL_STORAGE_MAX_DEVICES ? 1U : 0U;
    for (uint32_t index = 0U; index < value.metadata.record_count; ++index) {
      storage_device_record(&value.records[index], &infos[index]);
    }
  } else {
    xaios_control_path_request_payload_t query;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_PATH_REQUEST ||
        request->payload_length != sizeof(query)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (!fixed_string_valid(query.path, sizeof(query.path))) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    xaios_block_device_t *device = 0;
    xaios_status_t status = block_device_open(query.path, &device);
    if (status == XAIOS_ERR_NOT_FOUND) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_NOT_FOUND);
    }
    if (status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    status = block_device_info(device, &infos[0]);
    xaios_status_t close_status = block_device_close(device);
    if (status != XAIOS_OK || close_status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    value.metadata.record_count = 1U;
    value.metadata.total_count = 1U;
    storage_device_record(&value.records[0], &infos[0]);
  }

  uint64_t payload_size = sizeof(value.metadata) +
                          (uint64_t)value.metadata.record_count *
                              sizeof(value.records[0]);
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES, &value,
                        payload_size);
}

xaios_status_t control_protocol_fill_runtime_snapshot(
    const xaios_control_runtime_snapshot_request_t *request,
    xaios_control_runtime_snapshot_payload_t *payload) {
  uint64_t now_ns;
  uint32_t next_cpu;
  uint32_t next_process;
  if (request == 0 || payload == 0 || request->reserved != 0U ||
      request->cpu_limit > XAIOS_CONTROL_RUNTIME_CPU_MAX ||
      request->process_limit > XAIOS_CONTROL_RUNTIME_PROCESS_MAX ||
      request->process_start > XAIOS_MAX_USER_PROCESSES ||
      request->wait_ms > 1000U) {
    return XAIOS_ERR_INVALID;
  }
  if (request->wait_ms != 0U) {
    uint64_t start_ns = timer_now_ns();
    uint64_t wait_ns = (uint64_t)request->wait_ms * UINT64_C(1000000);
    uint64_t deadline_ns = start_ns > UINT64_MAX - wait_ns
                               ? UINT64_MAX
                               : start_ns + wait_ns;
    user_process_idle_until(deadline_ns);
  }
  now_ns = timer_now_ns();
  bytes_zero(payload, sizeof(*payload));
  payload->sampled_at_ns = now_ns;
  payload->cpu_busy_total_ns = user_cpu_busy_total(now_ns);
  payload->physical_pages = pmm_total_pages();
  payload->managed_pages = pmm_managed_pages();
  payload->free_pages = pmm_free_pages();
  payload->cpu_total = user_cpu_usage_count();
  payload->cpu_start = request->cpu_start > payload->cpu_total
                           ? payload->cpu_total
                           : request->cpu_start;
  payload->process_capacity = XAIOS_MAX_USER_PROCESSES;
  payload->process_start = request->process_start;
  payload->process_active = (uint32_t)user_process_active_count();
  payload->process_failed = (uint32_t)user_process_current_failed_count();
  scheduler_load_average_hundredths(payload->load_average_hundredths);

  next_cpu = payload->cpu_start;
  while (next_cpu < payload->cpu_total &&
         payload->cpu_count < request->cpu_limit) {
    xaios_cpu_usage_snapshot_t usage;
    xaios_control_runtime_cpu_record_t *record =
        &payload->cpus[payload->cpu_count];
    uint32_t ordinal = next_cpu++;
    if (user_cpu_usage_snapshot(ordinal, now_ns, &usage) != XAIOS_OK) {
      continue;
    }
    const xaios_cpu_state_t *state = smp_cpu_state(usage.cpu_id);
    record->cpu_id = usage.cpu_id;
    record->active_pid = usage.active_pid;
    record->role = state == 0 ? XAIOS_CPU_ROLE_OFFLINE : (uint32_t)state->role;
    record->busy_ns = usage.busy_ns;
    record->elapsed_ns = usage.elapsed_ns;
    ++payload->cpu_count;
  }
  payload->cpu_next =
      request->cpu_limit != 0U && next_cpu < payload->cpu_total
          ? next_cpu
          : UINT32_MAX;

  next_process = request->process_start;
  for (uint32_t pid = request->process_start + 1U;
       pid <= XAIOS_MAX_USER_PROCESSES &&
       payload->process_count < request->process_limit;
       ++pid) {
    xaios_user_process_t process;
    next_process = pid;
    if (user_process_snapshot_at(pid, now_ns, &process) != XAIOS_OK) {
      continue;
    }
    xaios_control_runtime_process_record_t *record =
        &payload->processes[payload->process_count++];
    record->pid = process.pid;
    record->parent_pid = process.parent_pid;
    record->cpu_id = process.running_cpu_id;
    record->state = (uint32_t)process.state;
    record->runtime_ns = process.runtime_ns;
    record->resident_pages = process.resident_pages;
    record->syscall_count = process.syscall_count;
    string_copy(record->name, sizeof(record->name),
                process.name == 0 ? "(unknown)" : process.name);
  }
  payload->process_next =
      request->process_limit != 0U && next_process < XAIOS_MAX_USER_PROCESSES
          ? next_process
          : UINT32_MAX;
  return XAIOS_OK;
}
