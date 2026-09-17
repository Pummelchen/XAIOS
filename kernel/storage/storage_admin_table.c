/*
 * The partition-table half of storage admin: the shared byte and string
 * helpers, GUID derivation, usable-LBA geometry, table read and write with
 * read-back verification, partition registration, and the request and plan
 * validation the command layer uses. See storage_admin_internal.h.
 *
 * Split out of a 1184-line storage_admin.c together with
 * storage_admin_self_test.c. The one attached device's state and the two GPT
 * scratch buffers are defined here, because this is the file that reads and
 * writes the table; the public command layer in storage_admin.c and the
 * self-test include the private header and borrow them.
 */

#include <xaios/block_device.h>
#include <xaios/gpt.h>
#include <xaios/partition_device.h>
#include <xaios/storage_admin.h>

#include "storage_admin_internal.h"

storage_admin_state_t g_sa_state;
uint8_t g_sa_read_scratch[XAIOS_GPT_READ_SCRATCH_BYTES];
uint8_t g_sa_write_scratch[XAIOS_GPT_WRITE_SCRATCH_BYTES];

void sa_bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

static void bytes_copy(void *destination, const void *source,
                       uint64_t length) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < length; ++index) out[index] = in[index];
}

static uint64_t string_length(const char *value, uint64_t capacity) {
  uint64_t length = 0U;
  if (value == 0) return capacity;
  while (length < capacity && value[length] != '\0') ++length;
  return length;
}

int sa_string_equal(const char *left, const char *right) {
  if (left == 0 || right == 0) return 0;
  for (uint64_t index = 0U; index < XAIOS_BLOCK_DEVICE_ID_MAX; ++index) {
    if (left[index] != right[index]) return 0;
    if (left[index] == '\0') return 1;
  }
  return 0;
}

void sa_string_copy(char *destination, uint64_t capacity,
                    const char *source) {
  uint64_t index = 0U;
  while (index + 1U < capacity && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  destination[index] = '\0';
}

static int info_equal(const xaios_block_device_info_t *left,
                      const xaios_block_device_info_t *right) {
  return sa_string_equal(left->identifier, right->identifier) &&
         left->capacity_bytes == right->capacity_bytes &&
         left->capacity_logical_sectors == right->capacity_logical_sectors &&
         left->logical_sector_size == right->logical_sector_size &&
         left->read_only == right->read_only &&
         left->flush_supported == right->flush_supported;
}

static void append_decimal(char *output, uint64_t capacity, uint64_t *offset,
                           uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U && count < sizeof(digits));
  while (count != 0U && *offset + 1U < capacity) {
    output[(*offset)++] = digits[--count];
  }
  output[*offset] = '\0';
}

static xaios_status_t partition_identifier(
    const char *parent, uint32_t table_index,
    char output[XAIOS_BLOCK_DEVICE_ID_MAX]) {
  uint64_t length = string_length(parent, XAIOS_BLOCK_DEVICE_ID_MAX);
  if (length == 0U || length + 2U >= XAIOS_BLOCK_DEVICE_ID_MAX ||
      table_index >= XAIOS_GPT_ENTRY_COUNT) {
    return XAIOS_ERR_INVALID;
  }
  bytes_copy(output, parent, length);
  output[length++] = 'p';
  output[length] = '\0';
  append_decimal(output, XAIOS_BLOCK_DEVICE_ID_MAX, &length,
                 table_index + 1U);
  return output[length] == '\0' ? XAIOS_OK : XAIOS_ERR_INVALID;
}

uint32_t sa_known_type(const xaios_guid_t *type) {
  if (gpt_guid_equal(type, &XAIOS_GPT_TYPE_STATEFS)) {
    return XAIOS_STORAGE_PARTITION_STATE;
  }
  if (gpt_guid_equal(type, &XAIOS_GPT_TYPE_MODELFS)) {
    return XAIOS_STORAGE_PARTITION_MODEL;
  }
  if (gpt_guid_equal(type, &XAIOS_GPT_TYPE_RECOVERY)) {
    return XAIOS_STORAGE_PARTITION_RECOVERY;
  }
  if (gpt_guid_equal(type, &XAIOS_GPT_TYPE_ESP)) {
    return XAIOS_STORAGE_PARTITION_ESP;
  }
  return 0U;
}

const xaios_guid_t *sa_type_guid(uint32_t type) {
  if (type == XAIOS_STORAGE_PARTITION_STATE) return &XAIOS_GPT_TYPE_STATEFS;
  if (type == XAIOS_STORAGE_PARTITION_MODEL) return &XAIOS_GPT_TYPE_MODELFS;
  if (type == XAIOS_STORAGE_PARTITION_RECOVERY) {
    return &XAIOS_GPT_TYPE_RECOVERY;
  }
  if (type == XAIOS_STORAGE_PARTITION_ESP) return &XAIOS_GPT_TYPE_ESP;
  return 0;
}

xaios_status_t sa_record_from_partition(
    const xaios_gpt_partition_t *partition,
    xaios_storage_partition_record_t *record) {
  if (partition == 0 || record == 0 ||
      partition->table_index_valid == 0U ||
      partition->table_index >= XAIOS_GPT_ENTRY_COUNT ||
      partition_identifier(g_sa_state.info.identifier, partition->table_index,
                           record->identifier) != XAIOS_OK ||
      gpt_guid_format(&partition->type_guid, record->type_guid) != XAIOS_OK ||
      gpt_guid_format(&partition->unique_guid, record->unique_guid) !=
          XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t index = 0U; index < XAIOS_GPT_NAME_CODE_UNITS; ++index) {
    uint16_t unit = partition->name[index];
    if (unit == 0U) break;
    record->name[index] =
        unit >= 0x20U && unit <= 0x7eU ? (char)unit : '?';
  }
  record->first_lba = partition->first_lba;
  record->last_lba = partition->last_lba;
  uint64_t sectors = partition->last_lba - partition->first_lba + 1U;
  if (sectors > UINT64_MAX / g_sa_state.info.logical_sector_size) {
    return XAIOS_ERR_INVALID;
  }
  record->size_bytes = sectors * g_sa_state.info.logical_sector_size;
  record->attributes = partition->attributes;
  record->table_index = partition->table_index;
  record->known_type = sa_known_type(&partition->type_guid);
  return XAIOS_OK;
}

xaios_status_t sa_fill_report(const xaios_gpt_table_t *table,
                              xaios_storage_partition_report_t *report) {
  if (table == 0 || report == 0) return XAIOS_ERR_INVALID;
  sa_bytes_zero(report, sizeof(*report));
  sa_string_copy(report->device_identifier, sizeof(report->device_identifier),
                 g_sa_state.info.identifier);
  if (gpt_guid_format(&table->disk_guid, report->disk_guid) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  report->capacity_bytes = g_sa_state.info.capacity_bytes;
  report->logical_sector_size = g_sa_state.info.logical_sector_size;
  report->first_usable_lba = table->first_usable_lba;
  report->last_usable_lba = table->last_usable_lba;
  report->partition_count = table->partition_count;
  report->primary_valid = table->primary_valid;
  report->backup_valid = table->backup_valid;
  report->copies_consistent = table->copies_consistent;
  report->selected_copy = table->selected_copy;
  report->mutation_allowed = g_sa_state.mutation_allowed;
  return XAIOS_OK;
}

static void derive_disk_guid(xaios_guid_t *guid) {
  uint64_t first = UINT64_C(1469598103934665603);
  uint64_t second = UINT64_C(1099511628211);
  const uint8_t *identifier =
      (const uint8_t *)(const void *)g_sa_state.info.identifier;
  uint64_t length = string_length(g_sa_state.info.identifier,
                                  sizeof(g_sa_state.info.identifier));
  for (uint64_t index = 0U; index < length; ++index) {
    first = (first ^ identifier[index]) * UINT64_C(1099511628211);
    second = (second + identifier[index]) * UINT64_C(1469598103934665603);
  }
  first ^= g_sa_state.info.capacity_bytes;
  second ^= g_sa_state.info.logical_sector_size;
  for (uint32_t index = 0U; index < 8U; ++index) {
    guid->bytes[index] = (uint8_t)(first >> (index * 8U));
    guid->bytes[8U + index] = (uint8_t)(second >> (index * 8U));
  }
  guid->bytes[6] = (uint8_t)((guid->bytes[6] & 0x0fU) | 0x50U);
  guid->bytes[8] = (uint8_t)((guid->bytes[8] & 0x3fU) | 0x80U);
}

void sa_derive_partition_guid(const xaios_guid_t *disk_guid,
                              uint64_t operation_id,
                              uint32_t table_index, xaios_guid_t *guid) {
  *guid = *disk_guid;
  for (uint32_t index = 0U; index < 8U; ++index) {
    guid->bytes[index] ^= (uint8_t)(operation_id >> (index * 8U));
  }
  guid->bytes[12] ^= (uint8_t)table_index;
  guid->bytes[13] ^= (uint8_t)(table_index >> 8U);
  guid->bytes[6] = (uint8_t)((guid->bytes[6] & 0x0fU) | 0x50U);
  guid->bytes[8] = (uint8_t)((guid->bytes[8] & 0x3fU) | 0x80U);
}

static xaios_status_t table_geometry(xaios_gpt_table_t *table) {
  uint64_t entry_bytes =
      (uint64_t)XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE;
  uint64_t entry_sectors =
      (entry_bytes + g_sa_state.info.logical_sector_size - 1U) /
      g_sa_state.info.logical_sector_size;
  if (g_sa_state.info.capacity_logical_sectors <= 3U + 2U * entry_sectors) {
    return XAIOS_ERR_INVALID;
  }
  table->first_usable_lba = 2U + entry_sectors;
  table->last_usable_lba =
      g_sa_state.info.capacity_logical_sectors - 2U - entry_sectors;
  return XAIOS_OK;
}

xaios_status_t sa_read_table(xaios_gpt_table_t *table,
                             uint32_t allow_unformatted) {
  xaios_status_t status = gpt_read(g_sa_state.device, table, g_sa_read_scratch,
                                   sizeof(g_sa_read_scratch));
  if (status == XAIOS_OK) return status;
  if (allow_unformatted == 0U || status != XAIOS_ERR_INVALID) return status;
  const uint64_t probe_bytes = UINT64_C(1048576);
  uint64_t sector_size = g_sa_state.info.logical_sector_size;
  uint64_t edge_bytes = g_sa_state.info.capacity_bytes < probe_bytes
                            ? g_sa_state.info.capacity_bytes
                            : probe_bytes;
  edge_bytes -= edge_bytes % sector_size;
  uint64_t offsets[2] = {0U, g_sa_state.info.capacity_bytes - edge_bytes};
  for (uint32_t edge = 0U; edge < 2U; ++edge) {
    if (edge != 0U && offsets[edge] < edge_bytes) continue;
    for (uint64_t offset = offsets[edge];
         offset < offsets[edge] + edge_bytes; offset += sector_size) {
      if (block_read(g_sa_state.device, offset, g_sa_read_scratch, sector_size) !=
          XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      for (uint64_t byte = 0U; byte < sector_size; ++byte) {
        if (g_sa_read_scratch[byte] != 0U) return XAIOS_ERR_INVALID;
      }
    }
  }
  sa_bytes_zero(table, sizeof(*table));
  derive_disk_guid(&table->disk_guid);
  table->selected_copy = XAIOS_GPT_COPY_NONE;
  return table_geometry(table);
}

xaios_status_t sa_register_partition(
    const xaios_gpt_partition_t *partition) {
  if (partition->table_index_valid == 0U ||
      partition->table_index >= XAIOS_GPT_MAX_PARTITIONS) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed =
      &g_sa_state.partitions[partition->table_index];
  if (managed->active != 0U) return XAIOS_ERR_BUSY;
  sa_bytes_zero(managed, sizeof(*managed));
  managed->descriptor = *partition;
  if (partition_identifier(g_sa_state.info.identifier, partition->table_index,
                           managed->identifier) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = partition_device_register(
      &managed->device, g_sa_state.device, managed->identifier, partition, 0U);
  if (status == XAIOS_OK) managed->active = 1U;
  return status;
}

xaios_status_t sa_unregister_partition(uint32_t table_index) {
  if (table_index >= XAIOS_GPT_MAX_PARTITIONS ||
      g_sa_state.partitions[table_index].active == 0U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  managed_partition_t *managed = &g_sa_state.partitions[table_index];
  uint32_t open_count = 0U;
  if (block_device_open_count(&managed->device.block_device, &open_count) !=
          XAIOS_OK ||
      open_count != 0U) {
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = partition_device_unregister(&managed->device);
  if (status == XAIOS_OK) sa_bytes_zero(managed, sizeof(*managed));
  return status;
}

xaios_status_t sa_validate_target_device(const char *identifier) {
  if (g_sa_state.attached == 0U || identifier == 0 ||
      !sa_string_equal(identifier, g_sa_state.info.identifier)) {
    return XAIOS_ERR_NOT_FOUND;
  }
  return XAIOS_OK;
}

static xaios_status_t revalidate_device(void) {
  xaios_block_device_info_t current;
  return block_device_info(g_sa_state.device, &current) == XAIOS_OK &&
                 info_equal(&current, &g_sa_state.info)
             ? XAIOS_OK
             : XAIOS_ERR_BUSY;
}

xaios_status_t sa_validate_confirmation(
    const char *confirmation, const xaios_guid_t *expected) {
  xaios_guid_t supplied;
  return gpt_guid_parse(confirmation, &supplied) == XAIOS_OK &&
                 gpt_guid_equal(&supplied, expected)
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

static int table_equal(const xaios_gpt_table_t *left,
                       const xaios_gpt_table_t *right) {
  if (!gpt_guid_equal(&left->disk_guid, &right->disk_guid) ||
      left->partition_count != right->partition_count) {
    return 0;
  }
  for (uint64_t index = 0U; index < left->partition_count; ++index) {
    const xaios_gpt_partition_t *a = &left->partitions[index];
    int found = 0;
    for (uint64_t other = 0U; other < right->partition_count; ++other) {
      const xaios_gpt_partition_t *b = &right->partitions[other];
      if (a->table_index == b->table_index &&
          gpt_guid_equal(&a->type_guid, &b->type_guid) &&
          gpt_guid_equal(&a->unique_guid, &b->unique_guid) &&
          a->first_lba == b->first_lba && a->last_lba == b->last_lba &&
          a->attributes == b->attributes) {
        found = 1;
        break;
      }
    }
    if (!found) return 0;
  }
  return 1;
}

xaios_status_t sa_write_and_verify(const xaios_gpt_table_t *table) {
  if (revalidate_device() != XAIOS_OK) return XAIOS_ERR_BUSY;
  xaios_status_t status = gpt_write(
      g_sa_state.device, &table->disk_guid, table->partitions,
      table->partition_count, 0U, XAIOS_GPT_FAULT_NONE, g_sa_write_scratch,
      sizeof(g_sa_write_scratch));
  if (status != XAIOS_OK) return status;
  xaios_gpt_table_t verified;
  status = sa_read_table(&verified, 0U);
  if (status != XAIOS_OK || verified.primary_valid == 0U ||
      verified.backup_valid == 0U || verified.copies_consistent == 0U ||
      !table_equal(table, &verified)) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t sa_request_valid(
    const xaios_storage_partition_request_t *request, uint32_t mutation,
    uint32_t require_name) {
  if (request == 0 || request->reserved != 0U ||
      (mutation != 0U && request->operation_id == 0U) ||
      string_length(request->target, sizeof(request->target)) ==
          sizeof(request->target) ||
      string_length(request->target, sizeof(request->target)) == 0U ||
      string_length(request->confirmation, sizeof(request->confirmation)) ==
          sizeof(request->confirmation) ||
      string_length(request->name, sizeof(request->name)) ==
          sizeof(request->name) ||
      (require_name != 0U &&
       string_length(request->name, sizeof(request->name)) == 0U) ||
      (mutation != 0U && g_sa_state.mutation_allowed == 0U)) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t index = 0U; request->name[index] != '\0'; ++index) {
    if ((uint8_t)request->name[index] < 0x20U ||
        (uint8_t)request->name[index] > 0x7eU) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

uint64_t sa_aligned_up(uint64_t value, uint64_t alignment) {
  if (alignment == 0U || value > UINT64_MAX - (alignment - 1U)) {
    return UINT64_MAX;
  }
  return (value + alignment - 1U) / alignment * alignment;
}

int sa_lba_range_free(const xaios_gpt_table_t *table, uint64_t first,
                      uint64_t last, uint32_t ignored_table_index) {
  for (uint64_t index = 0U; index < table->partition_count; ++index) {
    const xaios_gpt_partition_t *partition = &table->partitions[index];
    if (partition->table_index == ignored_table_index) continue;
    if (!(last < partition->first_lba || first > partition->last_lba)) {
      return 0;
    }
  }
  return 1;
}

uint32_t sa_first_free_table_index(const xaios_gpt_table_t *table) {
  for (uint32_t candidate = 0U; candidate < XAIOS_GPT_ENTRY_COUNT;
       ++candidate) {
    int used = 0;
    for (uint64_t index = 0U; index < table->partition_count; ++index) {
      if (table->partitions[index].table_index == candidate) used = 1;
    }
    if (!used) return candidate;
  }
  return XAIOS_GPT_ENTRY_COUNT;
}

xaios_status_t storage_admin_partition_repair(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result) {
  if (result == 0 || sa_request_valid(request, 1U, 0U) != XAIOS_OK ||
      sa_validate_target_device(request->target) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_gpt_table_t table;
  xaios_status_t status = sa_read_table(&table, 0U);
  if (status != XAIOS_OK || table.primary_valid == table.backup_valid ||
      sa_validate_confirmation(request->confirmation, &table.disk_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  for (uint64_t index = 0U; index < table.partition_count; ++index) {
    managed_partition_t *managed =
        &g_sa_state.partitions[table.partitions[index].table_index];
    uint32_t open_count = 0U;
    if (managed->active == 0U ||
        block_device_open_count(&managed->device.block_device, &open_count) !=
            XAIOS_OK ||
        open_count != 0U) {
      return XAIOS_ERR_BUSY;
    }
  }
  sa_bytes_zero(result, sizeof(*result));
  if (sa_fill_report(&table, &result->report) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  status = sa_write_and_verify(&table);
  if (status != XAIOS_OK) return status;
  result->report.primary_valid = 1U;
  result->report.backup_valid = 1U;
  result->report.copies_consistent = 1U;
  result->resulting_partition_count = table.partition_count;
  result->changed = 1U;
  result->dry_run = 0U;
  return XAIOS_OK;
}
