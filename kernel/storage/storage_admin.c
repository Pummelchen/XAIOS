#include <xaios/storage_admin.h>
#include <xaios/fat.h>
#include <xaios/klog.h>

#include <xaios/partition_device.h>

#define STORAGE_ALIGNMENT_BYTES UINT64_C(1048576)

typedef struct managed_partition {
  xaios_partition_device_t device;
  xaios_gpt_partition_t descriptor;
  char identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  uint32_t active;
} managed_partition_t;

typedef struct storage_admin_state {
  xaios_block_device_t *device;
  xaios_block_device_info_t info;
  managed_partition_t partitions[XAIOS_GPT_MAX_PARTITIONS];
  uint32_t mutation_allowed;
  uint32_t attached;
} storage_admin_state_t;

static storage_admin_state_t g_storage;
static uint8_t g_read_scratch[XAIOS_GPT_READ_SCRATCH_BYTES];
static uint8_t g_write_scratch[XAIOS_GPT_WRITE_SCRATCH_BYTES];

static void bytes_zero(void *buffer, uint64_t length) {
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

static int string_equal(const char *left, const char *right) {
  if (left == 0 || right == 0) return 0;
  for (uint64_t index = 0U; index < XAIOS_BLOCK_DEVICE_ID_MAX; ++index) {
    if (left[index] != right[index]) return 0;
    if (left[index] == '\0') return 1;
  }
  return 0;
}

static void string_copy(char *destination, uint64_t capacity,
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
  return string_equal(left->identifier, right->identifier) &&
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

static uint32_t known_type(const xaios_guid_t *type) {
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

static const xaios_guid_t *type_guid(uint32_t type) {
  if (type == XAIOS_STORAGE_PARTITION_STATE) return &XAIOS_GPT_TYPE_STATEFS;
  if (type == XAIOS_STORAGE_PARTITION_MODEL) return &XAIOS_GPT_TYPE_MODELFS;
  if (type == XAIOS_STORAGE_PARTITION_RECOVERY) {
    return &XAIOS_GPT_TYPE_RECOVERY;
  }
  if (type == XAIOS_STORAGE_PARTITION_ESP) return &XAIOS_GPT_TYPE_ESP;
  return 0;
}

static xaios_status_t record_from_partition(
    const xaios_gpt_partition_t *partition,
    xaios_storage_partition_record_t *record) {
  if (partition == 0 || record == 0 ||
      partition->table_index_valid == 0U ||
      partition->table_index >= XAIOS_GPT_ENTRY_COUNT ||
      partition_identifier(g_storage.info.identifier, partition->table_index,
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
  if (sectors > UINT64_MAX / g_storage.info.logical_sector_size) {
    return XAIOS_ERR_INVALID;
  }
  record->size_bytes = sectors * g_storage.info.logical_sector_size;
  record->attributes = partition->attributes;
  record->table_index = partition->table_index;
  record->known_type = known_type(&partition->type_guid);
  return XAIOS_OK;
}

static xaios_status_t fill_report(const xaios_gpt_table_t *table,
                                  xaios_storage_partition_report_t *report) {
  if (table == 0 || report == 0) return XAIOS_ERR_INVALID;
  bytes_zero(report, sizeof(*report));
  string_copy(report->device_identifier, sizeof(report->device_identifier),
              g_storage.info.identifier);
  if (gpt_guid_format(&table->disk_guid, report->disk_guid) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  report->capacity_bytes = g_storage.info.capacity_bytes;
  report->logical_sector_size = g_storage.info.logical_sector_size;
  report->first_usable_lba = table->first_usable_lba;
  report->last_usable_lba = table->last_usable_lba;
  report->partition_count = table->partition_count;
  report->primary_valid = table->primary_valid;
  report->backup_valid = table->backup_valid;
  report->copies_consistent = table->copies_consistent;
  report->selected_copy = table->selected_copy;
  report->mutation_allowed = g_storage.mutation_allowed;
  return XAIOS_OK;
}

static void derive_disk_guid(xaios_guid_t *guid) {
  uint64_t first = UINT64_C(1469598103934665603);
  uint64_t second = UINT64_C(1099511628211);
  const uint8_t *identifier =
      (const uint8_t *)(const void *)g_storage.info.identifier;
  uint64_t length = string_length(g_storage.info.identifier,
                                  sizeof(g_storage.info.identifier));
  for (uint64_t index = 0U; index < length; ++index) {
    first = (first ^ identifier[index]) * UINT64_C(1099511628211);
    second = (second + identifier[index]) * UINT64_C(1469598103934665603);
  }
  first ^= g_storage.info.capacity_bytes;
  second ^= g_storage.info.logical_sector_size;
  for (uint32_t index = 0U; index < 8U; ++index) {
    guid->bytes[index] = (uint8_t)(first >> (index * 8U));
    guid->bytes[8U + index] = (uint8_t)(second >> (index * 8U));
  }
  guid->bytes[6] = (uint8_t)((guid->bytes[6] & 0x0fU) | 0x50U);
  guid->bytes[8] = (uint8_t)((guid->bytes[8] & 0x3fU) | 0x80U);
}

static void derive_partition_guid(const xaios_guid_t *disk_guid,
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
      (entry_bytes + g_storage.info.logical_sector_size - 1U) /
      g_storage.info.logical_sector_size;
  if (g_storage.info.capacity_logical_sectors <= 3U + 2U * entry_sectors) {
    return XAIOS_ERR_INVALID;
  }
  table->first_usable_lba = 2U + entry_sectors;
  table->last_usable_lba =
      g_storage.info.capacity_logical_sectors - 2U - entry_sectors;
  return XAIOS_OK;
}

static xaios_status_t read_table(xaios_gpt_table_t *table,
                                 uint32_t allow_unformatted) {
  xaios_status_t status = gpt_read(g_storage.device, table, g_read_scratch,
                                   sizeof(g_read_scratch));
  if (status == XAIOS_OK) return status;
  if (allow_unformatted == 0U || status != XAIOS_ERR_INVALID) return status;
  const uint64_t probe_bytes = UINT64_C(1048576);
  uint64_t sector_size = g_storage.info.logical_sector_size;
  uint64_t edge_bytes = g_storage.info.capacity_bytes < probe_bytes
                            ? g_storage.info.capacity_bytes
                            : probe_bytes;
  edge_bytes -= edge_bytes % sector_size;
  uint64_t offsets[2] = {0U, g_storage.info.capacity_bytes - edge_bytes};
  for (uint32_t edge = 0U; edge < 2U; ++edge) {
    if (edge != 0U && offsets[edge] < edge_bytes) continue;
    for (uint64_t offset = offsets[edge];
         offset < offsets[edge] + edge_bytes; offset += sector_size) {
      if (block_read(g_storage.device, offset, g_read_scratch, sector_size) !=
          XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      for (uint64_t byte = 0U; byte < sector_size; ++byte) {
        if (g_read_scratch[byte] != 0U) return XAIOS_ERR_INVALID;
      }
    }
  }
  bytes_zero(table, sizeof(*table));
  derive_disk_guid(&table->disk_guid);
  table->selected_copy = XAIOS_GPT_COPY_NONE;
  return table_geometry(table);
}

static xaios_status_t register_partition(
    const xaios_gpt_partition_t *partition) {
  if (partition->table_index_valid == 0U ||
      partition->table_index >= XAIOS_GPT_MAX_PARTITIONS) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed =
      &g_storage.partitions[partition->table_index];
  if (managed->active != 0U) return XAIOS_ERR_BUSY;
  bytes_zero(managed, sizeof(*managed));
  managed->descriptor = *partition;
  if (partition_identifier(g_storage.info.identifier, partition->table_index,
                           managed->identifier) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = partition_device_register(
      &managed->device, g_storage.device, managed->identifier, partition, 0U);
  if (status == XAIOS_OK) managed->active = 1U;
  return status;
}

static xaios_status_t unregister_partition(uint32_t table_index) {
  if (table_index >= XAIOS_GPT_MAX_PARTITIONS ||
      g_storage.partitions[table_index].active == 0U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  managed_partition_t *managed = &g_storage.partitions[table_index];
  uint32_t open_count = 0U;
  if (block_device_open_count(&managed->device.block_device, &open_count) !=
          XAIOS_OK ||
      open_count != 0U) {
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = partition_device_unregister(&managed->device);
  if (status == XAIOS_OK) bytes_zero(managed, sizeof(*managed));
  return status;
}

static xaios_status_t validate_target_device(const char *identifier) {
  if (g_storage.attached == 0U || identifier == 0 ||
      !string_equal(identifier, g_storage.info.identifier)) {
    return XAIOS_ERR_NOT_FOUND;
  }
  return XAIOS_OK;
}

static xaios_status_t revalidate_device(void) {
  xaios_block_device_info_t current;
  return block_device_info(g_storage.device, &current) == XAIOS_OK &&
                 info_equal(&current, &g_storage.info)
             ? XAIOS_OK
             : XAIOS_ERR_BUSY;
}

static xaios_status_t validate_confirmation(
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

static xaios_status_t write_and_verify(const xaios_gpt_table_t *table) {
  if (revalidate_device() != XAIOS_OK) return XAIOS_ERR_BUSY;
  xaios_status_t status = gpt_write(
      g_storage.device, &table->disk_guid, table->partitions,
      table->partition_count, 0U, XAIOS_GPT_FAULT_NONE, g_write_scratch,
      sizeof(g_write_scratch));
  if (status != XAIOS_OK) return status;
  xaios_gpt_table_t verified;
  status = read_table(&verified, 0U);
  if (status != XAIOS_OK || verified.primary_valid == 0U ||
      verified.backup_valid == 0U || verified.copies_consistent == 0U ||
      !table_equal(table, &verified)) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t storage_admin_attach(xaios_block_device_t *device,
                                    uint32_t mutation_allowed) {
  if (device == 0 || mutation_allowed > 1U || g_storage.attached != 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK ||
      info.read_only != 0U || info.flush_supported == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  bytes_zero(&g_storage, sizeof(g_storage));
  g_storage.device = device;
  g_storage.info = info;
  g_storage.mutation_allowed = mutation_allowed;
  g_storage.attached = 1U;
  xaios_gpt_table_t table;
  xaios_status_t status = read_table(&table, 0U);
  if (status == XAIOS_ERR_INVALID) return XAIOS_OK;
  if (status != XAIOS_OK) {
    bytes_zero(&g_storage, sizeof(g_storage));
    return status;
  }
  for (uint64_t index = 0U; index < table.partition_count; ++index) {
    status = register_partition(&table.partitions[index]);
    if (status != XAIOS_OK) {
      (void)storage_admin_detach();
      return status;
    }
  }
  return XAIOS_OK;
}

xaios_status_t storage_admin_detach(void) {
  if (g_storage.attached == 0U) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t index = 0U; index < XAIOS_GPT_MAX_PARTITIONS; ++index) {
    if (g_storage.partitions[index].active != 0U &&
        unregister_partition(index) != XAIOS_OK) {
      return XAIOS_ERR_BUSY;
    }
  }
  bytes_zero(&g_storage, sizeof(g_storage));
  return XAIOS_OK;
}

xaios_status_t storage_admin_partition_list(
    const char *device_identifier, xaios_storage_partition_record_t *records,
    uint64_t capacity, uint64_t *out_count,
    xaios_storage_partition_report_t *report) {
  if (out_count == 0 || report == 0 ||
      (capacity != 0U && records == 0) ||
      validate_target_device(device_identifier) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_gpt_table_t table;
  xaios_status_t status = read_table(&table, 0U);
  if (status != XAIOS_OK || fill_report(&table, report) != XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  for (uint64_t index = 0U; index < table.partition_count && index < capacity;
       ++index) {
    bytes_zero(&records[index], sizeof(records[index]));
    if (record_from_partition(&table.partitions[index], &records[index]) !=
        XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  }
  *out_count = table.partition_count;
  return XAIOS_OK;
}

xaios_status_t storage_admin_partition_verify(
    const char *device_identifier, xaios_storage_partition_report_t *report) {
  uint64_t count = 0U;
  return storage_admin_partition_list(device_identifier, 0, 0U, &count,
                                      report);
}

static xaios_status_t request_valid(
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
      (mutation != 0U && g_storage.mutation_allowed == 0U)) {
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

static uint64_t aligned_up(uint64_t value, uint64_t alignment) {
  if (alignment == 0U || value > UINT64_MAX - (alignment - 1U)) {
    return UINT64_MAX;
  }
  return (value + alignment - 1U) / alignment * alignment;
}

static int lba_range_free(const xaios_gpt_table_t *table, uint64_t first,
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

static uint32_t first_free_table_index(const xaios_gpt_table_t *table) {
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

static xaios_status_t plan_create(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan, xaios_gpt_table_t *resulting) {
  if (request_valid(request, 0U, 1U) != XAIOS_OK || plan == 0 ||
      resulting == 0 || type_guid(request->partition_type) == 0 ||
      validate_target_device(request->target) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = read_table(resulting, 1U);
  if (status != XAIOS_OK ||
      (resulting->selected_copy != XAIOS_GPT_COPY_NONE &&
       (resulting->primary_valid == 0U || resulting->backup_valid == 0U ||
        resulting->copies_consistent == 0U)) ||
      resulting->partition_count >= XAIOS_GPT_MAX_PARTITIONS) {
    return status != XAIOS_OK ? status : XAIOS_ERR_BUSY;
  }
  uint32_t slot = first_free_table_index(resulting);
  if (slot == XAIOS_GPT_ENTRY_COUNT) return XAIOS_ERR_NO_MEMORY;
  uint64_t alignment_lbas =
      STORAGE_ALIGNMENT_BYTES / g_storage.info.logical_sector_size;
  if (alignment_lbas == 0U) alignment_lbas = 1U;
  uint64_t requested_lbas = 0U;
  if (request->size_bytes != 0U) {
    if (request->size_bytes >
        UINT64_MAX - (g_storage.info.logical_sector_size - 1U)) {
      return XAIOS_ERR_INVALID;
    }
    requested_lbas =
        (request->size_bytes + g_storage.info.logical_sector_size - 1U) /
        g_storage.info.logical_sector_size;
    requested_lbas = aligned_up(requested_lbas, alignment_lbas);
    if (requested_lbas == UINT64_MAX || requested_lbas == 0U) {
      return XAIOS_ERR_INVALID;
    }
  }
  uint64_t first = aligned_up(resulting->first_usable_lba, alignment_lbas);
  uint64_t selected_first = 0U;
  uint64_t selected_last = 0U;
  while (first <= resulting->last_usable_lba) {
    uint64_t next = resulting->last_usable_lba + 1U;
    for (uint64_t index = 0U; index < resulting->partition_count; ++index) {
      const xaios_gpt_partition_t *partition = &resulting->partitions[index];
      if (partition->first_lba >= first && partition->first_lba < next) {
        next = partition->first_lba;
      }
    }
    uint64_t available = next - first;
    uint64_t desired = requested_lbas == 0U ? available : requested_lbas;
    if (desired != 0U && desired <= available) {
      selected_first = first;
      selected_last = first + desired - 1U;
      break;
    }
    if (next > resulting->last_usable_lba) break;
    uint64_t occupied_last = next;
    for (uint64_t index = 0U; index < resulting->partition_count; ++index) {
      const xaios_gpt_partition_t *partition = &resulting->partitions[index];
      if (partition->first_lba == next && partition->last_lba > occupied_last) {
        occupied_last = partition->last_lba;
      }
    }
    if (occupied_last == UINT64_MAX) break;
    first = aligned_up(occupied_last + 1U, alignment_lbas);
    if (first == UINT64_MAX) break;
  }
  if (selected_first == 0U) return XAIOS_ERR_NO_MEMORY;

  xaios_gpt_partition_t *partition =
      &resulting->partitions[resulting->partition_count];
  bytes_zero(partition, sizeof(*partition));
  partition->type_guid = *type_guid(request->partition_type);
  derive_partition_guid(&resulting->disk_guid, request->operation_id, slot,
                        &partition->unique_guid);
  partition->first_lba = selected_first;
  partition->last_lba = selected_last;
  partition->table_index = slot;
  partition->table_index_valid = 1U;
  for (uint32_t index = 0U; request->name[index] != '\0'; ++index) {
    partition->name[index] = (uint16_t)(uint8_t)request->name[index];
  }
  ++resulting->partition_count;
  if (gpt_write(g_storage.device, &resulting->disk_guid,
                resulting->partitions, resulting->partition_count, 1U,
                XAIOS_GPT_FAULT_NONE, g_write_scratch,
                sizeof(g_write_scratch)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(plan, sizeof(*plan));
  if (fill_report(resulting, &plan->report) != XAIOS_OK ||
      record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  plan->resulting_partition_count = resulting->partition_count;
  plan->affected_bytes = plan->partition.size_bytes;
  plan->changed = 1U;
  plan->dry_run = 1U;
  return XAIOS_OK;
}

xaios_status_t storage_admin_partition_plan_create(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan) {
  xaios_gpt_table_t table;
  return plan_create(request, plan, &table);
}

xaios_status_t storage_admin_partition_create(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result) {
  xaios_gpt_table_t table;
  xaios_storage_partition_plan_t plan;
  xaios_status_t status = request_valid(request, 1U, 1U);
  if (status != XAIOS_OK) return status;
  status = plan_create(request, &plan, &table);
  if (status != XAIOS_OK ||
      validate_confirmation(request->confirmation, &table.disk_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  status = write_and_verify(&table);
  if (status != XAIOS_OK) return status;
  status = register_partition(&table.partitions[table.partition_count - 1U]);
  if (status != XAIOS_OK) return status;
  plan.dry_run = 0U;
  if (result != 0) *result = plan;
  return XAIOS_OK;
}

static managed_partition_t *find_managed(const char *identifier) {
  for (uint32_t index = 0U; index < XAIOS_GPT_MAX_PARTITIONS; ++index) {
    managed_partition_t *managed = &g_storage.partitions[index];
    if (managed->active != 0U &&
        string_equal(identifier, managed->identifier)) {
      return managed;
    }
  }
  return 0;
}

xaios_status_t storage_admin_partition_open(
    const char *partition_identifier_value, uint32_t required_type,
    uint32_t require_idle, xaios_block_device_t **out_device,
    xaios_storage_partition_record_t *record) {
  if (partition_identifier_value == 0 || out_device == 0 || record == 0 ||
      require_idle > 1U || required_type == 0U) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed = find_managed(partition_identifier_value);
  if (managed == 0) return XAIOS_ERR_NOT_FOUND;
  if (known_type(&managed->descriptor.type_guid) != required_type) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint32_t open_count = 0U;
  if (block_device_open_count(&managed->device.block_device, &open_count) !=
      XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (require_idle != 0U && open_count != 0U) return XAIOS_ERR_BUSY;
  bytes_zero(record, sizeof(*record));
  xaios_status_t status = record_from_partition(&managed->descriptor, record);
  if (status != XAIOS_OK) return status;
  return block_device_open(managed->identifier, out_device);
}

xaios_status_t storage_admin_partition_close(xaios_block_device_t *device) {
  return block_device_close(device);
}

static xaios_gpt_partition_t *find_table_partition(
    xaios_gpt_table_t *table, uint32_t table_index, uint64_t *array_index) {
  for (uint64_t index = 0U; index < table->partition_count; ++index) {
    if (table->partitions[index].table_index == table_index) {
      if (array_index != 0) *array_index = index;
      return &table->partitions[index];
    }
  }
  return 0;
}

static xaios_status_t plan_delete(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan, xaios_gpt_table_t *resulting,
    uint32_t *table_index) {
  if (request_valid(request, 0U, 0U) != XAIOS_OK || plan == 0 ||
      resulting == 0 || table_index == 0) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed = find_managed(request->target);
  if (managed == 0) return XAIOS_ERR_NOT_FOUND;
  xaios_status_t status = read_table(resulting, 0U);
  if (status != XAIOS_OK || resulting->primary_valid == 0U ||
      resulting->backup_valid == 0U || resulting->copies_consistent == 0U) {
    return status != XAIOS_OK ? status : XAIOS_ERR_BUSY;
  }
  uint64_t array_index = 0U;
  xaios_gpt_partition_t *partition = find_table_partition(
      resulting, managed->descriptor.table_index, &array_index);
  if (partition == 0) return XAIOS_ERR_BUSY;
  bytes_zero(plan, sizeof(*plan));
  if (fill_report(resulting, &plan->report) != XAIOS_OK ||
      record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  plan->affected_bytes = plan->partition.size_bytes;
  for (uint64_t index = array_index + 1U; index < resulting->partition_count;
       ++index) {
    resulting->partitions[index - 1U] = resulting->partitions[index];
  }
  --resulting->partition_count;
  bytes_zero(&resulting->partitions[resulting->partition_count],
             sizeof(resulting->partitions[0]));
  plan->resulting_partition_count = resulting->partition_count;
  plan->changed = 1U;
  plan->dry_run = 1U;
  *table_index = managed->descriptor.table_index;
  return gpt_write(g_storage.device, &resulting->disk_guid,
                   resulting->partitions, resulting->partition_count, 1U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch));
}

xaios_status_t storage_admin_partition_plan_delete(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan) {
  xaios_gpt_table_t table;
  uint32_t table_index = 0U;
  return plan_delete(request, plan, &table, &table_index);
}

xaios_status_t storage_admin_partition_delete(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result) {
  xaios_gpt_table_t table;
  xaios_storage_partition_plan_t plan;
  uint32_t table_index = 0U;
  xaios_status_t status = request_valid(request, 1U, 0U);
  if (status != XAIOS_OK) return status;
  status = plan_delete(request, &plan, &table, &table_index);
  xaios_guid_t partition_guid;
  if (status != XAIOS_OK ||
      gpt_guid_parse(plan.partition.unique_guid, &partition_guid) != XAIOS_OK ||
      validate_confirmation(request->confirmation, &partition_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  managed_partition_t saved = g_storage.partitions[table_index];
  status = unregister_partition(table_index);
  if (status != XAIOS_OK) return status;
  status = write_and_verify(&table);
  if (status != XAIOS_OK) {
    (void)register_partition(&saved.descriptor);
    return status;
  }
  plan.dry_run = 0U;
  if (result != 0) *result = plan;
  return XAIOS_OK;
}

static xaios_status_t plan_resize(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan, xaios_gpt_table_t *resulting,
    uint32_t *table_index) {
  if (request_valid(request, 0U, 0U) != XAIOS_OK || plan == 0 ||
      resulting == 0 || table_index == 0) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed = find_managed(request->target);
  if (managed == 0) return XAIOS_ERR_NOT_FOUND;
  xaios_status_t status = read_table(resulting, 0U);
  if (status != XAIOS_OK || resulting->primary_valid == 0U ||
      resulting->backup_valid == 0U || resulting->copies_consistent == 0U) {
    return status != XAIOS_OK ? status : XAIOS_ERR_BUSY;
  }
  xaios_gpt_partition_t *partition = find_table_partition(
      resulting, managed->descriptor.table_index, 0);
  if (partition == 0) return XAIOS_ERR_BUSY;
  uint64_t current_lbas = partition->last_lba - partition->first_lba + 1U;
  uint64_t target_lbas = 0U;
  uint64_t maximum_last = resulting->last_usable_lba;
  for (uint64_t index = 0U; index < resulting->partition_count; ++index) {
    const xaios_gpt_partition_t *other = &resulting->partitions[index];
    if (other->table_index != partition->table_index &&
        other->first_lba > partition->first_lba &&
        other->first_lba - 1U < maximum_last) {
      maximum_last = other->first_lba - 1U;
    }
  }
  if (request->size_bytes == 0U) {
    target_lbas = maximum_last - partition->first_lba + 1U;
  } else {
    if (request->size_bytes >
        UINT64_MAX - (g_storage.info.logical_sector_size - 1U)) {
      return XAIOS_ERR_INVALID;
    }
    target_lbas =
        (request->size_bytes + g_storage.info.logical_sector_size - 1U) /
        g_storage.info.logical_sector_size;
  }
  if (target_lbas <= current_lbas ||
      target_lbas - 1U > maximum_last - partition->first_lba ||
      !lba_range_free(resulting, partition->first_lba,
                      partition->first_lba + target_lbas - 1U,
                      partition->table_index)) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  bytes_zero(plan, sizeof(*plan));
  if (fill_report(resulting, &plan->report) != XAIOS_OK ||
      record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t previous_bytes = plan->partition.size_bytes;
  partition->last_lba = partition->first_lba + target_lbas - 1U;
  bytes_zero(&plan->partition, sizeof(plan->partition));
  if (record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  plan->affected_bytes = plan->partition.size_bytes - previous_bytes;
  plan->resulting_partition_count = resulting->partition_count;
  plan->changed = 1U;
  plan->dry_run = 1U;
  *table_index = partition->table_index;
  return gpt_write(g_storage.device, &resulting->disk_guid,
                   resulting->partitions, resulting->partition_count, 1U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch));
}

xaios_status_t storage_admin_partition_plan_resize(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan) {
  xaios_gpt_table_t table;
  uint32_t table_index = 0U;
  return plan_resize(request, plan, &table, &table_index);
}

xaios_status_t storage_admin_partition_resize(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result) {
  xaios_gpt_table_t table;
  xaios_storage_partition_plan_t plan;
  uint32_t table_index = 0U;
  xaios_status_t status = request_valid(request, 1U, 0U);
  if (status != XAIOS_OK) return status;
  status = plan_resize(request, &plan, &table, &table_index);
  xaios_guid_t partition_guid;
  if (status != XAIOS_OK ||
      gpt_guid_parse(plan.partition.unique_guid, &partition_guid) != XAIOS_OK ||
      validate_confirmation(request->confirmation, &partition_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  managed_partition_t saved = g_storage.partitions[table_index];
  status = unregister_partition(table_index);
  if (status != XAIOS_OK) return status;
  status = write_and_verify(&table);
  if (status == XAIOS_OK) {
    xaios_gpt_partition_t *partition =
        find_table_partition(&table, table_index, 0);
    status = partition == 0 ? XAIOS_ERR_IO : register_partition(partition);
  }
  if (status != XAIOS_OK) {
    if (g_storage.partitions[table_index].active == 0U) {
      (void)register_partition(&saved.descriptor);
    }
    return status;
  }
  plan.dry_run = 0U;
  if (result != 0) *result = plan;
  return XAIOS_OK;
}

xaios_status_t storage_admin_partition_repair(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result) {
  if (result == 0 || request_valid(request, 1U, 0U) != XAIOS_OK ||
      validate_target_device(request->target) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_gpt_table_t table;
  xaios_status_t status = read_table(&table, 0U);
  if (status != XAIOS_OK || table.primary_valid == table.backup_valid ||
      validate_confirmation(request->confirmation, &table.disk_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  for (uint64_t index = 0U; index < table.partition_count; ++index) {
    managed_partition_t *managed =
        &g_storage.partitions[table.partitions[index].table_index];
    uint32_t open_count = 0U;
    if (managed->active == 0U ||
        block_device_open_count(&managed->device.block_device, &open_count) !=
            XAIOS_OK ||
        open_count != 0U) {
      return XAIOS_ERR_BUSY;
    }
  }
  bytes_zero(result, sizeof(*result));
  if (fill_report(&table, &result->report) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  status = write_and_verify(&table);
  if (status != XAIOS_OK) return status;
  result->report.primary_valid = 1U;
  result->report.backup_valid = 1U;
  result->report.copies_consistent = 1U;
  result->resulting_partition_count = table.partition_count;
  result->changed = 1U;
  result->dry_run = 0U;
  return XAIOS_OK;
}

/* Partition a real disk at boot, the way an installer would.

   Everything below this line was written, reachable from the control protocol,
   and never once run against a device. The hosted tests cover argument
   parsing; the ABI contract checks the command names exist. Neither writes a
   partition table, so "XAIOS can partition a disk" rested on code nobody had
   watched work. It does now, on the scratch device the boot path already
   attaches, on every gate run.

   The test creates a partition, reads the table back to confirm it is there,
   and deletes it again. Leaving it behind would make each boot find the disk
   in the state the last one left it, which is how a test stops testing
   anything. Failure is reported and survivable: a machine with no scratch
   device is normal, and losing one is not worth refusing to boot over. */
static int bytes_equal_const(const void *left, const void *right,
                             uint64_t length) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (uint64_t index = 0U; index < length; ++index) {
    if (a[index] != b[index]) return 0;
  }
  return 1;
}

/* Put the disk back the way it was found. A test that leaves its partition
   behind makes every later boot start from what the last one left, which is
   how a test stops testing anything. */
static void esp_self_test_cleanup(xaios_storage_partition_request_t *request,
                                  const xaios_storage_partition_plan_t *created,
                                  uint64_t baseline) {
  string_copy(request->target, sizeof(request->target),
              created->partition.identifier);
  string_copy(request->confirmation, sizeof(request->confirmation),
              created->partition.unique_guid);
  request->operation_id = UINT64_C(4);
  xaios_storage_partition_plan_t deleted;
  xaios_status_t status = storage_admin_partition_delete(request, &deleted);
  if (status != XAIOS_OK) {
    klog("storage-admin: esp self-test could not remove %s status=%d\n",
         created->partition.identifier, (int)status);
    return;
  }
  xaios_storage_partition_report_t report;
  uint64_t count = 0U;
  if (storage_admin_partition_verify(g_storage.info.identifier, &report) ==
          XAIOS_OK &&
      storage_admin_partition_list(g_storage.info.identifier, 0, 0U, &count,
                                   &report) == XAIOS_OK &&
      count != baseline) {
    klog("storage-admin: esp self-test left the table at %lu, not %lu\n",
         count, baseline);
  }
}

/* Make a partition of this disk bootable, which is the whole reason the
   partition writer and the FAT writer exist.

   A machine XAIOS installs onto needs an EFI System Partition: a partition of
   the standard type, holding a FAT filesystem, holding the loader at the path
   firmware looks for. Each of those three is a separate thing that can be
   wrong, and until now XAIOS could do none of them -- every bootable disk was
   built by a script on someone else's operating system. This runs all three
   against the scratch disk on every boot and reads the result back, so the
   claim "XAIOS can make a disk that boots itself" is checked rather than
   asserted.

   What it deliberately does not check is that firmware agrees, because
   firmware is not here. The hosted FAT test does the closest available thing
   by having mtools read the same writer's output. */
static void esp_install_self_test(uint64_t baseline) {
  xaios_storage_partition_request_t request;
  bytes_zero(&request, sizeof(request));
  string_copy(request.target, sizeof(request.target),
              g_storage.info.identifier);
  string_copy(request.name, sizeof(request.name), "XAIOS ESP");
  request.partition_type = XAIOS_STORAGE_PARTITION_ESP;
  /* Large enough that FAT16 has somewhere to put 4085 clusters, which is the
     smallest volume the format actually permits. */
  request.size_bytes = UINT64_C(8388608);
  request.operation_id = UINT64_C(3);

  xaios_storage_partition_plan_t plan;
  xaios_status_t status = storage_admin_partition_plan_create(&request, &plan);
  if (status != XAIOS_OK) {
    klog("storage-admin: esp self-test plan failed status=%d\n", (int)status);
    return;
  }
  string_copy(request.confirmation, sizeof(request.confirmation),
              plan.report.disk_guid);
  xaios_storage_partition_plan_t created;
  status = storage_admin_partition_create(&request, &created);
  if (status != XAIOS_OK) {
    klog("storage-admin: esp self-test create failed status=%d\n",
         (int)status);
    return;
  }

  xaios_block_device_t *partition = 0;
  xaios_storage_partition_record_t record;
  status = storage_admin_partition_open(created.partition.identifier,
                                        XAIOS_STORAGE_PARTITION_ESP, 1U,
                                        &partition, &record);
  if (status != XAIOS_OK) {
    klog("storage-admin: esp self-test open failed status=%d\n", (int)status);
    esp_self_test_cleanup(&request, &created, baseline);
    return;
  }

  xaios_fat_volume_t volume;
  status = fat_format(partition, "XAIOS", &volume);
  if (status == XAIOS_OK) status = fat_mkdir(&volume, "/EFI/BOOT");
  if (status == XAIOS_OK) status = fat_mkdir(&volume, "/EFI/XAIOS");
  if (status != XAIOS_OK) {
    klog("storage-admin: esp self-test format failed status=%d\n",
         (int)status);
    (void)storage_admin_partition_close(partition);
    esp_self_test_cleanup(&request, &created, baseline);
    return;
  }

  /* Not the real loader -- the kernel does not have a copy of it to hand --
     but written to the path firmware actually opens, so the directory tree and
     the 8.3 name are the ones that have to work. */
  static const char marker[] =
      "XAIOS EFI System Partition written by the running system.";
  status = fat_write_file(&volume, "/EFI/BOOT/BOOTAA64.EFI", marker,
                          sizeof(marker));
  if (status == XAIOS_OK) {
    status = fat_write_file(&volume, "/EFI/XAIOS/XAIOS.EFI", marker,
                            sizeof(marker));
  }
  if (status != XAIOS_OK) {
    klog("storage-admin: esp self-test write failed status=%d\n",
         (int)status);
    (void)storage_admin_partition_close(partition);
    esp_self_test_cleanup(&request, &created, baseline);
    return;
  }

  /* Read back through a mount that shares no state with the writer, which is
     what shows the geometry reached the disk rather than only the struct. */
  xaios_fat_volume_t reopened;
  char readback[sizeof(marker)];
  uint64_t length = 0U;
  status = fat_mount(partition, &reopened);
  if (status == XAIOS_OK) {
    status = fat_read_file(&reopened, "/EFI/BOOT/BOOTAA64.EFI", readback,
                           sizeof(readback), &length);
  }
  if (status != XAIOS_OK || length != sizeof(marker) ||
      !bytes_equal_const(readback, marker, sizeof(marker))) {
    klog("storage-admin: esp self-test read back wrong status=%d length=%lu\n",
         (int)status, length);
    (void)storage_admin_partition_close(partition);
    esp_self_test_cleanup(&request, &created, baseline);
    return;
  }

  (void)storage_admin_partition_close(partition);
  klog("storage-admin: esp create/format/install self-test passed "
       "partition=%s clusters=%lu bytes_per_cluster=%lu\n",
       created.partition.identifier, reopened.cluster_count,
       reopened.sectors_per_cluster * reopened.sector_size);
  esp_self_test_cleanup(&request, &created, baseline);
}

void storage_admin_self_test(void) {
  if (g_storage.attached == 0U) {
    klog("storage-admin: partition self-test skipped no attached device\n");
    return;
  }

  xaios_storage_partition_report_t report;
  xaios_storage_partition_record_t records[XAIOS_GPT_MAX_PARTITIONS];
  uint64_t before = 0U;
  /* A disk with no partition table cannot be listed, and that is correct
     rather than a failure: there is nothing to list. It is also the state a
     disk is in when someone installs XAIOS onto it, so this test starts by
     tolerating it instead of requiring a table it may be about to create. */
  if (storage_admin_partition_list(g_storage.info.identifier, records,
                                   XAIOS_GPT_MAX_PARTITIONS, &before,
                                   &report) != XAIOS_OK) {
    before = 0U;
  }

  xaios_storage_partition_request_t request;
  bytes_zero(&request, sizeof(request));
  string_copy(request.target, sizeof(request.target),
              g_storage.info.identifier);
  string_copy(request.name, sizeof(request.name), "xaios-self-test");
  request.partition_type = XAIOS_STORAGE_PARTITION_STATE;
  request.size_bytes = UINT64_C(1048576);
  request.operation_id = UINT64_C(1);

  xaios_storage_partition_plan_t plan;
  xaios_status_t status = storage_admin_partition_plan_create(&request, &plan);
  if (status != XAIOS_OK) {
    klog("storage-admin: partition self-test plan failed status=%d\n",
         (int)status);
    return;
  }
  if (plan.dry_run == 0U || plan.changed == 0U) {
    klog("storage-admin: partition self-test plan is not a dry run\n");
    return;
  }

  /* The disk's own GUID, which is what the confirmation is: an operator who
     has not looked at the disk cannot name it, and a request naming the wrong
     one is refused rather than applied to whatever is there. The plan reports
     it, which is the only way to learn it for a disk that has no table yet. */
  string_copy(request.confirmation, sizeof(request.confirmation),
              plan.report.disk_guid);

  xaios_storage_partition_plan_t created;
  status = storage_admin_partition_create(&request, &created);
  if (status != XAIOS_OK) {
    klog("storage-admin: partition self-test create failed status=%d\n",
         (int)status);
    return;
  }

  uint64_t after = 0U;
  if (storage_admin_partition_list(g_storage.info.identifier, records,
                                   XAIOS_GPT_MAX_PARTITIONS, &after,
                                   &report) != XAIOS_OK ||
      after != before + 1U) {
    klog("storage-admin: partition self-test created partition not in the "
         "table count=%lu expected=%lu\n",
         after, before + 1U);
    return;
  }

  /* Deleting confirms against the partition's own GUID, not the disk's --
     creating changes a disk, deleting destroys a particular partition, and
     each names the thing it is about to affect. */
  string_copy(request.target, sizeof(request.target),
              created.partition.identifier);
  string_copy(request.confirmation, sizeof(request.confirmation),
              created.partition.unique_guid);
  request.operation_id = UINT64_C(2);
  status = storage_admin_partition_delete(&request, &created);
  if (status != XAIOS_OK) {
    klog("storage-admin: partition self-test delete failed status=%d; the "
         "scratch disk keeps %s\n",
         (int)status, created.partition.identifier);
    return;
  }

  /* The table survives the delete even when the disk had none to begin with:
     creating the partition wrote one, and deleting the partition does not take
     it away again. So this must succeed either way, with the count back where
     it started. */
  uint64_t restored = 0U;
  if (storage_admin_partition_list(g_storage.info.identifier, records,
                                   XAIOS_GPT_MAX_PARTITIONS, &restored,
                                   &report) != XAIOS_OK ||
      restored != before) {
    klog("storage-admin: partition self-test left the table at %lu, not %lu\n",
         restored, before);
    return;
  }

  klog("storage-admin: partition create/verify/delete self-test passed "
       "device=%s partitions=%lu\n",
       g_storage.info.identifier, before);

  esp_install_self_test(before);
}
