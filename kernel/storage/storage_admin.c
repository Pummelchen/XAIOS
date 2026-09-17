/*
 * Storage administration: the public command layer over one attached scratch
 * device. See storage_admin_internal.h.
 *
 * Split out of a 1184-line storage_admin.c. The partition-table primitives and
 * their state are in storage_admin_table.c and the boot self-test is in
 * storage_admin_self_test.c; this file keeps the commands the control protocol
 * and the installer call, plus the create/delete/resize planning they share.
 * The move is verbatim and the order of operations is unchanged.
 */

#include <xaios/storage_admin.h>
#include <xaios/partition_device.h>

#include "storage_admin_internal.h"

#define STORAGE_ALIGNMENT_BYTES UINT64_C(1048576)

xaios_status_t storage_admin_attach(xaios_block_device_t *device,
                                    uint32_t mutation_allowed) {
  if (device == 0 || mutation_allowed > 1U || g_sa_state.attached != 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK ||
      info.read_only != 0U || info.flush_supported == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  sa_bytes_zero(&g_sa_state, sizeof(g_sa_state));
  g_sa_state.device = device;
  g_sa_state.info = info;
  g_sa_state.mutation_allowed = mutation_allowed;
  g_sa_state.attached = 1U;
  xaios_gpt_table_t table;
  xaios_status_t status = sa_read_table(&table, 0U);
  if (status == XAIOS_ERR_INVALID) return XAIOS_OK;
  if (status != XAIOS_OK) {
    sa_bytes_zero(&g_sa_state, sizeof(g_sa_state));
    return status;
  }
  for (uint64_t index = 0U; index < table.partition_count; ++index) {
    status = sa_register_partition(&table.partitions[index]);
    if (status != XAIOS_OK) {
      (void)storage_admin_detach();
      return status;
    }
  }
  return XAIOS_OK;
}

xaios_status_t storage_admin_detach(void) {
  if (g_sa_state.attached == 0U) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t index = 0U; index < XAIOS_GPT_MAX_PARTITIONS; ++index) {
    if (g_sa_state.partitions[index].active != 0U &&
        sa_unregister_partition(index) != XAIOS_OK) {
      return XAIOS_ERR_BUSY;
    }
  }
  sa_bytes_zero(&g_sa_state, sizeof(g_sa_state));
  return XAIOS_OK;
}

xaios_status_t storage_admin_partition_list(
    const char *device_identifier, xaios_storage_partition_record_t *records,
    uint64_t capacity, uint64_t *out_count,
    xaios_storage_partition_report_t *report) {
  if (out_count == 0 || report == 0 ||
      (capacity != 0U && records == 0) ||
      sa_validate_target_device(device_identifier) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_gpt_table_t table;
  xaios_status_t status = sa_read_table(&table, 0U);
  if (status != XAIOS_OK || sa_fill_report(&table, report) != XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  for (uint64_t index = 0U; index < table.partition_count && index < capacity;
       ++index) {
    sa_bytes_zero(&records[index], sizeof(records[index]));
    if (sa_record_from_partition(&table.partitions[index], &records[index]) !=
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

static xaios_status_t plan_create(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan, xaios_gpt_table_t *resulting) {
  if (sa_request_valid(request, 0U, 1U) != XAIOS_OK || plan == 0 ||
      resulting == 0 || sa_type_guid(request->partition_type) == 0 ||
      sa_validate_target_device(request->target) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = sa_read_table(resulting, 1U);
  if (status != XAIOS_OK ||
      (resulting->selected_copy != XAIOS_GPT_COPY_NONE &&
       (resulting->primary_valid == 0U || resulting->backup_valid == 0U ||
        resulting->copies_consistent == 0U)) ||
      resulting->partition_count >= XAIOS_GPT_MAX_PARTITIONS) {
    return status != XAIOS_OK ? status : XAIOS_ERR_BUSY;
  }
  uint32_t slot = sa_first_free_table_index(resulting);
  if (slot == XAIOS_GPT_ENTRY_COUNT) return XAIOS_ERR_NO_MEMORY;
  uint64_t alignment_lbas =
      STORAGE_ALIGNMENT_BYTES / g_sa_state.info.logical_sector_size;
  if (alignment_lbas == 0U) alignment_lbas = 1U;
  uint64_t requested_lbas = 0U;
  if (request->size_bytes != 0U) {
    if (request->size_bytes >
        UINT64_MAX - (g_sa_state.info.logical_sector_size - 1U)) {
      return XAIOS_ERR_INVALID;
    }
    requested_lbas =
        (request->size_bytes + g_sa_state.info.logical_sector_size - 1U) /
        g_sa_state.info.logical_sector_size;
    requested_lbas = sa_aligned_up(requested_lbas, alignment_lbas);
    if (requested_lbas == UINT64_MAX || requested_lbas == 0U) {
      return XAIOS_ERR_INVALID;
    }
  }
  uint64_t first = sa_aligned_up(resulting->first_usable_lba, alignment_lbas);
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
    first = sa_aligned_up(occupied_last + 1U, alignment_lbas);
    if (first == UINT64_MAX) break;
  }
  if (selected_first == 0U) return XAIOS_ERR_NO_MEMORY;

  xaios_gpt_partition_t *partition =
      &resulting->partitions[resulting->partition_count];
  sa_bytes_zero(partition, sizeof(*partition));
  partition->type_guid = *sa_type_guid(request->partition_type);
  sa_derive_partition_guid(&resulting->disk_guid, request->operation_id, slot,
                           &partition->unique_guid);
  partition->first_lba = selected_first;
  partition->last_lba = selected_last;
  partition->table_index = slot;
  partition->table_index_valid = 1U;
  for (uint32_t index = 0U; request->name[index] != '\0'; ++index) {
    partition->name[index] = (uint16_t)(uint8_t)request->name[index];
  }
  ++resulting->partition_count;
  if (gpt_write(g_sa_state.device, &resulting->disk_guid,
                resulting->partitions, resulting->partition_count, 1U,
                XAIOS_GPT_FAULT_NONE, g_sa_write_scratch,
                sizeof(g_sa_write_scratch)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  sa_bytes_zero(plan, sizeof(*plan));
  if (sa_fill_report(resulting, &plan->report) != XAIOS_OK ||
      sa_record_from_partition(partition, &plan->partition) != XAIOS_OK) {
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
  xaios_status_t status = sa_request_valid(request, 1U, 1U);
  if (status != XAIOS_OK) return status;
  status = plan_create(request, &plan, &table);
  if (status != XAIOS_OK ||
      sa_validate_confirmation(request->confirmation, &table.disk_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  status = sa_write_and_verify(&table);
  if (status != XAIOS_OK) return status;
  status = sa_register_partition(&table.partitions[table.partition_count - 1U]);
  if (status != XAIOS_OK) return status;
  plan.dry_run = 0U;
  if (result != 0) *result = plan;
  return XAIOS_OK;
}

static managed_partition_t *find_managed(const char *identifier) {
  for (uint32_t index = 0U; index < XAIOS_GPT_MAX_PARTITIONS; ++index) {
    managed_partition_t *managed = &g_sa_state.partitions[index];
    if (managed->active != 0U &&
        sa_string_equal(identifier, managed->identifier)) {
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
  if (sa_known_type(&managed->descriptor.type_guid) != required_type) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint32_t open_count = 0U;
  if (block_device_open_count(&managed->device.block_device, &open_count) !=
      XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (require_idle != 0U && open_count != 0U) return XAIOS_ERR_BUSY;
  sa_bytes_zero(record, sizeof(*record));
  xaios_status_t status = sa_record_from_partition(&managed->descriptor, record);
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
  if (sa_request_valid(request, 0U, 0U) != XAIOS_OK || plan == 0 ||
      resulting == 0 || table_index == 0) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed = find_managed(request->target);
  if (managed == 0) return XAIOS_ERR_NOT_FOUND;
  xaios_status_t status = sa_read_table(resulting, 0U);
  if (status != XAIOS_OK || resulting->primary_valid == 0U ||
      resulting->backup_valid == 0U || resulting->copies_consistent == 0U) {
    return status != XAIOS_OK ? status : XAIOS_ERR_BUSY;
  }
  uint64_t array_index = 0U;
  xaios_gpt_partition_t *partition = find_table_partition(
      resulting, managed->descriptor.table_index, &array_index);
  if (partition == 0) return XAIOS_ERR_BUSY;
  sa_bytes_zero(plan, sizeof(*plan));
  if (sa_fill_report(resulting, &plan->report) != XAIOS_OK ||
      sa_record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  plan->affected_bytes = plan->partition.size_bytes;
  for (uint64_t index = array_index + 1U; index < resulting->partition_count;
       ++index) {
    resulting->partitions[index - 1U] = resulting->partitions[index];
  }
  --resulting->partition_count;
  sa_bytes_zero(&resulting->partitions[resulting->partition_count],
                sizeof(resulting->partitions[0]));
  plan->resulting_partition_count = resulting->partition_count;
  plan->changed = 1U;
  plan->dry_run = 1U;
  *table_index = managed->descriptor.table_index;
  return gpt_write(g_sa_state.device, &resulting->disk_guid,
                   resulting->partitions, resulting->partition_count, 1U,
                   XAIOS_GPT_FAULT_NONE, g_sa_write_scratch,
                   sizeof(g_sa_write_scratch));
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
  xaios_status_t status = sa_request_valid(request, 1U, 0U);
  if (status != XAIOS_OK) return status;
  status = plan_delete(request, &plan, &table, &table_index);
  xaios_guid_t partition_guid;
  if (status != XAIOS_OK ||
      gpt_guid_parse(plan.partition.unique_guid, &partition_guid) != XAIOS_OK ||
      sa_validate_confirmation(request->confirmation, &partition_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  managed_partition_t saved = g_sa_state.partitions[table_index];
  status = sa_unregister_partition(table_index);
  if (status != XAIOS_OK) return status;
  status = sa_write_and_verify(&table);
  if (status != XAIOS_OK) {
    (void)sa_register_partition(&saved.descriptor);
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
  if (sa_request_valid(request, 0U, 0U) != XAIOS_OK || plan == 0 ||
      resulting == 0 || table_index == 0) {
    return XAIOS_ERR_INVALID;
  }
  managed_partition_t *managed = find_managed(request->target);
  if (managed == 0) return XAIOS_ERR_NOT_FOUND;
  xaios_status_t status = sa_read_table(resulting, 0U);
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
        UINT64_MAX - (g_sa_state.info.logical_sector_size - 1U)) {
      return XAIOS_ERR_INVALID;
    }
    target_lbas =
        (request->size_bytes + g_sa_state.info.logical_sector_size - 1U) /
        g_sa_state.info.logical_sector_size;
  }
  if (target_lbas <= current_lbas ||
      target_lbas - 1U > maximum_last - partition->first_lba ||
      !sa_lba_range_free(resulting, partition->first_lba,
                         partition->first_lba + target_lbas - 1U,
                      partition->table_index)) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  sa_bytes_zero(plan, sizeof(*plan));
  if (sa_fill_report(resulting, &plan->report) != XAIOS_OK ||
      sa_record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t previous_bytes = plan->partition.size_bytes;
  partition->last_lba = partition->first_lba + target_lbas - 1U;
  sa_bytes_zero(&plan->partition, sizeof(plan->partition));
  if (sa_record_from_partition(partition, &plan->partition) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  plan->affected_bytes = plan->partition.size_bytes - previous_bytes;
  plan->resulting_partition_count = resulting->partition_count;
  plan->changed = 1U;
  plan->dry_run = 1U;
  *table_index = partition->table_index;
  return gpt_write(g_sa_state.device, &resulting->disk_guid,
                   resulting->partitions, resulting->partition_count, 1U,
                   XAIOS_GPT_FAULT_NONE, g_sa_write_scratch,
                   sizeof(g_sa_write_scratch));
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
  xaios_status_t status = sa_request_valid(request, 1U, 0U);
  if (status != XAIOS_OK) return status;
  status = plan_resize(request, &plan, &table, &table_index);
  xaios_guid_t partition_guid;
  if (status != XAIOS_OK ||
      gpt_guid_parse(plan.partition.unique_guid, &partition_guid) != XAIOS_OK ||
      sa_validate_confirmation(request->confirmation, &partition_guid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  managed_partition_t saved = g_sa_state.partitions[table_index];
  status = sa_unregister_partition(table_index);
  if (status != XAIOS_OK) return status;
  status = sa_write_and_verify(&table);
  if (status == XAIOS_OK) {
    xaios_gpt_partition_t *partition =
        find_table_partition(&table, table_index, 0);
    status = partition == 0 ? XAIOS_ERR_IO : sa_register_partition(partition);
  }
  if (status != XAIOS_OK) {
    if (g_sa_state.partitions[table_index].active == 0U) {
      (void)sa_register_partition(&saved.descriptor);
    }
    return status;
  }
  plan.dry_run = 0U;
  if (result != 0) *result = plan;
  return XAIOS_OK;
}
