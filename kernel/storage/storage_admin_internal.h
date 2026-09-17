/*
 * Private interface between storage_admin.c, storage_admin_table.c and
 * storage_admin_self_test.c: the module's one attached-device state, the two
 * GPT scratch buffers it borrows, and the partition-table primitives the
 * command layer and the boot self-test call.
 *
 * Split out of storage_admin.c, which was 1184 lines. The state, the scratch
 * buffers and the table, report and validation primitives are defined once, in
 * storage_admin_table.c, and declared here; the public command layer stays in
 * storage_admin.c and the boot self-test moves to storage_admin_self_test.c.
 * Nothing here owns state the module did not already own as a static: there is
 * still exactly one attached device and one writer at a time, and the scratch
 * buffers are borrowed for the duration of one gpt read or write and never
 * returned to a caller.
 */

#ifndef XAIOS_KERNEL_STORAGE_STORAGE_ADMIN_INTERNAL_H
#define XAIOS_KERNEL_STORAGE_STORAGE_ADMIN_INTERNAL_H

#include <xaios/block_device.h>
#include <xaios/gpt.h>
#include <xaios/partition_device.h>
#include <xaios/storage_admin.h>

/* One partition registered with the block-device layer, and the descriptor the
   table reported for it. `active` is what makes an entry a live registration
   rather than a zeroed slot. */
typedef struct managed_partition {
  xaios_partition_device_t device;
  xaios_gpt_partition_t descriptor;
  char identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  uint32_t active;
} managed_partition_t;

/* The module's whole state: the one attached device, a copy of the info the
   attach validated, and the partitions registered from its table. */
typedef struct storage_admin_state {
  xaios_block_device_t *device;
  xaios_block_device_info_t info;
  managed_partition_t partitions[XAIOS_GPT_MAX_PARTITIONS];
  uint32_t mutation_allowed;
  uint32_t attached;
} storage_admin_state_t;

/* Defined once, in storage_admin_table.c. */
extern storage_admin_state_t g_sa_state;
extern uint8_t g_sa_read_scratch[XAIOS_GPT_READ_SCRATCH_BYTES];
extern uint8_t g_sa_write_scratch[XAIOS_GPT_WRITE_SCRATCH_BYTES];

/* The partition-table, report and validation primitives storage_admin_table.c
   provides to the command layer and the boot self-test. */
void sa_bytes_zero(void *buffer, uint64_t length);
int sa_string_equal(const char *left, const char *right);
void sa_string_copy(char *destination, uint64_t capacity, const char *source);
uint32_t sa_known_type(const xaios_guid_t *type);
const xaios_guid_t *sa_type_guid(uint32_t type);
xaios_status_t sa_record_from_partition(
    const xaios_gpt_partition_t *partition,
    xaios_storage_partition_record_t *record);
xaios_status_t sa_fill_report(const xaios_gpt_table_t *table,
                              xaios_storage_partition_report_t *report);
void sa_derive_partition_guid(const xaios_guid_t *disk_guid,
                              uint64_t operation_id, uint32_t table_index,
                              xaios_guid_t *guid);
xaios_status_t sa_read_table(xaios_gpt_table_t *table,
                             uint32_t allow_unformatted);
xaios_status_t sa_register_partition(
    const xaios_gpt_partition_t *partition);
xaios_status_t sa_unregister_partition(uint32_t table_index);
xaios_status_t sa_validate_target_device(const char *identifier);
xaios_status_t sa_validate_confirmation(const char *confirmation,
                                        const xaios_guid_t *expected);
xaios_status_t sa_write_and_verify(const xaios_gpt_table_t *table);
xaios_status_t sa_request_valid(
    const xaios_storage_partition_request_t *request, uint32_t mutation,
    uint32_t require_name);
uint64_t sa_aligned_up(uint64_t value, uint64_t alignment);
int sa_lba_range_free(const xaios_gpt_table_t *table, uint64_t first,
                      uint64_t last, uint32_t ignored_table_index);
uint32_t sa_first_free_table_index(const xaios_gpt_table_t *table);

#endif
