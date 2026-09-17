/*
 * The storage-admin boot self-test: create, verify and delete a partition and
 * install an EFI System Partition on the attached scratch device on every
 * boot, so the table writer and the FAT writer are exercised against a real
 * disk rather than only by hosted tests of their arguments. See
 * storage_admin_internal.h.
 *
 * Split out of a 1184-line storage_admin.c, verbatim. It reaches the attached
 * device through the private header's one state variable and the module's
 * table primitives; nothing here is new behaviour.
 */

#include <xaios/fat.h>
#include <xaios/klog.h>
#include <xaios/storage_admin.h>

#include "storage_admin_internal.h"

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
  sa_string_copy(request->target, sizeof(request->target),
                 created->partition.identifier);
  sa_string_copy(request->confirmation, sizeof(request->confirmation),
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
  if (storage_admin_partition_verify(g_sa_state.info.identifier, &report) ==
          XAIOS_OK &&
      storage_admin_partition_list(g_sa_state.info.identifier, 0, 0U, &count,
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
  sa_bytes_zero(&request, sizeof(request));
  sa_string_copy(request.target, sizeof(request.target),
                 g_sa_state.info.identifier);
  sa_string_copy(request.name, sizeof(request.name), "XAIOS ESP");
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
  sa_string_copy(request.confirmation, sizeof(request.confirmation),
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
  if (g_sa_state.attached == 0U) {
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
  if (storage_admin_partition_list(g_sa_state.info.identifier, records,
                                   XAIOS_GPT_MAX_PARTITIONS, &before,
                                   &report) != XAIOS_OK) {
    before = 0U;
  }

  xaios_storage_partition_request_t request;
  sa_bytes_zero(&request, sizeof(request));
  sa_string_copy(request.target, sizeof(request.target),
                 g_sa_state.info.identifier);
  sa_string_copy(request.name, sizeof(request.name), "xaios-self-test");
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
  sa_string_copy(request.confirmation, sizeof(request.confirmation),
                 plan.report.disk_guid);

  xaios_storage_partition_plan_t created;
  status = storage_admin_partition_create(&request, &created);
  if (status != XAIOS_OK) {
    klog("storage-admin: partition self-test create failed status=%d\n",
         (int)status);
    return;
  }

  uint64_t after = 0U;
  if (storage_admin_partition_list(g_sa_state.info.identifier, records,
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
  sa_string_copy(request.target, sizeof(request.target),
                 created.partition.identifier);
  sa_string_copy(request.confirmation, sizeof(request.confirmation),
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
  if (storage_admin_partition_list(g_sa_state.info.identifier, records,
                                   XAIOS_GPT_MAX_PARTITIONS, &restored,
                                   &report) != XAIOS_OK ||
      restored != before) {
    klog("storage-admin: partition self-test left the table at %lu, not %lu\n",
         restored, before);
    return;
  }

  klog("storage-admin: partition create/verify/delete self-test passed "
       "device=%s partitions=%lu\n",
       g_sa_state.info.identifier, before);

  esp_install_self_test(before);
}
