/* What one small append actually costs the disk.
 *
 * `write_metadata` rebuilds the whole metadata region and writes every sector
 * of it, however little changed: 1280 sectors -- 640 KiB -- on a v5 volume, and
 * 2560 on v6. A 32-byte audit record therefore moved something like forty times
 * the file's own traffic, and that is why `B-45` took file bytes to almost
 * nothing and per-record time did not move.
 *
 * This measures it rather than describing it. The block device underneath
 * counts sectors, so the number in the assertion below is the number the disk
 * sees, and a change that claims to reduce it has to reduce this.
 *
 * The bound is deliberately generous -- it is a ceiling that catches a
 * regression, not a target to tune against. What it must never do is pass
 * while the whole region is being rewritten per append. B-48.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xaios/block_device.h>
#include <xaios/xaiboot_fs.h>

void klog(const char *fmt, ...) { (void)fmt; }
uint32_t smp_online_count(void) { return 1U; }
uint32_t xaios_translation_enabled(void) { return 1U; }
uint32_t smp_locking_active(void) { return 0U; }
void panic_at(const char *file, int line, const char *fmt, ...) {
  (void)fmt;
  fprintf(stderr, "panic at %s:%d\n", file, line);
  __builtin_trap();
}
xaios_status_t virtio_block_read_sector(uint64_t s, void *b, uint64_t n) {
  (void)s; (void)b; (void)n; return XAIOS_ERR_IO;
}
xaios_status_t virtio_block_write_sector(uint64_t s, const void *b,
                                         uint64_t n) {
  (void)s; (void)b; (void)n; return XAIOS_ERR_IO;
}
xaios_status_t virtio_block_flush(void) { return XAIOS_ERR_IO; }
uint64_t virtio_block_capacity_sectors(void) { return 0U; }

#define SECTOR 512U
/* A v5 volume: 8192 data sectors. The durable volume every machine here boots
   with, and the one the cost was measured on. */
#define DATA_SECTORS 8192U
#define DISK_SECTORS (3072U + 2560U * 2U + 2U + 1U + DATA_SECTORS)
#define DISK_BYTES ((uint64_t)DISK_SECTORS * SECTOR)

static uint8_t *g_disk;
static xaios_block_device_t g_device;
static uint64_t g_sectors_written;
static uint64_t g_flushes;
static int g_counting;

static xaios_status_t disk_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  (void)context;
  if (offset + length > DISK_BYTES) return XAIOS_ERR_INVALID;
  memcpy(buffer, g_disk + offset, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t disk_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  (void)context;
  if (offset + length > DISK_BYTES) return XAIOS_ERR_INVALID;
  memcpy(g_disk + offset, buffer, (size_t)length);
  if (g_counting) g_sectors_written += (length + SECTOR - 1U) / SECTOR;
  return XAIOS_OK;
}

static xaios_status_t disk_flush(void *context) {
  (void)context;
  if (g_counting) ++g_flushes;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_ops = {disk_read, disk_write,
                                                disk_flush, 0, 0};

static void register_disk(const char *name, uint64_t sectors) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memset(&g_device, 0, sizeof(g_device));
  snprintf(info.identifier, sizeof(info.identifier), "%s", name);
  snprintf(info.backend, sizeof(info.backend), "test");
  info.capacity_bytes = sectors * SECTOR;
  info.capacity_logical_sectors = sectors;
  info.logical_sector_size = SECTOR;
  info.physical_block_size = SECTOR;
  info.max_transfer_bytes = SECTOR;
  info.flush_supported = 1U;
  assert(block_device_register(&g_device, &info, &k_ops, 0) == XAIOS_OK);
}

#define APPENDS 20U
#define RECORD_BYTES 32U
/* Per append, across the whole metadata region and the data block. Rewriting
   all 1280 metadata sectors every time puts this at about 1300; anything at or
   under this bound means only a part of the region is reaching the disk. */
#define SECTORS_PER_APPEND_CEILING 640U

int main(void) {
  g_disk = calloc(DISK_BYTES, 1U);
  assert(g_disk != 0);
  register_disk("/dev/costdisk", DISK_SECTORS);
  assert(xaiboot_fs_mount_device("/dev/costdisk") == XAIOS_OK);

  xaios_xbfs_fsck_result_t fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);

  uint8_t record[RECORD_BYTES];
  memset(record, 0xA5, sizeof(record));

  /* One write first, outside the count: the file has to exist, and creating it
     is a different and larger operation than extending it. */
  assert(xaiboot_fs_write("/state/cost.log", record, sizeof(record)) ==
         XAIOS_OK);

  g_counting = 1;
  for (unsigned i = 0U; i < APPENDS; ++i) {
    int64_t fd = xaiboot_fs_open("/state/cost.log", XAIOS_XBFS_OPEN_WRITE);
    assert(fd >= 0);
    int64_t written = xaiboot_fs_write_fd((uint32_t)fd, record,
                                          sizeof(record));
    assert(written == (int64_t)sizeof(record));
    assert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  }
  g_counting = 0;

  uint64_t per_append = g_sectors_written / APPENDS;
  printf("xaiboot-fs write cost: %u appends of %u bytes moved %llu sectors, "
         "%llu per append (%llu KiB), %llu flushes\n",
         APPENDS, RECORD_BYTES, (unsigned long long)g_sectors_written,
         (unsigned long long)per_append,
         (unsigned long long)(per_append * SECTOR / 1024U),
         (unsigned long long)g_flushes);

  assert(xaiboot_fs_fsck().valid == 1U);
  assert(per_append <= SECTORS_PER_APPEND_CEILING);

  free(g_disk);
  return 0;
}
