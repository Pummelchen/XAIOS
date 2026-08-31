/* A block device made of memory, for a machine that has no disk to give one.
 *
 * XAIOS keeps everything a running system decides -- the control
 * configuration, the boot counter, service state, and the credentials sshd
 * authenticates against -- on a xaibootFS volume. A machine booted from
 * read-only media with no second disk has nowhere to put any of it, and what
 * happens then is not that those things become read-only. It is that
 * admin_control_init never runs, /state/control/config.bin is never written,
 * sshd rejects its runtime configuration, and the machine comes up with the
 * local console locked and no SSH server: a live boot with no way in.
 *
 * The fix is not to teach every one of those paths to work without storage.
 * It is to give them storage. xaibootFS already talks to a registered block
 * device through a small interface, so a device backed by memory rather than
 * by a disk makes all of it work unchanged, and makes the one thing that is
 * genuinely different about a live boot -- that nothing survives the power
 * going off -- the only thing that is different.
 *
 * This is deliberately not a cache, a ramdisk image, or an overlay. It is
 * empty at boot and formatted like any other blank volume, which is what
 * makes the code above it take exactly the path it takes on a real disk.
 */

#include <xaios/ram_block.h>

#include <xaios/kheap.h>
#include <xaios/klog.h>

/* Sized for what xaiboot_fs_mount_device formats: the v5 layout, its metadata
   mirror, and 8192 data sectors. Rounded up rather than computed from the
   filesystem's constants, because a block device that knows the geometry of
   the filesystem on it is a layering mistake that costs nothing to avoid --
   and the slack is a few hundred kilobytes.

   16 MiB is also a deliberate ceiling. A live boot keeps configuration and
   credentials, not data; anything that wants more than this wants a disk,
   and should be told so rather than quietly consuming the machine's RAM. */
#define RAM_BLOCK_BYTES UINT64_C(16777216)
#define RAM_BLOCK_SECTOR_SIZE UINT64_C(512)

static xaios_block_device_t g_device;
static uint8_t *g_storage;
static uint32_t g_present;

static void bytes_copy(void *destination, const void *source, uint64_t count) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t i = 0U; i < count; ++i) out[i] = in[i];
}

static void bytes_zero(void *buffer, uint64_t count) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < count; ++i) out[i] = 0U;
}

/* Every entry point bounds-checks against the arena rather than trusting the
   caller's offset. The caller is the filesystem, which computes offsets from
   its own geometry -- exactly the arithmetic that has been wrong before. */
static int range_ok(uint64_t offset, uint64_t length) {
  return g_storage != 0 && length != 0U && offset <= RAM_BLOCK_BYTES &&
         length <= RAM_BLOCK_BYTES - offset;
}

static xaios_status_t ram_read(void *context, uint64_t offset, void *buffer,
                               uint64_t length) {
  (void)context;
  if (buffer == 0 || !range_ok(offset, length)) return XAIOS_ERR_INVALID;
  bytes_copy(buffer, g_storage + offset, length);
  return XAIOS_OK;
}

static xaios_status_t ram_write(void *context, uint64_t offset,
                                const void *buffer, uint64_t length) {
  (void)context;
  if (buffer == 0 || !range_ok(offset, length)) return XAIOS_ERR_INVALID;
  bytes_copy(g_storage + offset, buffer, length);
  return XAIOS_OK;
}

/* There is no cache between this and the memory, so a flush has already
   happened by the time it is asked for. It still has to succeed: xaibootFS
   refuses a device that cannot flush, and refusing here would be claiming a
   durability problem this device does not have -- its durability problem is
   that the machine is going to lose all of it, which no flush would fix. */
static xaios_status_t ram_flush(void *context) {
  (void)context;
  return g_storage != 0 ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t ram_write_zeroes(void *context, uint64_t offset,
                                       uint64_t length) {
  (void)context;
  if (!range_ok(offset, length)) return XAIOS_ERR_INVALID;
  bytes_zero(g_storage + offset, length);
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_ram_ops = {
    ram_read, ram_write, ram_flush, 0 /* discard */, ram_write_zeroes,
};

xaios_status_t ram_block_create(const char *identifier) {
  if (identifier == 0 || identifier[0] == '\0') return XAIOS_ERR_INVALID;
  if (g_present != 0U) return XAIOS_ERR_BUSY;

  /* From the heap, not from .bss: a machine that has a disk never calls this,
     and sixteen megabytes it does not use should not be sixteen megabytes it
     cannot use. */
  g_storage = (uint8_t *)kheap_alloc(RAM_BLOCK_BYTES, RAM_BLOCK_SECTOR_SIZE);
  if (g_storage == 0) {
    klog("ram-block: no memory for a %lu MiB volume\n",
         RAM_BLOCK_BYTES / UINT64_C(1048576));
    return XAIOS_ERR_NO_MEMORY;
  }
  /* Zeroed, so the filesystem above finds no valid volume and formats one.
     Leaving heap contents here would offer it whatever the last user of this
     memory wrote, to be validated as a filesystem. */
  bytes_zero(g_storage, RAM_BLOCK_BYTES);

  xaios_block_device_info_t info;
  bytes_zero(&info, sizeof(info));
  uint64_t i = 0U;
  while (identifier[i] != '\0' && i + 1U < sizeof(info.identifier)) {
    info.identifier[i] = identifier[i];
    ++i;
  }
  info.identifier[i] = '\0';
  const char backend[] = "ram";
  bytes_copy(info.backend, backend, sizeof(backend));
  info.capacity_bytes = RAM_BLOCK_BYTES;
  info.capacity_logical_sectors = RAM_BLOCK_BYTES / RAM_BLOCK_SECTOR_SIZE;
  info.logical_sector_size = RAM_BLOCK_SECTOR_SIZE;
  info.physical_block_size = RAM_BLOCK_SECTOR_SIZE;
  info.max_transfer_bytes = RAM_BLOCK_BYTES;
  info.max_write_zeroes_bytes = RAM_BLOCK_BYTES;
  info.read_only = 0U;
  info.flush_supported = 1U;
  info.write_zeroes_supported = 1U;

  xaios_status_t status =
      block_device_register(&g_device, &info, &k_ram_ops, 0);
  if (status != XAIOS_OK) {
    kheap_free(g_storage);
    g_storage = 0;
    return status;
  }
  g_present = 1U;
  klog("ram-block: %s registered bytes=%lu sectors=%lu\n", info.identifier,
       info.capacity_bytes, info.capacity_logical_sectors);
  return XAIOS_OK;
}

int ram_block_present(void) { return g_present != 0U ? 1 : 0; }
