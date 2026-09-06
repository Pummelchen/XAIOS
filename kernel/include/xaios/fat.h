#ifndef XAIOS_FAT_H
#define XAIOS_FAT_H

#include <xaios/block_device.h>
#include <xaios/status.h>
#include <xaios/types.h>

/*
 * FAT16, enough of it to build an EFI System Partition.
 *
 * XAIOS does not use FAT for anything of its own -- it keeps its state on
 * xaibootFS and its models on xaiFS. It needs FAT for exactly one reason: UEFI
 * firmware boots from a FAT filesystem, and a machine that cannot write one
 * cannot make a disk that boots itself. Every bootable XAIOS disk so far has
 * been assembled by a script on a Mac or a Linux box, which is fine for
 * producing releases and useless for installing onto a machine from inside
 * XAIOS.
 *
 * So this is a writer, not a filesystem. It formats a volume, creates
 * directories, writes whole files and reads them back to check. It does not
 * append, truncate, delete, or seek, and it has no VFS binding, because an
 * installer does not need any of that and each one is a way to corrupt a
 * volume that firmware has to be able to read.
 *
 * FAT16 rather than FAT32 deliberately. The EFI specification requires
 * firmware to support FAT12, FAT16 and FAT32 on removable media, so either
 * would be legal -- but VMware Fusion boots an El Torito image with a FAT16
 * filesystem and silently boots nothing at all from a FAT32 one. That is
 * recorded in scripts/build-unified-image.sh, was measured rather than read,
 * and applies with equal force to a volume written here.
 *
 * Names are 8.3 where they fit, with VFAT long-name entries where they do
 * not. That second half was added late and for one reason: UEFI's
 * removable-media path is named for the machine, and while
 * \EFI\BOOT\BOOTAA64.EFI and \EFI\BOOT\BOOTX64.EFI fit 8.3 exactly,
 * \EFI\BOOT\BOOTRISCV64.EFI has eleven characters of base where 8.3 allows
 * eight. Two architectures out of three fitting looked like a property of the
 * format and was a coincidence about two names.
 *
 * Without it a RISC-V machine could format an EFI System Partition perfectly
 * and had no way to put on it the one file its own firmware opens -- and,
 * reading, could not see that file on a volume this repository had built with
 * mtools, so an installer copying from one silently wrote a disk with four
 * files where it should have had five. Both halves are needed and both are
 * here: long names are written with the alias they belong to, and read back
 * by either name.
 */

#define XAIOS_FAT_PATH_MAX 128U
#define XAIOS_FAT_LABEL_MAX 12U

typedef struct xaios_fat_volume {
  xaios_block_device_t *device;
  uint64_t sector_size;
  uint64_t total_sectors;
  uint64_t reserved_sectors;
  uint64_t fat_count;
  uint64_t sectors_per_fat;
  uint64_t sectors_per_cluster;
  uint64_t root_entry_count;
  uint64_t root_start_sector;
  uint64_t root_sectors;
  uint64_t data_start_sector;
  uint64_t cluster_count;
  uint32_t mounted;
} xaios_fat_volume_t;

/*
 * Format the device as FAT16 and leave it mounted in volume.
 *
 * label may be null, in which case the volume gets no label. A volume too
 * small to hold a FAT16 filesystem with the geometry this chooses is refused
 * rather than formatted as something else: firmware that cannot read what came
 * out would give no reason, and neither would we.
 */
xaios_status_t fat_format(xaios_block_device_t *device, const char *label,
                          xaios_fat_volume_t *volume);

/* Mount an already-formatted volume. */
xaios_status_t fat_mount(xaios_block_device_t *device,
                         xaios_fat_volume_t *volume);

/*
 * Create a directory, and every parent it needs. Path components are
 * separated by '/', are 8.3 and case-insensitive, and an existing directory is
 * success rather than an error -- an installer that runs twice should behave
 * the same way the second time.
 */
xaios_status_t fat_mkdir(xaios_fat_volume_t *volume, const char *path);

/*
 * Write a whole file, creating it or replacing what is there. Parent
 * directories must exist.
 */
xaios_status_t fat_write_file(xaios_fat_volume_t *volume, const char *path,
                              const void *data, uint64_t length);

/*
 * Read a whole file back. Returns XAIOS_ERR_NO_MEMORY if the file is larger
 * than capacity, with the size still reported, so a caller can size a buffer.
 */
xaios_status_t fat_read_file(xaios_fat_volume_t *volume, const char *path,
                             void *buffer, uint64_t capacity,
                             uint64_t *out_length);

/* Whether a path exists, and whether it is a directory. */
xaios_status_t fat_stat(xaios_fat_volume_t *volume, const char *path,
                        uint64_t *out_size, uint32_t *out_is_directory);

/*
 * Copy a file between two mounted volumes without holding it in memory. An
 * installer copies a kernel and an initial filesystem, which are megabytes;
 * whole-file read and write would need memory for the largest file that might
 * ever be met. The destination's directory entry is written last, after every
 * byte is on the disk, so a file never appears before its contents.
 */
xaios_status_t fat_copy_file(xaios_fat_volume_t *destination,
                             const char *destination_path,
                             xaios_fat_volume_t *source,
                             const char *source_path);

/* Format, populate and read back a volume in memory, checked without a disk. */
void fat_self_test(void);

#endif
