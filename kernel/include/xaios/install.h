#ifndef XAIOS_INSTALL_H
#define XAIOS_INSTALL_H

#include <xaios/block_device.h>
#include <xaios/status.h>
#include <xaios/types.h>

/*
 * Install XAIOS onto a disk, from inside XAIOS.
 *
 * Every bootable XAIOS disk before this was assembled by a script running on
 * macOS or Linux. That is fine for building a release and useless for the
 * thing an operating system is expected to be able to do: put itself on a
 * machine's disk and leave it able to start on its own.
 *
 * The work is the three things firmware requires, and nothing more:
 *
 *   - a GUID partition table with an EFI System Partition of the standard
 *     type, and a partition for durable state;
 *   - a FAT filesystem on the EFI partition, because that is what firmware
 *     reads;
 *   - the loader, the kernel and the initial filesystem at the paths firmware
 *     opens, copied from the volume this machine itself booted from.
 *
 * The durable partition is left empty on purpose. The first boot of the new
 * disk formats it, exactly as the first boot of any XAIOS installation does,
 * so the installed system takes the same path as every other one rather than a
 * private one that only the installer has ever exercised.
 */

#define XAIOS_INSTALL_MAX_FILES 8U

typedef struct xaios_install_file {
  const char *path;
  uint64_t bytes;
  uint32_t copied;
} xaios_install_file_t;

typedef struct xaios_install_report {
  char esp_identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  char state_identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  xaios_install_file_t files[XAIOS_INSTALL_MAX_FILES];
  uint64_t file_count;
  uint64_t bytes_copied;
  uint64_t esp_bytes;
  uint64_t state_bytes;
} xaios_install_report_t;

/*
 * Install onto target, taking the boot files from source_esp. The target must
 * be the disk currently attached for storage administration, and is named
 * rather than inferred: an installer that writes to whatever happens to be
 * attached is one whose most destructive argument is invisible at the call
 * site.
 *
 * confirmation must be the target disk's own GUID, exactly as the partition
 * operations require, because this destroys whatever the disk held. Installing
 * onto the disk the source partition lives on is refused outright: an
 * installer that can overwrite the system running it is a way to lose a
 * machine to a typo.
 */
/*
 * The GUID that install_to_disk will require as its confirmation for target.
 * A disk with a partition table reports its own; a blank one -- the normal
 * state of a disk being installed onto -- has none, so this plans a partition
 * to learn the GUID that would result, without writing anything.
 */
xaios_status_t install_target_confirmation(const char *target, char *out,
                                           uint64_t capacity);

xaios_status_t install_to_disk(const char *target, const char *source_esp,
                               const char *confirmation,
                               uint64_t operation_id,
                               xaios_install_report_t *report);

/*
 * Install onto target from files held in memory, for a machine that arrived
 * over the network and has no EFI System Partition to copy from.
 *
 * The loader that booted such a machine carries an unmodified copy of itself,
 * the kernel and the initial filesystem as its own sections, and reports where
 * they are through the boot information. It cannot offer the binary it is
 * running: firmware maps a PE with its sections at their virtual addresses, so
 * the image in memory is not the file it came from.
 *
 * What this writes is an ordinary EFI System Partition. A machine installed
 * over the network is not a special kind of machine afterwards.
 */
typedef struct xaios_install_payload {
  const void *loader;
  uint64_t loader_bytes;
  const void *kernel;
  uint64_t kernel_bytes;
  const void *initfs;
  uint64_t initfs_bytes;
  const void *seed;
  uint64_t seed_bytes;
} xaios_install_payload_t;

xaios_status_t install_to_disk_from_payload(
    const char *target, const xaios_install_payload_t *payload,
    const char *confirmation, uint64_t operation_id,
    xaios_install_report_t *report);

#endif
