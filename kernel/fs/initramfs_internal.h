/*
 * Private interface between the two translation units of the initramfs
 * read-only image. initramfs.c parses and validates the on-disk image and
 * owns the file table; initramfs_config.c owns the manifest's key=value
 * configuration and the descriptor it publishes. The kernel's public surface
 * is xaios/initramfs.h -- nothing here is used outside kernel/fs.
 *
 * Split out of initramfs.c, which was 552 lines.
 */

#ifndef XAIOS_KERNEL_FS_INITRAMFS_INTERNAL_H
#define XAIOS_KERNEL_FS_INITRAMFS_INTERNAL_H

#include <xaios/status.h>
#include <xaios/initramfs.h>

#define INITFS_PATH_MAX 64U
#define INITFS_MODE_MAX 32U

/* The bounded string equality the loaded file table and the configuration
   parser both match paths with. Defined once, in initramfs.c. */
int initramfs_str_eq(const char *a, const char *b);

/* Parse the manifest file against the file table initramfs_init has already
   populated, publish the descriptor through initramfs_config(), and reject a
   manifest that is missing a required field. Defined in initramfs_config.c. */
xaios_status_t initramfs_parse_config_manifest(
    const xaios_initramfs_file_t *file);

/* The two targets parse_config_manifest names must be executable files in the
   loaded table, and the descriptor must be a plain file there. Defined in
   initramfs_config.c. */
xaios_status_t initramfs_config_validate_targets(void);

/* Clear the published descriptor so a failed initramfs_init does not leave a
   previous mount's configuration visible. Defined in initramfs_config.c. */
void initramfs_config_reset(void);

#endif
