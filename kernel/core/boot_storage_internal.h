/* Private interface shared by kmain.c and the boot-storage half of it.
 *
 * kmain.c keeps the boot order and calls one stage here at the point where the
 * machine's storage is discovered. What moves out is the part that is about
 * disks rather than about sequence: the partition-table walk for an xaibootFS
 * volume on the disk this machine booted from, the EFI System Partition it
 * reports and remembers, the install self-test, and the bring-up and mount of
 * the persistent volume.
 *
 * The disk state those helpers share is file-scope here and is never handed out
 * as a pointer. A caller that needs the boot ESP's name copies it into a buffer
 * it owns; nothing returns a pointer into this file's state.
 *
 * The symbols defined here carry the `boot_storage_' prefix so two modules
 * cannot collide at link time. XAIOS_INSTALL_SELF_TEST is defaulted here
 * because code on both sides of the interface is compiled by it, and the two
 * halves must agree on its value.
 */
#ifndef XAIOS_KERNEL_CORE_BOOT_STORAGE_INTERNAL_H
#define XAIOS_KERNEL_CORE_BOOT_STORAGE_INTERNAL_H

#include <xaios/boot_info.h>
#include <xaios/status.h>

/* Off unless a gate asks for it. See the call site in kmain.c. */
#ifndef XAIOS_INSTALL_SELF_TEST
#define XAIOS_INSTALL_SELF_TEST 0
#endif

/* How far to count disks before concluding there is more than one, and what
   to name the disk of a machine that has exactly one. The slot map in the PCI
   transport runs to 6; naming well above it keeps an installed disk's name
   distinct from an attached volume's. */
#define BOOT_DISK_SCAN_LIMIT 4U
#define BOOT_DISK_SLOT_BASE 16U

/* Bring up storage and mount the persistent volume.
 *
 * Returns the status of the persistent mount -- XAIOS_OK when a disk or the
 * memory-backed fallback carries state -- and reports through the out
 * parameters whether NVMe came up (read later by the interrupt canary) and
 * whether that volume outlives the power going off. */
xaios_status_t boot_storage_bring_up(const xaios_boot_info_t *boot,
                                     xaios_status_t *nvme_status_out,
                                     uint32_t *durable_state_out);

/* Copy the identifier of the EFI System Partition this machine booted from
   into `out', which the caller owns, and return the number of bytes written.
   Zero means no such partition was found and `out' holds the empty string. */
uint64_t boot_storage_esp_copy(char *out, uint64_t capacity);

#if XAIOS_INSTALL_SELF_TEST
/* Copy XAIOS from the partition this machine booted from, or from the payload
   its loader carried, onto `target'. Gate-only; see the call site. */
void boot_storage_install_self_test(const char *target,
                                    const xaios_boot_info_t *boot);
#endif

#endif /* XAIOS_KERNEL_CORE_BOOT_STORAGE_INTERNAL_H */
