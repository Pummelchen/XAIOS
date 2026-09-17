/* Private interface shared by kmain.c and the userspace-launch half of it.
 *
 * kmain.c keeps the boot order: it calls these stages where userspace begins,
 * where the preemption gate has finished, and where the machine settles into
 * serving SSH. What moves out is the launching itself -- loading and running
 * /init and the service manager, bringing the persistent network stack up,
 * the diagnostic application profile a boot-test image runs, the boot-test
 * scheduler dispatch, and the setup/sshd tail.
 *
 * The application capability masks travel verbatim with the calls that use
 * them; nothing here decides a mask.
 *
 * The symbols defined here carry the `boot_apps_' prefix. The three test
 * switches the profile is compiled by are defaulted here so kmain.c and this
 * module cannot disagree about them.
 */
#ifndef XAIOS_KERNEL_CORE_BOOT_APPS_INTERNAL_H
#define XAIOS_KERNEL_CORE_BOOT_APPS_INTERNAL_H

#include <xaios/initramfs.h>
#include <xaios/status.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif
#ifndef XAIOS_LIBC_TEST
#define XAIOS_LIBC_TEST 0
#endif
#ifndef XAIOS_WT_HANDSHAKE_TEST
#define XAIOS_WT_HANDSHAKE_TEST 0
#endif

/* Load and run /init and the service manager, then bring the persistent
   network stack up. Sets *network_ready when the machine has an IPv4 network,
   which is what decides whether sshd is started at all. */
void boot_apps_launch_init(const xaios_initramfs_file_t *init_file,
                           const xaios_initramfs_file_t *manager_file,
                           const xaios_initramfs_config_t *init_config,
                           xaios_status_t persistent_status,
                           uint32_t *network_ready);

/* The diagnostic applications a boot-test image runs once. */
void boot_apps_run_profile(void);

#if XAIOS_BOOT_TEST_APPS
/* The scheduled-dispatch and preemption proof, and the concurrent workers. */
void boot_apps_run_test_dispatch(const xaios_initramfs_file_t *worker_file);
#endif

/* Setup when the machine has no account, and then the persistent sshd. */
void boot_apps_run_tail(void);

#endif /* XAIOS_KERNEL_CORE_BOOT_APPS_INTERNAL_H */
