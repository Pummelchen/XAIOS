/* Private interface shared by kmain.c and the runtime half of it.
 *
 * kmain.c keeps the boot order: it calls this stage once the fault-test marker
 * is behind it, and returns only when the machine has settled into serving the
 * persistent network and sshd. What moves out is the runtime phase itself --
 * the page allocator canary, the initial filesystem lookups, launching /init
 * and the service manager, the preemptive scheduler with its interrupt
 * canaries, the boot-test profile, the second boot-summary report, the network
 * readiness gate, and the wall-clock sync that precedes the tail.
 *
 * The NTP deadline and the wait that uses it move together, so the loop and the
 * bound it is held to stay one unit.
 *
 * The symbol defined here carries the `boot_runtime_' prefix so two modules
 * cannot collide at link time.
 */
#ifndef XAIOS_KERNEL_CORE_BOOT_RUNTIME_INTERNAL_H
#define XAIOS_KERNEL_CORE_BOOT_RUNTIME_INTERNAL_H

#include <xaios/boot_info.h>
#include <xaios/status.h>

/* Launch userspace, enable the scheduler, run the boot-test profile, and settle
   into serving SSH. `persistent_status` is the xaibootFS mount result and
   `nvme_status` the NVMe probe result, both read by steps here. */
void boot_runtime_run(const xaios_boot_info_t *boot,
                      xaios_status_t persistent_status,
                      xaios_status_t nvme_status);

#endif /* XAIOS_KERNEL_CORE_BOOT_RUNTIME_INTERNAL_H */
