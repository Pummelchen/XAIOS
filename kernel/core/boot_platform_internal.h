/* Private interface shared by kmain.c and the platform half of it.
 *
 * kmain.c keeps the boot order: it calls the CPU/memory stage where the machine
 * first has interrupt vectors and a timer of its own, and the platform stage
 * once translation is on and before the heap is first used. What moves out is
 * the bring-up itself -- interrupts, timer, stack canary, SMP, NUMA, physical
 * and virtual memory and the firmware framebuffer; then the arch interrupt,
 * IOMMU and ACPI mappings, the GIC and ECAM configuration, the heap, PCI,
 * console, input, SMMU, RTC and watchdog, and the runtime self-test battery
 * that follows them.
 *
 * These helpers own no state: nothing crosses back into this file, so no
 * pointer into file-scope state is ever handed out.
 *
 * The two symbols defined here carry the `boot_platform_' prefix so two modules
 * cannot collide at link time.
 */
#ifndef XAIOS_KERNEL_CORE_BOOT_PLATFORM_INTERNAL_H
#define XAIOS_KERNEL_CORE_BOOT_PLATFORM_INTERNAL_H

#include <xaios/boot_info.h>

/* Interrupts, timer, stack canary, SMP, NUMA, physical and virtual memory, and
   the firmware framebuffer mapping. Runs before the panic self-test. */
void boot_cpu_memory_bring_up(const xaios_boot_info_t *boot);

/* The architecture interrupt/IOMMU mappings and GIC/ECAM configuration, then
   the heap, PCI, virtio console, input, SMMU, RTC and watchdog, and the
   runtime self-test battery. Runs before storage is discovered. */
void boot_platform_bring_up(const xaios_boot_info_t *boot);

#endif /* XAIOS_KERNEL_CORE_BOOT_PLATFORM_INTERNAL_H */
