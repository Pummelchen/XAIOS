/* The x86-64 platform-services stage that runs once the application
 * processors are online: in the non-common-runtime configuration the
 * milestone 48-51 sequence -- ring-3 syscall validation, klog, the security
 * and scalar AI-kernel self-tests, PCI discovery, the two VirtIO probes, the
 * CPU placement policy and the two contract reports -- and in the
 * common-runtime configuration the common kernel's own entry. Either way it
 * ends in the halt.
 *
 * Split out of kernel/arch/x86_64/early.c. It is a part of the bring-up with a
 * boot position of its own and no ordering coupling: x86_64_kmain calls it at
 * exactly one point, immediately after start_application_processors() has
 * returned, so it touches no INIT-SIPI-SIPI, AP-trampoline or IDT ordering,
 * programs no timer and takes no interrupt. The moved body is early.c's block
 * verbatim; the seam is early_post_smp.h, and the macros below keep the moved
 * code's short names resolving to the primitives the modules beside this one
 * already export. */

#include <xaios/ai_kernels.h>
#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/types.h>

#include "early_contract.h"
#include "early_module.h"
#include "early_post_smp.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

/* The moved body names these the way early.c did; each expands to the
 * primitive defined once in the module beside this one. */
#define serial_puts xaios_x86_early_serial_puts
#define panic_halt xaios_x86_early_panic_halt
#define validate_ring3_syscall xaios_x86_mem_validate_ring3
#define discover_pci xaios_x86_pci_discover
#define validate_virtio_block_operation xaios_x86_pci_validate_virtio_block
#define validate_virtio_network_operation xaios_x86_pci_validate_virtio_network
#define validate_x86_os_contract xaios_x86_early_validate_os_contract
#define validate_hardware_gate xaios_x86_early_validate_hardware_gate

#if XAIOS_X86_COMMON_RUNTIME
/* The common kernel's entry, reached in place of the milestone sequence
 * below; early.c used to declare it and call it at this same point. */
extern void kmain(const xaios_boot_info_t *boot);
#endif

void xaios_x86_early_post_smp_bringup(uint16_t serial_base,
                                      const xaios_boot_info_t *boot) {
#if XAIOS_X86_COMMON_RUNTIME
  kmain(boot);
  panic_halt(serial_base, "common kernel returned");
#else
  validate_ring3_syscall(serial_base);
  klog_init(boot);
  security_self_test();
  serial_puts(serial_base,
              "x86_64: common security policy self-test passed\n");
  ai_kernel_self_test();
  serial_puts(serial_base,
              "x86_64: scalar AI kernel self-test passed\n");
  discover_pci(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 48 PCI discovery passed\n");
  validate_virtio_block_operation(serial_base);
  validate_virtio_network_operation(serial_base);
  x86_64_early_cpu_build_placement_policy(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 49 placement policy passed\n");
  validate_x86_os_contract(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 50 portable common runtime passed platform services pending\n");
  validate_hardware_gate(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 51 hardware gate blocked\n");
#endif

  for (;;) {
    __asm__ volatile("hlt");
  }
}
