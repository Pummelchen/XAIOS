/* The handover from firmware to the shared kernel.
 *
 * This file used to be the bring-up: it printed markers, enabled paging and
 * ran a few self-tests of its own. None of that is here any more, because
 * none of it needed to be architecture-specific. What remains is the part
 * that genuinely is -- learning what this machine is from its device tree,
 * telling the two drivers that must know before they are used, and calling
 * kmain.
 */
#include <stdint.h>

#include <xaios/boot_info.h>
#include <xaios/pci.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/virtio_transport.h>

void riscv64_platform_set_device_tree(const void *blob);
void klog(const char *fmt, ...);
void kmain(const xaios_boot_info_t *boot);
xaios_boot_info_t *riscv64_build_boot_info(uint64_t device_tree);
void riscv64_smp_record_boot_hart(uint32_t hart_id);
void riscv64_timer_set_device_tree(const void *blob);
void riscv64_exception_set_device_tree(const void *blob);

void riscv64_boot(uint64_t hart_id, uint64_t device_tree) {
  /* Nothing may use klog before kmain runs klog_init: the shared logger
     writes to a UART address it is told, and until it is told it writes
     nowhere. The bring-up used to print here, which is why the first
     fully-linked build produced no output at all rather than a crash.
     SBI is what can print before that, and the failure paths below use it
     for exactly that reason. */
  /* Which way this machine was booted, decided by looking rather than by
     assuming.
   *
   * There are two entry conventions and both are legitimate. SBI firmware
   * hands over with the hart id in a0 and the device tree in a1, which is the
   * boot protocol this port started with. The UEFI loader hands over with a
   * pointer to a boot_info structure in a0, exactly as it does on the other
   * two architectures, and there is no device tree in a1 at all.
   *
   * The structure carries a 64-bit magic, so the two are distinguishable
   * without guessing: a hart id is a small integer and can never be a
   * pointer, and anything that is a pointer is checked against the magic
   * before a single field is believed. The address guard comes first because
   * dereferencing a hart id would fault before the trap vector exists. */
  xaios_boot_info_t *boot = 0;
  if (hart_id >= UINT64_C(0x1000) &&
      ((const xaios_boot_info_t *)(uintptr_t)hart_id)->magic ==
          XAIOS_BOOT_INFO_MAGIC) {
    boot = (xaios_boot_info_t *)(uintptr_t)hart_id;
    device_tree = boot->device_tree;
    /* UEFI started one processor and firmware holds the rest, so the hart
       this is running on is CPU zero and its own id is not needed again. */
    riscv64_smp_record_boot_hart(0U);
    sbi_puts("riscv64: booted through UEFI\n");
  } else {
    riscv64_smp_record_boot_hart((uint32_t)hart_id);
    boot = riscv64_build_boot_info(device_tree);
  }
  if (boot == 0) {
    sbi_puts("riscv64: cannot describe this machine from its device tree\n");
    sbi_shutdown();
  }

  /* The pieces that have to know where things are before anything asks
     them. Both read the tree, which will not be mapped once translation is
     on unless vmm_init keeps it -- it does. */
  const void *blob = (const void *)(uintptr_t)device_tree;
  riscv64_timer_set_device_tree(blob);
  riscv64_exception_set_device_tree(blob);
  riscv64_platform_set_device_tree(blob);

  /* Where this board keeps its virtio slots. The tree lists them as
     separate nodes -- virtio_mmio@10001000 upwards -- so the first one's
     address and the spacing between them is what the transport needs. */
  uint64_t virtio_base = 0U;
  uint32_t virtio_slots = fdt_count_compatible(blob, "virtio,mmio");
  if (fdt_find_compatible_lowest(blob, "virtio,mmio", &virtio_base)) {
    virtio_transport_set_mmio_window(virtio_base, 0x1000U, virtio_slots);
    /* Worth printing: a window that is wrong by a stride finds nothing and
       reports it the same way a machine with no MMIO devices does. */
    sbi_puts("riscv64: virtio mmio window base=");
    sbi_put_u64_hex(virtio_base);
    sbi_puts(" slots=");
    sbi_put_u64(virtio_slots);
    sbi_puts("\n");
  } else {
    /* No tree, so no window -- said explicitly rather than left at the
       default, which is another architecture's address and faults when
       probed. */
    sbi_puts("riscv64: no virtio mmio window in the device tree\n");
    virtio_transport_set_mmio_window(0U, 0U, 0U);
  }

  /* And where it keeps configuration space. The shared ECAM enumerator
     defaults to the address AArch64's firmware uses, which is not this
     board's -- so the bridge is looked up by what it is rather than left at
     what another machine happened to be. Without this the enumerator reads
     all-ones, correctly concludes no host is present, and the boot disk is
     never found on a machine that has one. */
  uint64_t ecam_base = 0U;
  /* Firmware that publishes no device tree may still describe the host
     bridge: the loader reads ACPI's MCFG and passes what it found. Taken from
     there when the tree is silent, and from neither when both are -- in which
     case the enumerator is left with no window and reports no bus, rather
     than probing an address that belongs to a different machine. */
  if (!fdt_find_compatible(blob, "pci-host-ecam-generic", &ecam_base) &&
      boot->pci_ecam_base != 0U) {
    pci_configure_ecam(boot->pci_ecam_base, boot->pci_ecam_start_bus,
                       boot->pci_ecam_end_bus);
  }
  if (ecam_base != 0U) {
    /* Bus numbers come from bus-range in the tree; the generic binding
       defaults to 0-255 when it is absent, and the window's own size caps
       what is reachable regardless. */
    pci_configure_ecam(ecam_base, 0U, 255U);

    /* And where its devices may be placed. This board's firmware is an SBI
       implementation, not a UEFI one, so nothing has assigned base addresses
       and the enumerator has to. The windows come from the bridge's `ranges`,
       which is the only place that says which physical addresses the bridge
       actually decodes -- picking a plausible-looking address instead would
       put devices somewhere the bridge does not answer.

       Each entry is a 3-cell PCI address, then a 2-cell CPU address, then a
       2-cell size: 28 bytes. The top byte of the first cell says what kind of
       space it is -- 1 for I/O, 2 for 32-bit memory, 3 for 64-bit. */
    const uint8_t *ranges = 0;
    uint32_t ranges_length = 0U;
    if (fdt_find_compatible_property(blob, "pci-host-ecam-generic", "ranges",
                                     &ranges, &ranges_length)) {
      uint64_t base32 = 0U, size32 = 0U, base64 = 0U, size64 = 0U;
      for (uint32_t offset = 0U; offset + 28U <= ranges_length; offset += 28U) {
        const uint8_t *entry = ranges + offset;
        uint32_t space = ((uint32_t)entry[0] >> 24) & 0x3U;
        if (space == 0U) space = ((uint32_t)entry[0]) & 0x3U;
        uint64_t cpu = 0U, size = 0U;
        for (uint32_t i = 0U; i < 8U; ++i) cpu = (cpu << 8) | entry[12U + i];
        for (uint32_t i = 0U; i < 8U; ++i) size = (size << 8) | entry[20U + i];
        if (space == 2U) {
          base32 = cpu;
          size32 = size;
        } else if (space == 3U) {
          base64 = cpu;
          size64 = size;
        }
      }
      pci_configure_mmio_window(base32, size32, base64, size64);
    }
  }

  sbi_puts("riscv64: handing over to the shared kernel\n");

  /* And from here it is the same kernel the other two architectures run.
     Not a port of kmain -- kmain itself. */
  kmain(boot);

  sbi_puts("riscv64: kmain returned, which it should not\n");
  sbi_shutdown();
  for (;;) {
    __asm__ volatile("wfi");
  }
}
