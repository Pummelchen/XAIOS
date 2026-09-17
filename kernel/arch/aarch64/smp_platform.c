/* AArch64 platform discovery for SMP: how many CPUs firmware describes, which
 * MPIDR each ordinal maps to, and the PSCI CPU_ON call that starts one.
 *
 * Everything here is a question asked of firmware or of an interrupt
 * controller, and none of it owns CPU state. smp.c allocates the registry and
 * the secondary stacks, wakes the secondaries through the PSCI call below and
 * releases them at the rendezvous; smp_registry.c serves the registry's public
 * query and lease surface. The whole group moved out of smp.c unchanged: the
 * same order, the same fallback and the same boot-line wording, so the
 * "built-in-fallback" and "ACPI" reports still name what actually answered.
 */
#include <xaios/aarch64_acpi.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/types.h>

#include "smp_internal.h"

#define PSCI_0_2_FN64_CPU_ON UINT64_C(0xc4000003)

/* QEMU virt GICv3 redistributor region used for early CPU discovery. */
/* The layout the ARM virtual-machine convention places a GICv3 at. It is a
   last resort, used only when firmware describes no interrupt controller, and
   the choice is reported: the boot line reads "built-in-fallback" rather than
   "ACPI" whenever these apply. They were named for the hypervisor they were
   taken from, which made one vendor's memory map look like the definition of
   normal -- the same habit that had the loader advertise a serial port to a
   machine with none, and cost this port a boot. See
   docs/PLATFORM-NEUTRALITY.md. */
#define GIC_ARM_VIRT_REDISTRIBUTOR_BASE UINT64_C(0x080A0000)
#define GICR_STRIDE UINT64_C(0x20000)
#define GICR_TYPER 0x0008U
#define GICR_TYPER_LAST (UINT64_C(1) << 4U)
#define GIC_ARM_VIRT_REDISTRIBUTOR_END UINT64_C(0x09000000)
#define GIC_ARM_VIRT_REDISTRIBUTOR_HIGH_BASE UINT64_C(0x4000000000)
#define GIC_ARM_VIRT_REDISTRIBUTOR_HIGH_FRAMES UINT32_C(512)

uint64_t a64smp_read_mpidr_el1(void) {
  uint64_t value = 0;
  __asm__ volatile("mrs %[value], mpidr_el1" : [value] "=r"(value));
  return value;
}

static uint64_t mmio_read64(uint64_t base, uint32_t offset) {
  volatile uint64_t *reg = (volatile uint64_t *)(uintptr_t)(base + offset);
  return *reg;
}

uint64_t a64smp_psci_cpu_on(uint64_t mpidr, uint64_t entry, uint64_t context,
                            uint32_t use_hvc) {
  register uint64_t x0 __asm__("x0") = PSCI_0_2_FN64_CPU_ON;
  register uint64_t x1 __asm__("x1") = mpidr;
  register uint64_t x2 __asm__("x2") = entry;
  register uint64_t x3 __asm__("x3") = context;

  if (use_hvc != 0U) {
    __asm__ volatile("hvc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
  } else {
    __asm__ volatile("smc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
  }
  return x0;
}

/* QEMU virt exposes one contiguous GICv3 redistributor frame per vCPU. */
static uint32_t detect_cpu_count(void) {
  uint64_t frames = (GIC_ARM_VIRT_REDISTRIBUTOR_END - GIC_ARM_VIRT_REDISTRIBUTOR_BASE) / GICR_STRIDE;
  for (uint32_t cpu = 0; cpu < frames; ++cpu) {
    uint64_t base = GIC_ARM_VIRT_REDISTRIBUTOR_BASE + (uint64_t)cpu * GICR_STRIDE;
    if ((mmio_read64(base, GICR_TYPER) & GICR_TYPER_LAST) != 0) {
      if ((uint64_t)cpu + 1U < frames) return cpu + 1U;
      /* UEFI does not map QEMU's high redistributor window. Admit the
       * architectural window here and let PSCI determine populated CPUs. */
      return (uint32_t)frames + GIC_ARM_VIRT_REDISTRIBUTOR_HIGH_FRAMES;
    }
  }
  return 1U;
}

static uint64_t mpidr_for_ordinal(uint32_t ordinal) {
  return (uint64_t)(ordinal % 16U) |
         ((uint64_t)((ordinal / 16U) % 256U) << 8U) |
         ((uint64_t)(ordinal / 4096U) << 16U);
}

int a64smp_acpi_is_qemu_virt(const aarch64_acpi_info_t *info) {
  return info->gic_distributor_base == UINT64_C(0x08000000) &&
         info->gic_redistributor_base == UINT64_C(0x080A0000) &&
         info->pci_ecam_base == UINT64_C(0x4010000000);
}

/* PSCI_VERSION over HVC. Firmware that implements PSCI answers with a version;
   firmware that does not returns NOT_SUPPORTED. HVC is the conduit this tree
   already uses for SYSTEM_OFF on every AArch64 target. */
static uint32_t psci_probe_version(void) {
  register uint64_t x0 __asm__("x0") = UINT64_C(0x84000000);
  __asm__ volatile("hvc #0" : "+r"(x0) : : "x1", "x2", "x3", "memory");
  return (uint32_t)x0;
}

uint32_t a64smp_platform_cpu_capacity(const xaios_boot_info_t *boot,
                                      aarch64_acpi_info_t *acpi_info) {
  if (aarch64_acpi_parse(boot->acpi_rsdp, acpi_info) != 0 &&
      acpi_info->enabled_cpus != 0U) {
    if (acpi_info->psci_compliant != 0U || a64smp_acpi_is_qemu_virt(acpi_info)) {
      return acpi_info->enabled_cpus;
    }
    /* Firmware may implement PSCI and still leave the FADT's boot-architecture
       flags clear; Virtualization.framework reports four enabled CPUs that way
       while answering PSCI perfectly well. Refusing every secondary on the
       strength of an unset flag costs the whole machine, so ask PSCI itself
       before giving up on it. */
    if (acpi_info->enabled_cpus > 1U) {
      uint32_t version = psci_probe_version();
      if (version != UINT32_MAX && (version >> 16U) <= 1U) {
        klog("smp: firmware answers PSCI %u.%u without advertising it\n",
             version >> 16U, version & UINT32_C(0xffff));
        acpi_info->psci_compliant = 1U;
        acpi_info->psci_use_hvc = 1U;
        return acpi_info->enabled_cpus;
      }
    }
    return 1U;
  }
  *acpi_info = (aarch64_acpi_info_t){0};
  return detect_cpu_count();
}

uint64_t a64smp_platform_mpidr(const aarch64_acpi_info_t *acpi_info,
                               uint64_t boot_mpidr, uint32_t ordinal) {
  if (acpi_info->madt == 0U) return mpidr_for_ordinal(ordinal);
  if (ordinal == 0U) return boot_mpidr;
  uint32_t selected = 1U;
  for (uint32_t index = 0U; index < acpi_info->enabled_cpus; ++index) {
    uint64_t candidate = 0U;
    if (aarch64_acpi_cpu_mpidr(acpi_info, index, &candidate) == 0) break;
    if ((candidate & UINT64_C(0x00ffffff)) ==
        (boot_mpidr & UINT64_C(0x00ffffff))) {
      continue;
    }
    if (selected++ == ordinal) return candidate;
  }
  return 0U;
}
