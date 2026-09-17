/* Giving devices somewhere to live, when nothing else has.
 *
 * On every machine this kernel ran on before, firmware assigned PCI base
 * addresses before handing over: UEFI does it, and so does the firmware in a
 * hypervisor's virtual machine. A board booted straight from a supervisor-mode
 * SBI has no such stage, and its devices arrive with every base address still
 * zero -- present, enumerable, correctly identified, and unreachable. The
 * symptom is precise and misleading: a virtio device found by vendor and
 * device id whose capability structures all resolve to address zero, which
 * reads as a broken driver rather than an unfinished bus.
 *
 * Assignment only touches a base address that is zero, so a machine whose
 * firmware did this work keeps that firmware's layout untouched. Sizing is the
 * architectural method: write all-ones, read back, and the lowest bit still
 * set is the size, because the bits below it are hardwired to zero.
 */
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/types.h>

#include "pci_ecam_internal.h"

static uint64_t g_mmio_next;
static uint64_t g_mmio_limit;
static uint64_t g_mmio64_next;
static uint64_t g_mmio64_limit;

void pci_configure_mmio_window(uint64_t base, uint64_t size, uint64_t base64,
                               uint64_t size64) {
  g_mmio_next = base;
  g_mmio_limit = base + size;
  g_mmio64_next = base64;
  g_mmio64_limit = base64 + size64;
}

static uint64_t allocate_window(uint64_t size, int wide) {
  if (size == 0U) return 0U;
  uint64_t *next = wide != 0 ? &g_mmio64_next : &g_mmio_next;
  uint64_t limit = wide != 0 ? g_mmio64_limit : g_mmio_limit;
  /* Naturally aligned, which the specification requires and which a device
     silently ignores rather than reporting: an unaligned base has its low
     bits read back as zero and the device answers somewhere else. */
  uint64_t aligned = (*next + size - 1U) & ~(size - 1U);
  if (aligned + size > limit || limit == 0U) return 0U;
  *next = aligned + size;
  return aligned;
}

void pci_ecam_assign_bars(uint8_t bus, uint8_t dev, uint8_t func) {
  if (g_mmio_limit == 0U && g_mmio64_limit == 0U) return;
  for (uint32_t bar = 0; bar < XAIOS_PCI_MAX_BARS; ++bar) {
    uint16_t offset = (uint16_t)(XAIOS_PCI_BAR0 + bar * 4U);
    uint32_t low = pci_ecam_read32(bus, dev, func, offset);
    if ((low & 1U) != 0U) continue; /* an I/O port range, not memory */
    uint32_t type = (low >> 1U) & 3U;
    int wide = type == 2U ? 1 : 0;
    if (wide != 0 && bar + 1U >= XAIOS_PCI_MAX_BARS) break;

    uint64_t assigned = low & ~UINT64_C(0xf);
    if (wide != 0) {
      assigned |= (uint64_t)pci_ecam_read32(bus, dev, func,
                                            (uint16_t)(offset + 4U)) << 32U;
    }
    if (assigned != 0U) {
      /* Already placed by firmware. Left exactly where it was. */
      if (wide != 0) ++bar;
      continue;
    }

    pci_ecam_write32(bus, dev, func, offset, UINT32_C(0xffffffff));
    uint32_t probe_low = pci_ecam_read32(bus, dev, func, offset);
    uint64_t mask = (uint64_t)(probe_low & ~UINT32_C(0xf));
    if (wide != 0) {
      pci_ecam_write32(bus, dev, func, (uint16_t)(offset + 4U),
                       UINT32_C(0xffffffff));
      mask |= (uint64_t)pci_ecam_read32(bus, dev, func,
                                        (uint16_t)(offset + 4U)) << 32U;
    } else {
      mask |= ~UINT64_C(0xffffffff); /* sign-extend so ~mask+1 is the size */
    }
    uint64_t size = (~mask) + 1U;
    if (size == 0U || mask == ~UINT64_C(0)) {
      /* An unimplemented BAR reads back as all-zero once masked. Restored to
         zero rather than left holding the probe pattern. */
      pci_ecam_write32(bus, dev, func, offset, 0U);
      if (wide != 0) {
        pci_ecam_write32(bus, dev, func, (uint16_t)(offset + 4U), 0U);
        ++bar;
      }
      continue;
    }

    uint64_t address = allocate_window(size, wide);
    if (address == 0U) {
      klog("PCI: [%u:%u.%u] bar%u wants 0x%lx and the window is exhausted\n",
           bus, dev, func, bar, size);
      pci_ecam_write32(bus, dev, func, offset, 0U);
      if (wide != 0) {
        pci_ecam_write32(bus, dev, func, (uint16_t)(offset + 4U), 0U);
      }
      if (wide != 0) ++bar;
      continue;
    }
    pci_ecam_write32(bus, dev, func, offset,
                     (uint32_t)(address & UINT64_C(0xffffffff)) | (low & 0xfU));
    if (wide != 0) {
      pci_ecam_write32(bus, dev, func, (uint16_t)(offset + 4U),
                       (uint32_t)(address >> 32U));
      ++bar;
    }
  }

  /* Decoding has to be switched on, or every one of those addresses answers
     with all-ones exactly as an absent device would. */
  uint16_t command = pci_ecam_read16(bus, dev, func, XAIOS_PCI_COMMAND);
  pci_ecam_write16(bus, dev, func, XAIOS_PCI_COMMAND,
                   (uint16_t)(command | XAIOS_PCI_COMMAND_MEMORY |
                              XAIOS_PCI_COMMAND_BUS_MASTER));
}
