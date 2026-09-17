/* VMXNET3 discovery and identity.
 *
 * F-02: VMware Fusion's qualified profile uses PCI E1000E, which works and is
 * the slowest thing the platform offers. VMXNET3 is the paravirtual device
 * Fusion actually wants a guest to use, and nothing here has ever spoken to
 * one.
 *
 * This is the first part of that and only the first: find the device, map its
 * two register windows, agree a revision with it, and read back the identity
 * it reports. No queues, no DMA rings, no frames. The reason for stopping
 * here rather than pressing on is that everything after this point hangs off
 * a structure the device reads out of guest memory itself -- the driver-shared
 * area, a nest of configuration records at fixed offsets -- and a byte wrong
 * in it produces a device that activates and then behaves oddly, which is the
 * hardest kind of fault to tell from a driver bug. Getting discovery and the
 * register offsets confirmed against a real Fusion device first means that
 * when the rings do go in, a failure is about the rings.
 *
 * `network_device` does not know this file exists, so nothing can select a
 * driver that cannot yet carry a frame.
 *
 * The register layout is VMware's published one. Two windows: BAR0 carries
 * the doorbells a driver rings to hand descriptors over, BAR1 the control
 * registers. Commands are written to one register and their answer read back
 * from the same one, which is why `vmxnet3_command_result` writes and reads
 * rather than assuming a separate status word.
 */

#include <xaios/device_window.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/vmm.h>
#include <xaios/vmxnet3.h>

#include "vmxnet3_internal.h"

void vmxnet3_put32(uint8_t *base, uint32_t offset, uint32_t value) {
  base[offset] = (uint8_t)(value & 0xffU);
  base[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
  base[offset + 2U] = (uint8_t)((value >> 16U) & 0xffU);
  base[offset + 3U] = (uint8_t)((value >> 24U) & 0xffU);
}

void vmxnet3_put64(uint8_t *base, uint32_t offset, uint64_t value) {
  vmxnet3_put32(base, offset, (uint32_t)(value & UINT32_C(0xffffffff)));
  vmxnet3_put32(base, offset + 4U, (uint32_t)(value >> 32U));
}

void vmxnet3_put16(uint8_t *base, uint32_t offset, uint16_t value) {
  base[offset] = (uint8_t)(value & 0xffU);
  base[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
}

/* Reading back the same way it is written. The queue descriptor is a byte
   array on purpose, so the fields the device writes have to be reassembled
   little-endian rather than cast to a struct. */
uint32_t vmxnet3_get32(const uint8_t *base, uint32_t offset) {
  return (uint32_t)base[offset] | ((uint32_t)base[offset + 1U] << 8U) |
         ((uint32_t)base[offset + 2U] << 16U) |
         ((uint32_t)base[offset + 3U] << 24U);
}

uint64_t vmxnet3_get64(const uint8_t *base, uint32_t offset) {
  return (uint64_t)vmxnet3_get32(base, offset) |
         ((uint64_t)vmxnet3_get32(base, offset + 4U) << 32U);
}

/* The single driver instance. Its definition lives here; the ring
   and frame files read it through the private header. */
vmxnet3_driver_t *vmxnet3_instance;

uint32_t vmxnet3_read_bar0(uint32_t offset) {
  return *(volatile uint32_t *)(void *)(vmxnet3_instance->bar0 + offset);
}

void vmxnet3_write_bar0(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(vmxnet3_instance->bar0 + offset) = value;
}

uint32_t vmxnet3_read_bar1(uint32_t offset) {
  return *(volatile uint32_t *)(void *)(vmxnet3_instance->bar1 + offset);
}

void vmxnet3_write_bar1(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(vmxnet3_instance->bar1 + offset) = value;
}

/* A command's answer comes back through the register it was written to. */
uint32_t vmxnet3_command_result(uint32_t command) {
  vmxnet3_write_bar1(VMXNET3_REG_CMD, command);
  return vmxnet3_read_bar1(VMXNET3_REG_CMD);
}

static int supported_device(const xaios_pci_device_t *device) {
  return device != 0 && device->vendor_id == VMXNET3_VENDOR_VMWARE &&
         device->device_id == VMXNET3_DEVICE_ID &&
         device->class_code == XAIOS_PCI_CLASS_NETWORK;
}

static xaios_status_t map_window(uint32_t pci_index, uint32_t bar,
                                 const char *owner, uint64_t bytes,
                                 volatile uint8_t **out) {
  uint64_t physical = pci_bar_address(pci_index, bar);
  if (physical == 0U || (physical & (VMXNET3_PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  return device_window_map(owner, physical, bytes, out);
}

/* The highest revision both sides know.
 *
 * VRRS reports a bitmap of what the device supports rather than a number, and
 * a driver picks one and writes it back. Taking the highest bit set is what
 * makes this forward-compatible: a newer device offering revisions this
 * driver has never heard of still has bit 0, and refusing everything but an
 * exact match would turn a working device into an absent one. */
static uint32_t highest_supported(uint32_t bitmap) {
  uint32_t chosen = 0U;
  for (uint32_t bit = 0U; bit < 32U; ++bit) {
    if ((bitmap & (UINT32_C(1) << bit)) != 0U) chosen = bit + 1U;
  }
  return chosen;
}

xaios_status_t vmxnet3_probe(void) {
  if (vmxnet3_instance != 0) {
    return vmxnet3_instance->present != 0U ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
  }
  vmxnet3_instance = (vmxnet3_driver_t *)kheap_calloc(sizeof(*vmxnet3_instance), 16);
  if (vmxnet3_instance == 0) return XAIOS_ERR_NO_MEMORY;

  uint32_t index = 0U;
  const xaios_pci_device_t *found = 0;
  for (uint32_t candidate = 0U; candidate < XAIOS_PCI_MAX_DEVICES;
       ++candidate) {
    const xaios_pci_device_t *device = pci_device(candidate);
    if (device == 0) continue;
    if (supported_device(device)) {
      found = device;
      index = candidate;
      break;
    }
  }
  if (found == 0) return XAIOS_ERR_NOT_FOUND;

  if (pci_enable_device(index) != XAIOS_OK) return XAIOS_ERR_IO;
  xaios_status_t status =
      map_window(index, 0U, "vmxnet3-doorbell", VMXNET3_BAR0_BYTES,
                 &vmxnet3_instance->bar0);
  if (status != XAIOS_OK) {
    klog("vmxnet3: BAR0 mapping failed status=%d\n", (int)status);
    return status;
  }
  status = map_window(index, 1U, "vmxnet3-control", VMXNET3_BAR1_BYTES,
                      &vmxnet3_instance->bar1);
  if (status != XAIOS_OK) {
    klog("vmxnet3: BAR1 mapping failed status=%d\n", (int)status);
    return status;
  }

  uint32_t revisions = vmxnet3_read_bar1(VMXNET3_REG_VRRS);
  vmxnet3_instance->revision = highest_supported(revisions);
  if (vmxnet3_instance->revision == 0U) {
    klog("vmxnet3: device reports no usable revision (vrrs=0x%x)\n",
         revisions);
    return XAIOS_ERR_UNSUPPORTED;
  }
  vmxnet3_write_bar1(VMXNET3_REG_VRRS, UINT32_C(1) << (vmxnet3_instance->revision - 1U));
  uint32_t upt = vmxnet3_read_bar1(VMXNET3_REG_UVRS);
  vmxnet3_instance->upt_version = highest_supported(upt);
  if (vmxnet3_instance->upt_version == 0U) {
    klog("vmxnet3: device reports no usable UPT version (uvrs=0x%x)\n", upt);
    return XAIOS_ERR_UNSUPPORTED;
  }
  vmxnet3_write_bar1(VMXNET3_REG_UVRS, UINT32_C(1) << (vmxnet3_instance->upt_version - 1U));

  /* Prove the doorbell window before trusting a doorbell.
     The control window proves itself: revision, link and the permanent
     address all read back correct values, so a wrong BAR1 would be obvious
     immediately. The doorbell window proves nothing by being written -- every
     store to it succeeds whether or not the device is on the other end, and a
     transmit that is never picked up looks exactly like a protocol bug. IMR
     is the one BAR0 register that reads back what was written, so it is what
     separates "the device ignored the descriptor" from "the device was never
     told there was one". */
  {
    uint64_t bar0_pa = pci_bar_address(index, 0U);
    uint64_t bar1_pa = pci_bar_address(index, 1U);
    uint32_t imr_before = vmxnet3_read_bar0(VMXNET3_REG_IMR);
    vmxnet3_write_bar0(VMXNET3_REG_IMR, 1U);
    uint32_t imr_masked = vmxnet3_read_bar0(VMXNET3_REG_IMR);
    vmxnet3_write_bar0(VMXNET3_REG_IMR, 0U);
    uint32_t imr_cleared = vmxnet3_read_bar0(VMXNET3_REG_IMR);
    klog("vmxnet3: bar0_pa=0x%lx bar1_pa=0x%lx imr before=0x%x set=0x%x "
         "cleared=0x%x doorbell_window=%s\n",
         bar0_pa, bar1_pa, imr_before, imr_masked, imr_cleared,
         (imr_masked == 1U && imr_cleared == 0U) ? "live" : "NOT RESPONDING");
    /* What the configuration space actually says, beside what was made of
       it. A window that reads a constant is either the wrong window or a
       window nothing is decoding, and only the command register and the raw
       base addresses separate the two. */
    klog("vmxnet3: config command=0x%x bar0=0x%x bar1=0x%x bar2=0x%x "
         "txprod_reads=0x%x bar1_vrrs=0x%x bar0_at_vrrs=0x%x\n",
         pci_config_read16(index, 0x04U),
         pci_config_read32(index, 0x10U), pci_config_read32(index, 0x14U),
         pci_config_read32(index, 0x18U),
         vmxnet3_read_bar0(VMXNET3_REG_TXPROD), vmxnet3_read_bar1(VMXNET3_REG_VRRS),
         vmxnet3_read_bar0(0x000U));
  }

  /* The permanent address, asked for rather than read out of MACL/MACH: those
     hold whatever a driver last wrote, which before activation is nothing. */
  uint32_t low = vmxnet3_command_result(VMXNET3_CMD_GET_PERM_MAC_LO);
  uint32_t high = vmxnet3_command_result(VMXNET3_CMD_GET_PERM_MAC_HI);
  vmxnet3_instance->mac[0] = (uint8_t)(low & 0xffU);
  vmxnet3_instance->mac[1] = (uint8_t)((low >> 8U) & 0xffU);
  vmxnet3_instance->mac[2] = (uint8_t)((low >> 16U) & 0xffU);
  vmxnet3_instance->mac[3] = (uint8_t)((low >> 24U) & 0xffU);
  vmxnet3_instance->mac[4] = (uint8_t)(high & 0xffU);
  vmxnet3_instance->mac[5] = (uint8_t)((high >> 8U) & 0xffU);

  /* GET_LINK answers with the state in bit 0 and the speed above it. */
  uint32_t link = vmxnet3_command_result(VMXNET3_CMD_GET_LINK);
  vmxnet3_instance->link_up = (link & 1U) != 0U ? 1U : 0U;
  vmxnet3_instance->link_speed_mbps = link >> 16U;

  vmxnet3_instance->present = 1U;
  klog("vmxnet3: found revision=%u upt=%u link=%u speed=%u mac=%x:%x:%x:%x:%x:%x\n",
       vmxnet3_instance->revision, vmxnet3_instance->upt_version, vmxnet3_instance->link_up,
       vmxnet3_instance->link_speed_mbps, vmxnet3_instance->mac[0], vmxnet3_instance->mac[1],
       vmxnet3_instance->mac[2], vmxnet3_instance->mac[3], vmxnet3_instance->mac[4],
       vmxnet3_instance->mac[5]);
  return XAIOS_OK;
}

uint64_t vmxnet3_dma_address(const void *pointer, uint64_t length) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  uint64_t last_physical = 0U;
  uint32_t last_flags = 0U;
  uint64_t start = (uint64_t)(uintptr_t)pointer;
  if (pointer == 0 || length == 0U ||
      vmm_translate(start, &physical, &flags) != XAIOS_OK ||
      vmm_translate(start + length - 1U, &last_physical, &last_flags) !=
          XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (last_flags & XAIOS_VMM_PRESENT) == 0U ||
      last_physical != physical + length - 1U) {
    return 0U;
  }
  return physical;
}

uint32_t vmxnet3_is_present(void) {
  return vmxnet3_instance != 0 && vmxnet3_instance->present != 0U ? 1U : 0U;
}

xaios_status_t vmxnet3_get_mac(uint8_t mac[6]) {
  if (vmxnet3_is_present() == 0U || mac == 0) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t i = 0U; i < 6U; ++i) mac[i] = vmxnet3_instance->mac[i];
  return XAIOS_OK;
}

uint32_t vmxnet3_link_up(void) {
  return vmxnet3_is_present() != 0U && vmxnet3_instance->link_up != 0U ? 1U : 0U;
}

/* Says what it found, including finding nothing.
 *
 * A machine with no VMXNET3 is the ordinary case -- QEMU has none and Fusion
 * only presents one when its configuration asks for it -- so absence is
 * reported and is not a failure. What would be a failure is a device that is
 * present and answers nonsense, which is why the address is checked for being
 * an address at all rather than merely being read. */
void vmxnet3_self_test(void) {
  if (vmxnet3_probe() != XAIOS_OK) {
    klog("vmxnet3: no device present; this platform uses another NIC\n");
    return;
  }
  uint8_t mac[6];
  if (vmxnet3_get_mac(mac) != XAIOS_OK) {
    klog("vmxnet3: present but reported no address\n");
    return;
  }
  uint32_t all_zero = 1U;
  uint32_t all_ones = 1U;
  for (uint32_t i = 0U; i < 6U; ++i) {
    if (mac[i] != 0x00U) all_zero = 0U;
    if (mac[i] != 0xffU) all_ones = 0U;
  }
  if (all_zero != 0U || all_ones != 0U || (mac[0] & 1U) != 0U) {
    /* All zeroes is an unwritten register, all ones is a window that reads
       back nothing, and a set low bit in the first byte is a multicast
       address, which no interface owns. Each says the read did not reach the
       device rather than that the device has an odd address. */
    klog("vmxnet3: implausible hardware address; the register window is "
         "probably wrong\n");
    return;
  }
  klog("vmxnet3: self-test passed revision=%u link=%u\n", vmxnet3_instance->revision,
       vmxnet3_instance->link_up);
}
