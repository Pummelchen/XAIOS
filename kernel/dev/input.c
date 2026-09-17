#include <xaios/device_window.h>
#include <xaios/arch_cpu.h>
#include <xaios/input.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

#include "input_internal.h"

static xhci_keyboard_t *g_keyboard;

static uint32_t mmio_read32(uint64_t address) {
  return *(volatile uint32_t *)(uintptr_t)address;
}
static void mmio_write32(uint64_t address, uint32_t value) {
  *(volatile uint32_t *)(uintptr_t)address = value;
}
static void mmio_write64(uint64_t address, uint64_t value) {
  *(volatile uint64_t *)(uintptr_t)address = value;
}
void input_zero_bytes(void *buffer, uint64_t bytes) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < bytes; ++i) out[i] = 0U;
}
void input_copy_bytes(void *destination, const void *source, uint64_t bytes) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t i = 0U; i < bytes; ++i) out[i] = in[i];
}
uint64_t input_dma_address(const void *pointer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (vmm_translate((uint64_t)(uintptr_t)pointer, &physical, &flags) != XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U) return 0U;
  return physical;
}
static int map_mmio(uint64_t physical_base, uint64_t bytes, uint64_t *virtual_base) {
  if (physical_base == 0U || bytes == 0U || virtual_base == 0 ||
      physical_base > UINT64_MAX - bytes) return 0;
  volatile uint8_t *window = 0;
  if (device_window_map("input", physical_base, bytes, &window) != XAIOS_OK) {
    return 0;
  }
  *virtual_base = (uint64_t)(uintptr_t)window;
  return 1;
}

static int wait_register(uint64_t address, uint32_t set, uint32_t clear) {
  uint64_t start = timer_now_ns();
  for (uint64_t spins = 0U; spins < UINT64_C(10000000); ++spins) {
    uint32_t value = mmio_read32(address);
    if ((value & set) == set && (value & clear) == 0U) return 1;
    if ((spins & UINT64_C(0x3ff)) == 0U && start != 0U &&
        timer_now_ns() - start > UINT64_C(1000000000)) return 0;
  }
  return 0;
}
static xhci_trb_t *command_trb(xhci_keyboard_t *keyboard) {
  if (keyboard->command_index >= XHCI_RING_SIZE - 1U) return 0;
  return &keyboard->command_ring[keyboard->command_index++];
}
void input_ring_doorbell(xhci_keyboard_t *keyboard, uint32_t target) {
  xaios_cpu_io_barrier();
  uint32_t slot = target == 0U ? 0U : keyboard->slot_id;
  mmio_write32(keyboard->doorbell + (uint64_t)slot * 4U, target);
}
static int next_event(xhci_keyboard_t *keyboard, xhci_trb_t *event) {
  xhci_trb_t *source = &keyboard->event_ring[keyboard->event_index];
  if ((source->control & XHCI_TRB_CYCLE) != keyboard->event_cycle) return 0;
  *event = *source;
  xaios_cpu_memory_barrier();
  ++keyboard->event_index;
  if (keyboard->event_index == XHCI_EVENT_RING_SIZE) {
    keyboard->event_index = 0U;
    keyboard->event_cycle ^= XHCI_TRB_CYCLE;
  }
  mmio_write64(keyboard->runtime + XHCI_ERDP,
               input_dma_address(&keyboard->event_ring[keyboard->event_index]) | UINT64_C(0x8));
  /* Acknowledge the consumed event while retaining primary-interrupter enable. */
  mmio_write32(keyboard->runtime + XHCI_IMAN, UINT32_C(3));
  return 1;
}
static int wait_command(xhci_keyboard_t *keyboard, const xhci_trb_t *submitted,
                        uint32_t *slot_id) {
  uint64_t wanted = input_dma_address(submitted);
  uint64_t start = timer_now_ns();
  for (;;) {
    xhci_trb_t event;
    while (next_event(keyboard, &event)) {
      uint32_t type = (event.control >> XHCI_TRB_TYPE_SHIFT) & UINT32_C(0x3f);
      if (type == XHCI_TRB_COMMAND_EVENT &&
          (((uint64_t)event.parameter_hi << 32U) | event.parameter_lo) == wanted) {
        uint32_t completion = (event.status >> 24U) & UINT32_C(0xff);
        if (completion != XHCI_CC_SUCCESS) {
          klog("input: xHCI command completion=%u\n", completion);
          return 0;
        }
        if (slot_id != 0) *slot_id = event.control >> 24U;
        return 1;
      }
    }
    if (start != 0U && timer_now_ns() - start > UINT64_C(1000000000)) return 0;
  }
}
int input_submit_command(xhci_keyboard_t *keyboard, uint32_t type,
                         uint64_t parameter, uint32_t control, uint32_t *slot_id) {
  xhci_trb_t *trb = command_trb(keyboard);
  if (trb == 0) return 0;
  trb->parameter_lo = (uint32_t)parameter;
  trb->parameter_hi = (uint32_t)(parameter >> 32U);
  trb->status = 0U;
  trb->control = (type << XHCI_TRB_TYPE_SHIFT) | control | keyboard->command_cycle;
  input_ring_doorbell(keyboard, 0U);
  return wait_command(keyboard, trb, slot_id);
}
void input_context_write32(uint8_t *context, uint32_t index, uint32_t value) {
  *(uint32_t *)(void *)(context + (uint64_t)index * 4U) = value;
}
uint32_t input_context_read32(const uint8_t *context, uint32_t index) {
  return *(const uint32_t *)(const void *)(context + (uint64_t)index * 4U);
}
int input_control_transfer(xhci_keyboard_t *keyboard, uint8_t request_type,
                           uint8_t request, uint16_t value, uint16_t index,
                           void *data, uint16_t length) {
  xhci_trb_t *ring = keyboard->ep0_ring;
  uint32_t base = keyboard->ep0_index;
  if (base + 3U >= XHCI_RING_SIZE) return 0;
  uint32_t setup = (uint32_t)request_type | ((uint32_t)request << 8U) |
                   ((uint32_t)value << 16U);
  ring[base].parameter_lo = setup;
  ring[base].parameter_hi = (uint32_t)index | ((uint32_t)length << 16U);
  ring[base].status = 8U;
  ring[base].control = (XHCI_TRB_SETUP << XHCI_TRB_TYPE_SHIFT) |
                       XHCI_TRB_IDT | XHCI_TRB_CHAIN | XHCI_TRB_CYCLE |
                       (length == 0U ? 0U :
                        (request_type & UINT8_C(0x80) ? 3U : 2U) << 16U);
  uint32_t status_index = base + 1U;
  if (length != 0U) {
    uint64_t physical = input_dma_address(data);
    if (physical == 0U) return 0;
    ring[base + 1U].parameter_lo = (uint32_t)physical;
    ring[base + 1U].parameter_hi = (uint32_t)(physical >> 32U);
    ring[base + 1U].status = length;
    ring[base + 1U].control = (XHCI_TRB_DATA << XHCI_TRB_TYPE_SHIFT) |
                              XHCI_TRB_CHAIN | XHCI_TRB_CYCLE |
                              ((request_type & UINT8_C(0x80)) != 0U ?
                                   UINT32_C(1 << 16) : 0U);
    status_index = base + 2U;
  }
  ring[status_index].control = (XHCI_TRB_STATUS << XHCI_TRB_TYPE_SHIFT) |
                               XHCI_TRB_IOC | XHCI_TRB_CYCLE |
                               ((length == 0U || (request_type & UINT8_C(0x80)) == 0U) ?
                                    UINT32_C(1 << 16) : 0U);
  keyboard->ep0_index = status_index + 1U;
  input_ring_doorbell(keyboard, 1U);
  uint64_t wanted = input_dma_address(&ring[status_index]);
  uint64_t start = timer_now_ns();
  for (;;) {
    xhci_trb_t event;
    while (next_event(keyboard, &event)) {
      uint32_t type = (event.control >> XHCI_TRB_TYPE_SHIFT) & UINT32_C(0x3f);
      uint64_t pointer = ((uint64_t)event.parameter_hi << 32U) | event.parameter_lo;
      if (type == XHCI_TRB_TRANSFER_EVENT && pointer != wanted) {
        klog("input: xHCI control event pointer=0x%lx expected=0x%lx\n",
             pointer, wanted);
      }
      if (type == XHCI_TRB_TRANSFER_EVENT && pointer == wanted) {
        uint32_t completion = (event.status >> 24U) & UINT32_C(0xff);
        if (completion != XHCI_CC_SUCCESS) {
          klog("input: xHCI control completion=%u\n", completion);
        }
        return completion == XHCI_CC_SUCCESS;
      }
    }
    if (start != 0U && timer_now_ns() - start > UINT64_C(1000000000)) {
      klog("input: xHCI control transfer timed out\n");
      return 0;
    }
  }
}

static int setup_controller(xhci_keyboard_t *keyboard) {
  uint32_t caps = mmio_read32(keyboard->base + 4U);
  uint32_t slots = caps & UINT32_C(0xff);
  keyboard->context_bytes = (mmio_read32(keyboard->base + 16U) & UINT32_C(4)) != 0U ? 64U : 32U;
  if (slots == 0U) return 0;
  if (slots > XHCI_MAX_SLOTS) slots = XHCI_MAX_SLOTS;
  mmio_write32(keyboard->operational + XHCI_USBCMD,
               mmio_read32(keyboard->operational + XHCI_USBCMD) & ~XHCI_USBCMD_RUN);
  if (!wait_register(keyboard->operational + XHCI_USBSTS, XHCI_USBSTS_HCH, 0U)) return 0;
  mmio_write32(keyboard->operational + XHCI_USBCMD, XHCI_USBCMD_HCRST);
  if (!wait_register(keyboard->operational + XHCI_USBCMD, 0U, XHCI_USBCMD_HCRST) ||
      !wait_register(keyboard->operational + XHCI_USBSTS, 0U, XHCI_USBSTS_CNR)) return 0;
  mmio_write64(keyboard->operational + XHCI_DCBAAP, input_dma_address(keyboard->dcbaa));
  mmio_write64(keyboard->operational + XHCI_CRCR, input_dma_address(keyboard->command_ring) | XHCI_TRB_CYCLE);
  keyboard->erst->base = input_dma_address(keyboard->event_ring);
  keyboard->erst->size = XHCI_EVENT_RING_SIZE;
  mmio_write32(keyboard->runtime + XHCI_ERSTSZ, 1U);
  mmio_write64(keyboard->runtime + XHCI_ERSTBA, input_dma_address(keyboard->erst));
  mmio_write64(keyboard->runtime + XHCI_ERDP, input_dma_address(keyboard->event_ring));
  mmio_write32(keyboard->runtime + XHCI_IMAN, UINT32_C(2));
  mmio_write32(keyboard->operational + XHCI_CONFIG, slots);
  mmio_write32(keyboard->operational + XHCI_USBCMD, XHCI_USBCMD_RUN);
  return wait_register(keyboard->operational + XHCI_USBSTS, 0U, XHCI_USBSTS_HCH);
}
static int initialize_keyboard(xhci_keyboard_t *keyboard) {
  if (!setup_controller(keyboard)) {
    klog("input: xHCI controller setup failed status=0x%x\n",
         mmio_read32(keyboard->operational + XHCI_USBSTS));
    return 0;
  }
  uint32_t max_ports = (mmio_read32(keyboard->base + 4U) >> 24U) & UINT32_C(0xff);
  for (uint32_t port = 1U; port <= max_ports; ++port) {
    uint64_t portsc = keyboard->operational + XHCI_PORTSC + (uint64_t)(port - 1U) * 16U;
    uint32_t state = mmio_read32(portsc);
    if ((state & XHCI_PORTSC_CCS) == 0U) continue;
    mmio_write32(portsc, (state & UINT32_C(0x0000ffff)) | XHCI_PORTSC_PP | XHCI_PORTSC_PR);
    if (!wait_register(portsc, XHCI_PORTSC_PED, XHCI_PORTSC_PR)) continue;
    uint32_t slot_id = 0U;
    if (!input_submit_command(keyboard, XHCI_TRB_ENABLE_SLOT, 0U, 0U, &slot_id) ||
        slot_id == 0U) {
      klog("input: xHCI enable-slot failed port=%u\n", port);
      continue;
    }
    keyboard->slot_id = slot_id;
    input_zero_bytes(keyboard->input_context, keyboard->context_bytes * 33U);
    input_context_write32(keyboard->input_context, 1U, 3U);
    uint8_t *slot = keyboard->input_context + keyboard->context_bytes;
    uint32_t speed = (mmio_read32(portsc) >> 10U) & UINT32_C(0xf);
    uint32_t ep0_packet = speed == 2U ? 8U : (speed == 4U ? 512U : 64U);
    input_context_write32(slot, 0U, (speed << 20U) | (UINT32_C(1) << 27U));
    input_context_write32(slot, 1U, port << 16U);
    uint8_t *ep0 = keyboard->input_context + keyboard->context_bytes * 2U;
    uint64_t ep0_ring = input_dma_address(keyboard->ep0_ring);
    /* Each slot's device context starts its control endpoint at the base of
       this ring, so the driver's enqueue position has to start there too.
       Without this reset a second device inherits the previous device's
       position, and every control transfer to it times out waiting for
       completions that reference TRBs the controller already passed. */
    keyboard->ep0_index = 0U;
    input_zero_bytes(keyboard->ep0_ring, sizeof(xhci_trb_t) * XHCI_RING_SIZE);
    keyboard->ep0_ring[XHCI_RING_SIZE - 1U].parameter_lo = (uint32_t)ep0_ring;
    keyboard->ep0_ring[XHCI_RING_SIZE - 1U].parameter_hi =
        (uint32_t)(ep0_ring >> 32U);
    keyboard->ep0_ring[XHCI_RING_SIZE - 1U].control =
        (XHCI_TRB_LINK << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_CYCLE |
        UINT32_C(1 << 1);
    input_context_write32(ep0, 1U, (3U << 1U) | (4U << 3U) |
                              (ep0_packet << 16U));
    input_context_write32(ep0, 2U, (uint32_t)ep0_ring | XHCI_TRB_CYCLE);
    input_context_write32(ep0, 3U, (uint32_t)(ep0_ring >> 32U));
    input_context_write32(ep0, 4U, 8U);
    keyboard->dcbaa[slot_id] = input_dma_address(keyboard->device_context);
    if (!input_submit_command(keyboard, XHCI_TRB_ADDRESS_DEVICE,
                        input_dma_address(keyboard->input_context), slot_id << 24U, 0)) {
      klog("input: xHCI address-device failed port=%u slot=%u\n", port, slot_id);
      continue;
    }
    klog("input: xHCI addressed port=%u slot=%u slot_state=0x%x ep0_state=0x%x\n",
         port, slot_id, input_context_read32(keyboard->device_context, 3U),
         input_context_read32(keyboard->device_context + keyboard->context_bytes, 0U));
    klog("input: xHCI ep0 deq=0x%x%08x expected=0x%lx\n",
         input_context_read32(keyboard->device_context + keyboard->context_bytes, 3U),
         input_context_read32(keyboard->device_context + keyboard->context_bytes, 2U),
         ep0_ring | XHCI_TRB_CYCLE);
    if (input_configure_keyboard(keyboard, port)) return 1;
    klog("input: xHCI HID configuration failed port=%u slot=%u\n", port, slot_id);
  }
  return 0;
}
void input_poll(void) {
  if (g_keyboard == 0 || g_keyboard->initialized == 0U) return;
  xhci_trb_t event;
  while (next_event(g_keyboard, &event)) {
    uint32_t type = (event.control >> XHCI_TRB_TYPE_SHIFT) & UINT32_C(0x3f);
    if (type != XHCI_TRB_TRANSFER_EVENT) continue;
    uint64_t pointer = ((uint64_t)event.parameter_hi << 32U) | event.parameter_lo;
    if (pointer != input_dma_address(&g_keyboard->interrupt_ring[g_keyboard->transfer_index])) continue;
    if (((event.status >> 24U) & UINT32_C(0xff)) == XHCI_CC_SUCCESS) {
      input_process_report(g_keyboard->report, g_keyboard->previous_report);
    }
    uint32_t next_index = g_keyboard->transfer_index + 1U;
    if (next_index == XHCI_RING_SIZE - 1U) {
      next_index = 0U;
      g_keyboard->transfer_cycle ^= XHCI_TRB_CYCLE;
    }
    g_keyboard->interrupt_ring[next_index].parameter_lo =
        (uint32_t)input_dma_address(g_keyboard->report);
    g_keyboard->interrupt_ring[next_index].parameter_hi =
        (uint32_t)(input_dma_address(g_keyboard->report) >> 32U);
    g_keyboard->interrupt_ring[next_index].status = 8U;
    g_keyboard->interrupt_ring[next_index].control =
        (XHCI_TRB_NORMAL << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_IOC |
        g_keyboard->transfer_cycle;
    g_keyboard->transfer_index = next_index;
    input_ring_doorbell(g_keyboard, g_keyboard->endpoint_dci);
  }
}
static int allocate_keyboard(xhci_keyboard_t *keyboard) {
  keyboard->command_ring = kheap_calloc(sizeof(xhci_trb_t) * XHCI_RING_SIZE, 64U);
  keyboard->event_ring = kheap_calloc(sizeof(xhci_trb_t) * XHCI_EVENT_RING_SIZE, 64U);
  keyboard->ep0_ring = kheap_calloc(sizeof(xhci_trb_t) * XHCI_RING_SIZE, 64U);
  keyboard->interrupt_ring = kheap_calloc(sizeof(xhci_trb_t) * XHCI_RING_SIZE, 64U);
  keyboard->erst = kheap_calloc(sizeof(xhci_erst_t), 64U);
  keyboard->dcbaa = kheap_calloc(sizeof(uint64_t) * 256U, 64U);
  keyboard->device_context = kheap_calloc(64U * 33U, 64U);
  keyboard->input_context = kheap_calloc(64U * 33U, 64U);
  keyboard->report = kheap_calloc(8U, 64U);
  return keyboard->command_ring != 0 && keyboard->event_ring != 0 && keyboard->ep0_ring != 0 &&
         keyboard->interrupt_ring != 0 && keyboard->erst != 0 && keyboard->dcbaa != 0 &&
         keyboard->device_context != 0 && keyboard->input_context != 0 && keyboard->report != 0;
}
void input_init(void) {
  if (g_keyboard != 0) return;
  for (uint32_t index = 0U; index < pci_device_count(); ++index) {
    const xaios_pci_device_t *device = pci_device(index);
    if (device == 0 || device->class_code != XHCI_CLASS ||
        device->subclass != XHCI_SUBCLASS || device->prog_if != XHCI_PROGIF) continue;
    uint64_t bar = pci_bar_address(index, 0U);
    uint64_t base = 0U;
    klog("input: probing xHCI pci=%u bar=0x%lx\n", index, bar);
    if (bar == 0U || !map_mmio(bar, UINT64_C(0x5000), &base)) {
      klog("input: xHCI MMIO map failed pci=%u\n", index);
      continue;
    }
    if (pci_enable_device(index) != XAIOS_OK) {
      klog("input: xHCI PCI enable failed pci=%u\n", index);
      continue;
    }
    xhci_keyboard_t *keyboard = kheap_calloc(sizeof(*keyboard), 64U);
    if (keyboard == 0 || !allocate_keyboard(keyboard)) {
      klog("input: xHCI DMA allocation failed pci=%u\n", index);
      return;
    }
    keyboard->pci_index = index;
    keyboard->base = base;
    keyboard->operational = base + *(volatile uint8_t *)(uintptr_t)base;
    keyboard->doorbell = base + (mmio_read32(base + 20U) & ~UINT32_C(3));
    keyboard->runtime = base + (mmio_read32(base + 24U) & ~UINT32_C(0x1f));
    keyboard->event_cycle = XHCI_TRB_CYCLE;
    keyboard->command_cycle = XHCI_TRB_CYCLE;
    if (initialize_keyboard(keyboard)) {
      keyboard->initialized = 1U;
      g_keyboard = keyboard;
      klog("input: xHCI HID boot keyboard initialized pci=%u\n", index);
    } else {
      klog("input: xHCI HID keyboard probe failed pci=%u bar=0x%lx\n",
           index, bar);
    }
    return;
  }
  klog("input: no xHCI HID keyboard available; serial console remains active\n");
}

uint32_t input_keyboard_available(void) {
  return g_keyboard != 0 && g_keyboard->initialized != 0U;
}
