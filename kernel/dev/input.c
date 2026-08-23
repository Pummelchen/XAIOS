#include <xaios/assert.h>
#include <xaios/arch_cpu.h>
#include <xaios/input.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

#define INPUT_QUEUE_SIZE 128U
#define INPUT_MMIO_VIRTUAL_BASE UINT64_C(0x340000000)
#define XHCI_CLASS UINT8_C(0x0c)
#define XHCI_SUBCLASS UINT8_C(0x03)
#define XHCI_PROGIF UINT8_C(0x30)
#define XHCI_RING_SIZE 32U
#define XHCI_EVENT_RING_SIZE 32U
#define XHCI_MAX_SLOTS 8U
#define XHCI_PORTSC UINT32_C(0x400)
#define XHCI_USBCMD UINT32_C(0x00)
#define XHCI_USBSTS UINT32_C(0x04)
#define XHCI_CRCR UINT32_C(0x18)
#define XHCI_DCBAAP UINT32_C(0x30)
#define XHCI_CONFIG UINT32_C(0x38)
#define XHCI_IMAN UINT32_C(0x20)
#define XHCI_ERSTSZ UINT32_C(0x28)
#define XHCI_ERSTBA UINT32_C(0x30)
#define XHCI_ERDP UINT32_C(0x38)
#define XHCI_TRB_CYCLE UINT32_C(1)
#define XHCI_TRB_CHAIN UINT32_C(1 << 4)
#define XHCI_TRB_IOC UINT32_C(1 << 5)
#define XHCI_TRB_IDT UINT32_C(1 << 6)
#define XHCI_TRB_TYPE_SHIFT 10U
#define XHCI_TRB_NORMAL 1U
#define XHCI_TRB_SETUP 2U
#define XHCI_TRB_DATA 3U
#define XHCI_TRB_STATUS 4U
#define XHCI_TRB_LINK 6U
#define XHCI_TRB_ENABLE_SLOT 9U
#define XHCI_TRB_ADDRESS_DEVICE 11U
#define XHCI_TRB_CONFIGURE_ENDPOINT 12U
#define XHCI_TRB_TRANSFER_EVENT 32U
#define XHCI_TRB_COMMAND_EVENT 33U
#define XHCI_CC_SUCCESS 1U
#define XHCI_USBSTS_HCH UINT32_C(1)
#define XHCI_USBSTS_CNR UINT32_C(1 << 11)
#define XHCI_USBCMD_RUN UINT32_C(1)
#define XHCI_USBCMD_HCRST UINT32_C(1 << 1)
#define XHCI_PORTSC_CCS UINT32_C(1)
#define XHCI_PORTSC_PED UINT32_C(1 << 1)
#define XHCI_PORTSC_PR UINT32_C(1 << 4)
#define XHCI_PORTSC_PP UINT32_C(1 << 9)

typedef struct xhci_trb {
  uint32_t parameter_lo;
  uint32_t parameter_hi;
  uint32_t status;
  uint32_t control;
} xhci_trb_t;

typedef struct xhci_erst {
  uint64_t base;
  uint32_t size;
  uint32_t reserved;
} xhci_erst_t;

typedef struct xhci_keyboard {
  uint32_t pci_index;
  uint64_t base;
  uint64_t operational;
  uint64_t doorbell;
  uint64_t runtime;
  uint32_t context_bytes;
  uint32_t slot_id;
  uint32_t endpoint_dci;
  uint32_t event_index;
  uint32_t event_cycle;
  uint32_t command_index;
  uint32_t command_cycle;
  uint32_t ep0_index;
  uint32_t transfer_index;
  uint32_t transfer_cycle;
  uint32_t initialized;
  xhci_trb_t *command_ring;
  xhci_trb_t *event_ring;
  xhci_trb_t *ep0_ring;
  xhci_trb_t *interrupt_ring;
  xhci_erst_t *erst;
  uint64_t *dcbaa;
  uint8_t *device_context;
  uint8_t *input_context;
  uint8_t *report;
  uint8_t previous_report[8];
} xhci_keyboard_t;

static uint8_t g_queue[INPUT_QUEUE_SIZE];
static uint32_t g_queue_head;
static uint32_t g_queue_tail;
static xaios_spinlock_t g_input_lock = XAIOS_SPINLOCK_INIT;
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
static void zero_bytes(void *buffer, uint64_t bytes) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < bytes; ++i) out[i] = 0U;
}
static void copy_bytes(void *destination, const void *source, uint64_t bytes) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t i = 0U; i < bytes; ++i) out[i] = in[i];
}
static uint64_t dma_address(const void *pointer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (vmm_translate((uint64_t)(uintptr_t)pointer, &physical, &flags) != XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U) return 0U;
  return physical;
}
static int map_mmio(uint64_t physical_base, uint64_t bytes, uint64_t *virtual_base) {
  if (physical_base == 0U || bytes == 0U || virtual_base == 0 ||
      physical_base > UINT64_MAX - bytes) return 0;
  uint64_t physical_page = physical_base & ~UINT64_C(0xfff);
  uint64_t virtual_page = INPUT_MMIO_VIRTUAL_BASE;
  uint64_t end = (physical_base + bytes + UINT64_C(0xfff)) & ~UINT64_C(0xfff);
  while (physical_page < end) {
    uint64_t physical = 0U;
    uint32_t flags = 0U;
    if (vmm_translate(virtual_page, &physical, &flags) != XAIOS_OK ||
        physical != physical_page ||
        (flags & XAIOS_VMM_DEVICE) == 0U) {
      if (vmm_map_page(virtual_page, physical_page,
                       XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                           XAIOS_VMM_DEVICE) != XAIOS_OK) return 0;
    }
    physical_page += UINT64_C(4096);
    virtual_page += UINT64_C(4096);
  }
  *virtual_base = INPUT_MMIO_VIRTUAL_BASE + (physical_base & UINT64_C(0xfff));
  return 1;
}
static void queue_byte(uint8_t value) {
  xaios_spin_lock(&g_input_lock);
  uint32_t next = (g_queue_head + 1U) % INPUT_QUEUE_SIZE;
  if (next != g_queue_tail) {
    g_queue[g_queue_head] = value;
    g_queue_head = next;
  }
  xaios_spin_unlock(&g_input_lock);
}
static int usage_was_pressed(const uint8_t report[8], uint8_t usage) {
  for (uint32_t i = 2U; i < 8U; ++i) if (report[i] == usage) return 1;
  return 0;
}
static void queue_escape(uint8_t code) {
  queue_byte(UINT8_C(0x1b));
  queue_byte('[');
  queue_byte(code);
}
static void translate_usage(uint8_t modifiers, uint8_t usage) {
  int shift = (modifiers & UINT8_C(0x22)) != 0U;
  if (usage >= 4U && usage <= 29U) {
    queue_byte((uint8_t)((shift ? 'A' : 'a') + usage - 4U));
    return;
  }
  if (usage >= 30U && usage <= 38U) {
    static const char shifted[] = ")!@#$%^&*(";
    queue_byte((uint8_t)(shift ? shifted[usage - 30U] : '1' + usage - 30U));
    return;
  }
  switch (usage) {
  case 39U: queue_byte(shift ? '(' : '0'); break;
  case 40U: queue_byte('\n'); break;
  case 42U: queue_byte('\b'); break;
  case 43U: queue_byte('\t'); break;
  case 44U: queue_byte(' '); break;
  case 45U: queue_byte(shift ? '_' : '-'); break;
  case 46U: queue_byte(shift ? '+' : '='); break;
  case 47U: queue_byte(shift ? '{' : '['); break;
  case 48U: queue_byte(shift ? '}' : ']'); break;
  case 49U: queue_byte(shift ? '|' : '\\'); break;
  case 51U: queue_byte(shift ? ':' : ';'); break;
  case 52U: queue_byte(shift ? '"' : '\''); break;
  case 53U: queue_byte(shift ? '~' : '`'); break;
  case 54U: queue_byte(shift ? '<' : ','); break;
  case 55U: queue_byte(shift ? '>' : '.'); break;
  case 56U: queue_byte(shift ? '?' : '/'); break;
  case 79U: queue_escape('C'); break;
  case 80U: queue_escape('D'); break;
  case 81U: queue_escape('B'); break;
  case 82U: queue_escape('A'); break;
  default: break;
  }
}
static void process_report(xhci_keyboard_t *keyboard) {
  if (keyboard->report[2] == 1U) return; /* HID rollover error */
  for (uint32_t i = 2U; i < 8U; ++i) {
    uint8_t usage = keyboard->report[i];
    if (usage != 0U && !usage_was_pressed(keyboard->previous_report, usage)) {
      translate_usage(keyboard->report[0], usage);
    }
  }
  for (uint32_t i = 0U; i < 8U; ++i) keyboard->previous_report[i] = keyboard->report[i];
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
static void ring_doorbell(xhci_keyboard_t *keyboard, uint32_t target) {
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
               dma_address(&keyboard->event_ring[keyboard->event_index]) | UINT64_C(0x8));
  /* Acknowledge the consumed event while retaining primary-interrupter enable. */
  mmio_write32(keyboard->runtime + XHCI_IMAN, UINT32_C(3));
  return 1;
}
static int wait_command(xhci_keyboard_t *keyboard, const xhci_trb_t *submitted,
                        uint32_t *slot_id) {
  uint64_t wanted = dma_address(submitted);
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
static int submit_command(xhci_keyboard_t *keyboard, uint32_t type,
                          uint64_t parameter, uint32_t control, uint32_t *slot_id) {
  xhci_trb_t *trb = command_trb(keyboard);
  if (trb == 0) return 0;
  trb->parameter_lo = (uint32_t)parameter;
  trb->parameter_hi = (uint32_t)(parameter >> 32U);
  trb->status = 0U;
  trb->control = (type << XHCI_TRB_TYPE_SHIFT) | control | keyboard->command_cycle;
  ring_doorbell(keyboard, 0U);
  return wait_command(keyboard, trb, slot_id);
}
static void context_write32(uint8_t *context, uint32_t index, uint32_t value) {
  *(uint32_t *)(void *)(context + (uint64_t)index * 4U) = value;
}
static uint32_t context_read32(const uint8_t *context, uint32_t index) {
  return *(const uint32_t *)(const void *)(context + (uint64_t)index * 4U);
}
static int control_transfer(xhci_keyboard_t *keyboard, uint8_t request_type,
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
    uint64_t physical = dma_address(data);
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
  ring_doorbell(keyboard, 1U);
  uint64_t wanted = dma_address(&ring[status_index]);
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
/* Fetch an interface's HID report descriptor and report whether it declares a
   Generic Desktop Keyboard usage (Usage Page 0x01, Usage 0x06). This is what
   separates a keyboard from a pointing device on a composite HID device that
   advertises neither boot subclass nor protocol. */
static int report_descriptor_is_keyboard(xhci_keyboard_t *keyboard,
                                         uint8_t interface_number,
                                         uint16_t report_bytes) {
  uint8_t report[256];
  if (report_bytes == 0U) return 0;
  if (report_bytes > sizeof(report)) report_bytes = sizeof(report);
  zero_bytes(report, sizeof(report));
  if (!control_transfer(keyboard, UINT8_C(0x81), 6U, UINT16_C(0x2200),
                        interface_number, report, report_bytes)) {
    return 0;
  }
  for (uint16_t i = 0U; i + 3U < report_bytes; ++i) {
    if (report[i] == UINT8_C(0x05) && report[i + 1U] == UINT8_C(0x01) &&
        report[i + 2U] == UINT8_C(0x09) && report[i + 3U] == UINT8_C(0x06)) {
      return 1;
    }
  }
  return 0;
}

static int configure_keyboard(xhci_keyboard_t *keyboard, uint32_t port) {
  uint8_t descriptor[256];
  zero_bytes(descriptor, sizeof(descriptor));
  if (!control_transfer(keyboard, UINT8_C(0x80), 6U, UINT16_C(0x0100), 0U,
                        descriptor, 18U)) {
    klog("input: xHCI GET_DEVICE_DESCRIPTOR failed\n");
    return 0;
  }
  uint8_t config_value = 1U;
  if (!control_transfer(keyboard, UINT8_C(0x80), 6U, UINT16_C(0x0200), 0U,
                        descriptor, 9U)) {
    klog("input: xHCI GET_CONFIGURATION_HEADER failed\n");
    return 0;
  }
  uint16_t total = (uint16_t)descriptor[2] | ((uint16_t)descriptor[3] << 8U);
  if (total < 9U || total > sizeof(descriptor)) {
    klog("input: xHCI invalid configuration length=%u\n", total);
    return 0;
  }
  if (!control_transfer(keyboard, UINT8_C(0x80), 6U, UINT16_C(0x0200), 0U,
                        descriptor, total)) {
    klog("input: xHCI GET_CONFIGURATION_DESCRIPTOR failed\n");
    return 0;
  }
  uint8_t interface_number = 0U;
  uint8_t endpoint = 0U;
  uint16_t packet_size = 8U;
  uint8_t interval = 10U;
  /* Two ways to recognise a keyboard. A device that advertises the HID boot
     subclass and keyboard protocol says so outright, and QEMU does. VMware
     Fusion instead exposes a composite HID device whose interfaces are all
     subclass 0 / protocol 0, so the boot descriptors cannot pick the keyboard
     out from the pointing device sharing the same report size. For those,
     fall back to the report descriptor and look for a Generic Desktop
     Keyboard usage, which distinguishes them properly. */
  uint32_t candidate_interface = 0U;
  uint8_t candidate_number = 0U;
  uint8_t candidate_endpoint = 0U;
  uint16_t candidate_packet = 0U;
  uint8_t candidate_interval = 10U;
  uint16_t candidate_report_bytes = 0U;
  uint32_t hid_interface = 0U;
  uint8_t hid_number = 0U;
  uint16_t hid_report_bytes = 0U;
  uint32_t boot_keyboard_interface = 0U;
  for (uint32_t offset = 0U; offset + 2U <= total;) {
    uint8_t length = descriptor[offset];
    if (length < 2U || length > total - offset) return 0;
    if (descriptor[offset + 1U] == 2U) config_value = descriptor[offset + 5U];
    if (descriptor[offset + 1U] == 4U && length >= 9U) {
      boot_keyboard_interface = descriptor[offset + 5U] == 3U &&
                                 descriptor[offset + 6U] == 1U &&
                                 descriptor[offset + 7U] == 1U;
      if (boot_keyboard_interface != 0U) interface_number = descriptor[offset + 2U];
      hid_interface = descriptor[offset + 5U] == 3U;
      hid_number = descriptor[offset + 2U];
      hid_report_bytes = 0U;
    }
    /* HID class descriptor: remember the report descriptor length. */
    if (hid_interface != 0U && descriptor[offset + 1U] == UINT8_C(0x21) &&
        length >= 9U && descriptor[offset + 6U] == UINT8_C(0x22)) {
      hid_report_bytes = (uint16_t)descriptor[offset + 7U] |
                         ((uint16_t)descriptor[offset + 8U] << 8U);
    }
    if (boot_keyboard_interface != 0U && descriptor[offset + 1U] == 5U && length >= 7U &&
        (descriptor[offset + 2U] & UINT8_C(0x80)) != 0U && descriptor[offset + 3U] == 3U) {
      endpoint = descriptor[offset + 2U];
      packet_size = ((uint16_t)descriptor[offset + 4U] |
                     ((uint16_t)descriptor[offset + 5U] << 8U)) & UINT16_C(0x07ff);
      interval = descriptor[offset + 6U];
      break;
    }
    if (hid_interface != 0U && candidate_interface == 0U &&
        descriptor[offset + 1U] == 5U && length >= 7U &&
        (descriptor[offset + 2U] & UINT8_C(0x80)) != 0U &&
        descriptor[offset + 3U] == 3U) {
      uint16_t size = ((uint16_t)descriptor[offset + 4U] |
                       ((uint16_t)descriptor[offset + 5U] << 8U)) &
                      UINT16_C(0x07ff);
      if (size >= 8U && size <= 64U &&
          report_descriptor_is_keyboard(keyboard, hid_number,
                                        hid_report_bytes)) {
        candidate_interface = 1U;
        candidate_number = hid_number;
        candidate_endpoint = descriptor[offset + 2U];
        candidate_packet = size;
        candidate_interval = descriptor[offset + 6U];
        candidate_report_bytes = hid_report_bytes;
      }
    }
    offset += length;
  }
  if (endpoint == 0U && candidate_interface != 0U) {
    interface_number = candidate_number;
    endpoint = candidate_endpoint;
    packet_size = candidate_packet;
    interval = candidate_interval;
    klog("input: xHCI keyboard by report descriptor interface=%u report=%u\n",
         interface_number, candidate_report_bytes);
  }
  if (endpoint == 0U || packet_size == 0U || packet_size > 64U) {
    klog("input: xHCI HID endpoint unavailable endpoint=0x%x packet=%u\n",
         endpoint, packet_size);
    /* Report what the device actually advertises: a controller that enumerates
       but exposes no boot keyboard is a descriptor question, not a bus fault,
       and the descriptor is the only thing that can answer it. */
    for (uint32_t offset = 0U; offset + 2U <= total;) {
      uint8_t length = descriptor[offset];
      if (length < 2U || length > total - offset) break;
      if (descriptor[offset + 1U] == 4U && length >= 9U) {
        klog("input: xHCI interface=%u class=0x%x subclass=0x%x protocol=0x%x "
             "endpoints=%u\n",
             descriptor[offset + 2U], descriptor[offset + 5U],
             descriptor[offset + 6U], descriptor[offset + 7U],
             descriptor[offset + 4U]);
      } else if (descriptor[offset + 1U] == 5U && length >= 7U) {
        klog("input: xHCI endpoint=0x%x attributes=0x%x packet=%u\n",
             descriptor[offset + 2U], descriptor[offset + 3U],
             (uint32_t)(((uint16_t)descriptor[offset + 4U] |
                         ((uint16_t)descriptor[offset + 5U] << 8U)) &
                        UINT16_C(0x07ff)));
      }
      offset += length;
    }
    return 0;
  }
  if (!control_transfer(keyboard, 0U, 9U, config_value, 0U, 0, 0U)) {
    klog("input: xHCI SET_CONFIGURATION failed\n");
    return 0;
  }
  if (!control_transfer(keyboard, UINT8_C(0x21), UINT8_C(0x0b), 0U,
                        interface_number, 0, 0U)) {
    klog("input: xHCI SET_PROTOCOL failed\n");
    return 0;
  }
  keyboard->endpoint_dci = ((uint32_t)(endpoint & UINT8_C(0x0f)) * 2U) + 1U;
  if (keyboard->endpoint_dci >= 32U) return 0;
  zero_bytes(keyboard->input_context, keyboard->context_bytes * 33U);
  context_write32(keyboard->input_context, 1U, UINT32_C(1) | (UINT32_C(1) << keyboard->endpoint_dci));
  uint8_t *slot = keyboard->input_context + keyboard->context_bytes;
  copy_bytes(slot, keyboard->device_context + keyboard->context_bytes,
             keyboard->context_bytes);
  context_write32(slot, 0U, (context_read32(slot, 0U) & ~UINT32_C(0xf8000000)) |
                              (keyboard->endpoint_dci << 27U));
  uint8_t *ep = keyboard->input_context + keyboard->context_bytes * (1U + keyboard->endpoint_dci);
  context_write32(ep, 0U, (uint32_t)interval << 16U);
  context_write32(ep, 1U, (3U << 1U) | (7U << 3U) |
                              ((uint32_t)packet_size << 16U));
  uint64_t ring = dma_address(keyboard->interrupt_ring);
  context_write32(ep, 2U, (uint32_t)ring | XHCI_TRB_CYCLE);
  context_write32(ep, 3U, (uint32_t)(ring >> 32U));
  context_write32(ep, 4U, packet_size);
  if (!submit_command(keyboard, XHCI_TRB_CONFIGURE_ENDPOINT,
                      dma_address(keyboard->input_context), keyboard->slot_id << 24U, 0)) {
    klog("input: xHCI CONFIGURE_ENDPOINT failed\n");
    return 0;
  }
  keyboard->interrupt_ring[XHCI_RING_SIZE - 1U].parameter_lo =
      (uint32_t)dma_address(keyboard->interrupt_ring);
  keyboard->interrupt_ring[XHCI_RING_SIZE - 1U].parameter_hi =
      (uint32_t)(dma_address(keyboard->interrupt_ring) >> 32U);
  keyboard->interrupt_ring[XHCI_RING_SIZE - 1U].control =
      (XHCI_TRB_LINK << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_CYCLE | UINT32_C(1 << 1);
  keyboard->interrupt_ring[0].parameter_lo = (uint32_t)dma_address(keyboard->report);
  keyboard->interrupt_ring[0].parameter_hi =
      (uint32_t)(dma_address(keyboard->report) >> 32U);
  keyboard->interrupt_ring[0].status = 8U;
  keyboard->interrupt_ring[0].control = (XHCI_TRB_NORMAL << XHCI_TRB_TYPE_SHIFT) |
                                         XHCI_TRB_IOC | XHCI_TRB_CYCLE;
  keyboard->transfer_index = 0U;
  keyboard->transfer_cycle = XHCI_TRB_CYCLE;
  (void)port;
  ring_doorbell(keyboard, keyboard->endpoint_dci);
  return 1;
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
  mmio_write64(keyboard->operational + XHCI_DCBAAP, dma_address(keyboard->dcbaa));
  mmio_write64(keyboard->operational + XHCI_CRCR, dma_address(keyboard->command_ring) | XHCI_TRB_CYCLE);
  keyboard->erst->base = dma_address(keyboard->event_ring);
  keyboard->erst->size = XHCI_EVENT_RING_SIZE;
  mmio_write32(keyboard->runtime + XHCI_ERSTSZ, 1U);
  mmio_write64(keyboard->runtime + XHCI_ERSTBA, dma_address(keyboard->erst));
  mmio_write64(keyboard->runtime + XHCI_ERDP, dma_address(keyboard->event_ring));
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
    if (!submit_command(keyboard, XHCI_TRB_ENABLE_SLOT, 0U, 0U, &slot_id) ||
        slot_id == 0U) {
      klog("input: xHCI enable-slot failed port=%u\n", port);
      continue;
    }
    keyboard->slot_id = slot_id;
    zero_bytes(keyboard->input_context, keyboard->context_bytes * 33U);
    context_write32(keyboard->input_context, 1U, 3U);
    uint8_t *slot = keyboard->input_context + keyboard->context_bytes;
    uint32_t speed = (mmio_read32(portsc) >> 10U) & UINT32_C(0xf);
    uint32_t ep0_packet = speed == 2U ? 8U : (speed == 4U ? 512U : 64U);
    context_write32(slot, 0U, (speed << 20U) | (UINT32_C(1) << 27U));
    context_write32(slot, 1U, port << 16U);
    uint8_t *ep0 = keyboard->input_context + keyboard->context_bytes * 2U;
    uint64_t ep0_ring = dma_address(keyboard->ep0_ring);
    /* Each slot's device context starts its control endpoint at the base of
       this ring, so the driver's enqueue position has to start there too.
       Without this reset a second device inherits the previous device's
       position, and every control transfer to it times out waiting for
       completions that reference TRBs the controller already passed. */
    keyboard->ep0_index = 0U;
    zero_bytes(keyboard->ep0_ring, sizeof(xhci_trb_t) * XHCI_RING_SIZE);
    keyboard->ep0_ring[XHCI_RING_SIZE - 1U].parameter_lo = (uint32_t)ep0_ring;
    keyboard->ep0_ring[XHCI_RING_SIZE - 1U].parameter_hi =
        (uint32_t)(ep0_ring >> 32U);
    keyboard->ep0_ring[XHCI_RING_SIZE - 1U].control =
        (XHCI_TRB_LINK << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_CYCLE |
        UINT32_C(1 << 1);
    context_write32(ep0, 1U, (3U << 1U) | (4U << 3U) |
                              (ep0_packet << 16U));
    context_write32(ep0, 2U, (uint32_t)ep0_ring | XHCI_TRB_CYCLE);
    context_write32(ep0, 3U, (uint32_t)(ep0_ring >> 32U));
    context_write32(ep0, 4U, 8U);
    keyboard->dcbaa[slot_id] = dma_address(keyboard->device_context);
    if (!submit_command(keyboard, XHCI_TRB_ADDRESS_DEVICE,
                        dma_address(keyboard->input_context), slot_id << 24U, 0)) {
      klog("input: xHCI address-device failed port=%u slot=%u\n", port, slot_id);
      continue;
    }
    klog("input: xHCI addressed port=%u slot=%u slot_state=0x%x ep0_state=0x%x\n",
         port, slot_id, context_read32(keyboard->device_context, 3U),
         context_read32(keyboard->device_context + keyboard->context_bytes, 0U));
    klog("input: xHCI ep0 deq=0x%x%08x expected=0x%lx\n",
         context_read32(keyboard->device_context + keyboard->context_bytes, 3U),
         context_read32(keyboard->device_context + keyboard->context_bytes, 2U),
         ep0_ring | XHCI_TRB_CYCLE);
    if (configure_keyboard(keyboard, port)) return 1;
    klog("input: xHCI HID configuration failed port=%u slot=%u\n", port, slot_id);
  }
  return 0;
}
static void xhci_poll(void) {
  if (g_keyboard == 0 || g_keyboard->initialized == 0U) return;
  xhci_trb_t event;
  while (next_event(g_keyboard, &event)) {
    uint32_t type = (event.control >> XHCI_TRB_TYPE_SHIFT) & UINT32_C(0x3f);
    if (type != XHCI_TRB_TRANSFER_EVENT) continue;
    uint64_t pointer = ((uint64_t)event.parameter_hi << 32U) | event.parameter_lo;
    if (pointer != dma_address(&g_keyboard->interrupt_ring[g_keyboard->transfer_index])) continue;
    if (((event.status >> 24U) & UINT32_C(0xff)) == XHCI_CC_SUCCESS) process_report(g_keyboard);
    uint32_t next_index = g_keyboard->transfer_index + 1U;
    if (next_index == XHCI_RING_SIZE - 1U) {
      next_index = 0U;
      g_keyboard->transfer_cycle ^= XHCI_TRB_CYCLE;
    }
    g_keyboard->interrupt_ring[next_index].parameter_lo =
        (uint32_t)dma_address(g_keyboard->report);
    g_keyboard->interrupt_ring[next_index].parameter_hi =
        (uint32_t)(dma_address(g_keyboard->report) >> 32U);
    g_keyboard->interrupt_ring[next_index].status = 8U;
    g_keyboard->interrupt_ring[next_index].control =
        (XHCI_TRB_NORMAL << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_IOC |
        g_keyboard->transfer_cycle;
    g_keyboard->transfer_index = next_index;
    ring_doorbell(g_keyboard, g_keyboard->endpoint_dci);
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
int input_read_char(uint8_t *value) {
  if (value == 0) return 0;
  xhci_poll();
  xaios_spin_lock(&g_input_lock);
  if (g_queue_tail == g_queue_head) {
    xaios_spin_unlock(&g_input_lock);
    return 0;
  }
  *value = g_queue[g_queue_tail];
  g_queue_tail = (g_queue_tail + 1U) % INPUT_QUEUE_SIZE;
  xaios_spin_unlock(&g_input_lock);
  return 1;
}
uint32_t input_keyboard_available(void) {
  return g_keyboard != 0 && g_keyboard->initialized != 0U;
}
void input_self_test(void) {
  uint32_t old_head = g_queue_head;
  uint32_t old_tail = g_queue_tail;
  g_queue_head = 0U;
  g_queue_tail = 0U;
  translate_usage(0U, 4U);
  uint8_t value = 0U;
  kassert(input_read_char(&value) == 1 && value == 'a');
  translate_usage(UINT8_C(0x02), 4U);
  kassert(input_read_char(&value) == 1 && value == 'A');
  translate_usage(0U, 82U);
  kassert(input_read_char(&value) == 1 && value == UINT8_C(0x1b));
  kassert(input_read_char(&value) == 1 && value == '[');
  kassert(input_read_char(&value) == 1 && value == 'A');
  g_queue_head = old_head;
  g_queue_tail = old_tail;
  klog("input: keyboard translation self-test passed\n");
}
