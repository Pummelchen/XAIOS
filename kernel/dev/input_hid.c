/*
 * The xHCI HID keyboard's descriptor and endpoint path. See
 * input_internal.h for how this unit sits beside input.c.
 *
 * Everything here runs once, from initialize_keyboard in input.c, and only
 * for the interface the driver has already chosen. control_transfer,
 * submit_command, ring_doorbell and the context accessors it uses are
 * input.c's, declared in input_internal.h under their module-prefixed names.
 */

#include <xaios/klog.h>

#include "input_internal.h"

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
  input_zero_bytes(report, sizeof(report));
  if (!input_control_transfer(keyboard, UINT8_C(0x81), 6U, UINT16_C(0x2200),
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

int input_configure_keyboard(xhci_keyboard_t *keyboard, uint32_t port) {
  uint8_t descriptor[256];
  input_zero_bytes(descriptor, sizeof(descriptor));
  if (!input_control_transfer(keyboard, UINT8_C(0x80), 6U, UINT16_C(0x0100), 0U,
                              descriptor, 18U)) {
    klog("input: xHCI GET_DEVICE_DESCRIPTOR failed\n");
    return 0;
  }
  uint8_t config_value = 1U;
  if (!input_control_transfer(keyboard, UINT8_C(0x80), 6U, UINT16_C(0x0200), 0U,
                              descriptor, 9U)) {
    klog("input: xHCI GET_CONFIGURATION_HEADER failed\n");
    return 0;
  }
  uint16_t total = (uint16_t)descriptor[2] | ((uint16_t)descriptor[3] << 8U);
  if (total < 9U || total > sizeof(descriptor)) {
    klog("input: xHCI invalid configuration length=%u\n", total);
    return 0;
  }
  if (!input_control_transfer(keyboard, UINT8_C(0x80), 6U, UINT16_C(0x0200), 0U,
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
  if (!input_control_transfer(keyboard, 0U, 9U, config_value, 0U, 0, 0U)) {
    klog("input: xHCI SET_CONFIGURATION failed\n");
    return 0;
  }
  if (!input_control_transfer(keyboard, UINT8_C(0x21), UINT8_C(0x0b), 0U,
                              interface_number, 0, 0U)) {
    klog("input: xHCI SET_PROTOCOL failed\n");
    return 0;
  }
  keyboard->endpoint_dci = ((uint32_t)(endpoint & UINT8_C(0x0f)) * 2U) + 1U;
  if (keyboard->endpoint_dci >= 32U) return 0;
  input_zero_bytes(keyboard->input_context, keyboard->context_bytes * 33U);
  input_context_write32(keyboard->input_context, 1U,
                        UINT32_C(1) | (UINT32_C(1) << keyboard->endpoint_dci));
  uint8_t *slot = keyboard->input_context + keyboard->context_bytes;
  input_copy_bytes(slot, keyboard->device_context + keyboard->context_bytes,
                   keyboard->context_bytes);
  input_context_write32(slot, 0U,
                        (input_context_read32(slot, 0U) & ~UINT32_C(0xf8000000)) |
                            (keyboard->endpoint_dci << 27U));
  uint8_t *ep = keyboard->input_context +
                keyboard->context_bytes * (1U + keyboard->endpoint_dci);
  input_context_write32(ep, 0U, (uint32_t)interval << 16U);
  input_context_write32(ep, 1U, (3U << 1U) | (7U << 3U) |
                                  ((uint32_t)packet_size << 16U));
  uint64_t ring = input_dma_address(keyboard->interrupt_ring);
  input_context_write32(ep, 2U, (uint32_t)ring | XHCI_TRB_CYCLE);
  input_context_write32(ep, 3U, (uint32_t)(ring >> 32U));
  input_context_write32(ep, 4U, packet_size);
  if (!input_submit_command(keyboard, XHCI_TRB_CONFIGURE_ENDPOINT,
                            input_dma_address(keyboard->input_context),
                            keyboard->slot_id << 24U, 0)) {
    klog("input: xHCI CONFIGURE_ENDPOINT failed\n");
    return 0;
  }
  keyboard->interrupt_ring[XHCI_RING_SIZE - 1U].parameter_lo =
      (uint32_t)input_dma_address(keyboard->interrupt_ring);
  keyboard->interrupt_ring[XHCI_RING_SIZE - 1U].parameter_hi =
      (uint32_t)(input_dma_address(keyboard->interrupt_ring) >> 32U);
  keyboard->interrupt_ring[XHCI_RING_SIZE - 1U].control =
      (XHCI_TRB_LINK << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_CYCLE | UINT32_C(1 << 1);
  keyboard->interrupt_ring[0].parameter_lo =
      (uint32_t)input_dma_address(keyboard->report);
  keyboard->interrupt_ring[0].parameter_hi =
      (uint32_t)(input_dma_address(keyboard->report) >> 32U);
  keyboard->interrupt_ring[0].status = 8U;
  keyboard->interrupt_ring[0].control = (XHCI_TRB_NORMAL << XHCI_TRB_TYPE_SHIFT) |
                                         XHCI_TRB_IOC | XHCI_TRB_CYCLE;
  keyboard->transfer_index = 0U;
  keyboard->transfer_cycle = XHCI_TRB_CYCLE;
  (void)port;
  input_ring_doorbell(keyboard, keyboard->endpoint_dci);
  return 1;
}
