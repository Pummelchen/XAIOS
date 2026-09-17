/* The interface the xHCI HID keyboard driver's translation units share after
 * the split.
 *
 * input_queue.c owns the console byte queue, its lock, the HID usage-to-byte
 * keymap and the public entry points that drain the queue; input_hid.c owns
 * HID report-descriptor parsing and the keyboard interface's endpoint
 * programming; input.c keeps the controller bring-up, the command, event and
 * transfer rings, the poll that feeds the keymap, and the public entry points
 * that name the controller. The controller's register offsets, ring geometry
 * and device structure are declared here once because more than one unit
 * names them; the input_-prefixed helpers below are each defined once in
 * input.c and cross to input_hid.c, so nothing here is a second definition of
 * anything.
 */
#ifndef XAIOS_KERNEL_DEV_INPUT_INTERNAL_H
#define XAIOS_KERNEL_DEV_INPUT_INTERNAL_H

#include <xaios/types.h>

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

/* Defined in input_queue.c: translate one HID boot report into queued console
   bytes. `report' is the 8-byte boot-protocol report and `previous' the last
   one accepted, which the call updates. It walks the report exactly as the
   driver's poll did before the split. */
void input_process_report(const uint8_t report[8], uint8_t previous[8]);

/* Defined in input.c: drain the controller's event and transfer rings and hand
   any completed report to input_process_report. input_read_char and
   input_pending call it before they look at the queue. */
void input_poll(void);

/* Defined in input.c and shared with input_hid.c. Each is the same function
   the driver used before the split, carrying the module prefix because it now
   crosses a translation-unit boundary. */
void input_zero_bytes(void *buffer, uint64_t bytes);
void input_copy_bytes(void *destination, const void *source, uint64_t bytes);
uint64_t input_dma_address(const void *pointer);
int input_submit_command(xhci_keyboard_t *keyboard, uint32_t type,
                         uint64_t parameter, uint32_t control, uint32_t *slot_id);
void input_ring_doorbell(xhci_keyboard_t *keyboard, uint32_t target);
void input_context_write32(uint8_t *context, uint32_t index, uint32_t value);
uint32_t input_context_read32(const uint8_t *context, uint32_t index);
int input_control_transfer(xhci_keyboard_t *keyboard, uint8_t request_type,
                           uint8_t request, uint16_t value, uint16_t index,
                           void *data, uint16_t length);

/* Defined in input_hid.c: read the configuration descriptor, choose the HID
   keyboard interface and program its interrupt endpoint. initialize_keyboard,
   in input.c, is the only caller. */
int input_configure_keyboard(xhci_keyboard_t *keyboard, uint32_t port);

#endif /* XAIOS_KERNEL_DEV_INPUT_INTERNAL_H */
