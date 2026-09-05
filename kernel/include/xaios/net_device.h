#ifndef XAIOS_NET_DEVICE_H
#define XAIOS_NET_DEVICE_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef enum xaios_network_device_kind {
  XAIOS_NETWORK_DEVICE_NONE = 0,
  XAIOS_NETWORK_DEVICE_VIRTIO = 1,
  XAIOS_NETWORK_DEVICE_E1000E = 2,
  XAIOS_NETWORK_DEVICE_VMXNET3 = 3,
} xaios_network_device_kind_t;

void network_device_self_test(void);
xaios_status_t network_device_init_persistent(void);
xaios_status_t network_device_tx(const uint8_t *data, uint64_t length);
uint32_t network_device_rx_poll(uint8_t *buffer, uint64_t capacity);
/* A NIC interrupt says the link has something to say. The stack is not run
   from the interrupt -- it takes a lock a thread on the same CPU may hold --
   so this counts the event and wakes whoever is sleeping, and that thread
   drains the ring. */
void network_device_note_interrupt(void);
uint64_t network_device_activity(void);
/* Whether the selected device raises interrupts at all. One that does not
   has to be polled at the receive cadence or its ring fills and the link
   drops what arrives; e1000e and vmxnet3 are in that position today. */
int network_device_interrupt_driven(void);
void network_device_set_interrupt_driven(int enabled);
xaios_status_t network_device_get_mac(uint8_t mac[6]);
xaios_network_device_kind_t network_device_kind(void);
const char *network_device_name(void);

#endif
