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
xaios_status_t network_device_get_mac(uint8_t mac[6]);
xaios_network_device_kind_t network_device_kind(void);
const char *network_device_name(void);

#endif
