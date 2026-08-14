#include <xaios/e1000e.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/virtio_net.h>

static xaios_network_device_kind_t g_network_device_kind;

void network_device_self_test(void) {
  g_network_device_kind = XAIOS_NETWORK_DEVICE_NONE;
  virtio_net_self_test();
  if (virtio_net_is_available() != 0U) {
    g_network_device_kind = XAIOS_NETWORK_DEVICE_VIRTIO;
    klog("network-device: selected virtio-net\n");
    return;
  }

  if (e1000e_init() == XAIOS_OK) {
    g_network_device_kind = XAIOS_NETWORK_DEVICE_E1000E;
    klog("network-device: selected e1000e\n");
    return;
  }

  klog("network-device: no supported persistent NIC\n");
}

xaios_status_t network_device_init_persistent(void) {
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VIRTIO) {
    return virtio_net_init_persistent();
  }
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_E1000E &&
      e1000e_is_ready() != 0U) {
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_device_tx(const uint8_t *data, uint64_t length) {
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VIRTIO) {
    return virtio_net_tx(data, length);
  }
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_E1000E) {
    return e1000e_tx(data, length);
  }
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t network_device_rx_poll(uint8_t *buffer, uint64_t capacity) {
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VIRTIO) {
    return virtio_net_rx_poll(buffer, capacity);
  }
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_E1000E) {
    return e1000e_rx_poll(buffer, capacity);
  }
  return 0U;
}

xaios_status_t network_device_get_mac(uint8_t mac[6]) {
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VIRTIO) {
    return virtio_net_get_mac(mac);
  }
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_E1000E) {
    return e1000e_get_mac(mac);
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_network_device_kind_t network_device_kind(void) {
  return g_network_device_kind;
}

const char *network_device_name(void) {
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VIRTIO) return "virtio-net";
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_E1000E) return "e1000e";
  return "none";
}
