#include <xaios/e1000e.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/timer.h>
#include <xaios/virtio_net.h>
#include <xaios/vmxnet3.h>

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

  /* VMXNET3 last, and only if it activates. E1000E is the qualified path on
     the platform that has both, so this is what a machine falls back to when
     the configuration offers nothing else -- not a preference. */
  if (vmxnet3_activate() == XAIOS_OK) {
    g_network_device_kind = XAIOS_NETWORK_DEVICE_VMXNET3;
    klog("network-device: selected vmxnet3\n");
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
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VMXNET3) {
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
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VMXNET3) {
    return vmxnet3_tx(data, length);
  }
  return XAIOS_ERR_NOT_FOUND;
}

static volatile uint64_t g_network_activity;
static volatile uint32_t g_network_interrupt_driven;

void network_device_note_interrupt(void) {
  __atomic_add_fetch(&g_network_activity, 1U, __ATOMIC_RELAXED);
  timer_wake_signal();
}

uint64_t network_device_activity(void) {
  return __atomic_load_n(&g_network_activity, __ATOMIC_RELAXED);
}

int network_device_interrupt_driven(void) {
  return __atomic_load_n(&g_network_interrupt_driven, __ATOMIC_RELAXED) != 0U;
}

void network_device_set_interrupt_driven(int enabled) {
  __atomic_store_n(&g_network_interrupt_driven, enabled != 0 ? 1U : 0U,
                   __ATOMIC_RELAXED);
}

uint32_t network_device_rx_poll(uint8_t *buffer, uint64_t capacity) {
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VIRTIO) {
    return virtio_net_rx_poll(buffer, capacity);
  }
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_E1000E) {
    return e1000e_rx_poll(buffer, capacity);
  }
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VMXNET3) {
    return vmxnet3_rx_poll(buffer, capacity);
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
  if (g_network_device_kind == XAIOS_NETWORK_DEVICE_VMXNET3) {
    return vmxnet3_get_mac(mac);
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
