#ifndef XAIOS_VIRTIO_NET_H
#define XAIOS_VIRTIO_NET_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef struct xaios_net_iovec {
  const void *base;
  uint64_t length;
} xaios_net_iovec_t;

void virtio_net_self_test(void);
xaios_status_t virtio_net_init_persistent(void);
xaios_status_t virtio_net_tx_submit(const uint8_t *data, uint64_t len,
                                    uint64_t *token);
uint32_t virtio_net_tx_poll_completions(void);
xaios_status_t virtio_net_tx(const uint8_t *data, uint64_t len);
xaios_status_t virtio_net_txv(const xaios_net_iovec_t *vectors,
                              uint32_t vector_count);
uint32_t virtio_net_rx_poll(uint8_t *buffer, uint64_t buffer_size);
xaios_status_t virtio_net_get_mac(uint8_t mac[6]);
uint64_t virtio_net_interrupt_count(void);
uint64_t virtio_net_tx_completion_count(void);

#endif
