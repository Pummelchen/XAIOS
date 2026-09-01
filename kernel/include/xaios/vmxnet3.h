#ifndef XAIOS_VMXNET3_H
#define XAIOS_VMXNET3_H

#include <xaios/status.h>
#include <xaios/types.h>

/* VMXNET3, as far as identity.
 *
 * F-02 asks for a capability-gated VMXNET3 path: discovery, queues, DMA,
 * interrupts, recovery and interoperability gates. This header covers the
 * first of those and says so plainly, because a half-built driver that
 * pretends to a full interface is worse than one that does not: something
 * would eventually select it and find it cannot carry a frame.
 *
 * There is deliberately no `vmxnet3_tx` or `vmxnet3_rx_poll` here yet, and
 * `network_device` does not know this file exists. Adding the send and
 * receive paths means the driver-shared memory layout the device parses
 * directly, which has to be exact, and that work stands on this being right
 * first. */
xaios_status_t vmxnet3_probe(void);
xaios_status_t vmxnet3_activate(void);
xaios_status_t vmxnet3_tx(const uint8_t *data, uint64_t length);
uint32_t vmxnet3_rx_poll(uint8_t *buffer, uint64_t capacity);
uint32_t vmxnet3_is_present(void);
xaios_status_t vmxnet3_get_mac(uint8_t mac[6]);
uint32_t vmxnet3_link_up(void);
void vmxnet3_self_test(void);

#endif
