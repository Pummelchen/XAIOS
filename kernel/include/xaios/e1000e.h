#ifndef XAIOS_E1000E_H
#define XAIOS_E1000E_H

#include <xaios/status.h>
#include <xaios/types.h>

xaios_status_t e1000e_init(void);
xaios_status_t e1000e_tx(const uint8_t *data, uint64_t length);
uint32_t e1000e_rx_poll(uint8_t *buffer, uint64_t capacity);
xaios_status_t e1000e_get_mac(uint8_t mac[6]);
uint32_t e1000e_is_ready(void);

#endif
