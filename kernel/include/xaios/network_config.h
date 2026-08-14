#ifndef XAIOS_NETWORK_CONFIG_H
#define XAIOS_NETWORK_CONFIG_H

#include <xaios/status.h>
#include <xaios/types.h>

/* Addresses are stored in network byte order. */
void network_config_reset_defaults(void);
xaios_status_t network_config_dhcp(uint64_t timeout_ns);
uint32_t network_config_local_ipv4(void);
uint32_t network_config_gateway_ipv4(void);
uint32_t network_config_netmask(void);
uint32_t network_config_dns_server(void);
void network_config_gateway_mac(uint8_t mac[6]);
uint32_t network_config_is_dynamic(void);

#endif
