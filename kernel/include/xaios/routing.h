#ifndef XAIOS_ROUTING_H
#define XAIOS_ROUTING_H

#include <xaios/status.h>
#include <xaios/types.h>

/* B5: Table size expanded 8→32 */
#define ROUTING_TABLE_SIZE 32U

typedef struct routing_entry {
  uint32_t dest_network; /* network address (host byte order) */
  uint32_t netmask;      /* netmask (host byte order) */
  uint32_t gateway;      /* gateway IP (host order), 0 = direct */
  uint32_t active;
} routing_entry_t;

void routing_init(void);
xaios_status_t routing_add(uint32_t dest_network, uint32_t netmask,
                            uint32_t gateway);

/* Returns next-hop IP in host byte order.
 * For direct routes, returns dest_ip itself.
 * For indirect routes, returns the gateway IP. */
uint32_t routing_lookup(uint32_t dest_ip);

/* B5: Route deletion and clear */
xaios_status_t routing_remove(uint32_t dest_ip_net_order);
void routing_clear(void);

void routing_self_test(void);

#endif
