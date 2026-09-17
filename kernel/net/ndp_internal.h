/* Private interfaces of NDP, shared by the three translation units it is
   split across:

     ndp.c         the deterministic self-test, which drives every path
                   below and inspects the cache and DAD state directly;
     ndp_cache.c   the neighbour cache, its LRU eviction and expiry, the
                   NUD state machine, and the byte-order helpers all three
                   files use;
     ndp_proto.c   the ICMPv6 wire handling: neighbour solicitation and
                   advertisement, duplicate address detection, and router
                   solicitation and advertisement.

   This is not a public interface; xaios/ndp.h is, and all three include it.
   The cache and the router/DAD state are declared here rather than reached
   through accessors because the self-test builds and inspects exactly the
   state the protocol code advances, and a copied interface could drift from
   it. Every symbol below is defined once, in the file named beside it. */
#ifndef XAIOS_NDP_INTERNAL_H
#define XAIOS_NDP_INTERNAL_H

#include <xaios/ndp.h>

/* Neighbour cache and the shared byte-order helpers. Defined in ndp_cache.c;
   used by ndp.c and ndp_proto.c. */
extern xaios_ndp_entry_t g_ndp_cache[XAIOS_NDP_CACHE_SIZE];
extern uint64_t g_ndp_last_tick_ns;
void ndp_bytes_zero(void *buffer, uint64_t size);
void ndp_put_be16(uint8_t *dst, uint16_t value);
uint16_t ndp_get_be16(const uint8_t *src);
void ndp_put_be32(uint8_t *dst, uint32_t value);

/* Router and duplicate-address state, and the wire check the self-test
   exercises. Defined in ndp_proto.c; used by ndp.c (and by ndp_cache.c's
   ndp_init, which returns them to their power-on values). */
extern int g_ndp_has_default_gateway;
extern xaios_dad_state_t g_ndp_dad_state;
extern int g_ndp_dad_active;
int ndp_hop_limit_is_valid(const uint8_t *frame);
xaios_status_t ndp_build_router_solicitation(uint8_t *rs_frame,
                                             uint64_t capacity,
                                             uint64_t *out_len,
                                             const uint8_t src_mac[6],
                                             const xaios_ip_addr_t *src_ip);

#endif /* XAIOS_NDP_INTERNAL_H */
