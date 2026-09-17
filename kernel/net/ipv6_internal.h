/* Private interface of IPv6, shared by the two translation units it is split
   across:

     ipv6.c       the fixed header's build and parse, the pseudo-header
                  checksum, the link-local address derivation, the byte-order
                  helpers both files use, and the deterministic self-test,
                  which drives every path below;
     ipv6_ext.c   the extension-header chain walk and the fragmentation and
                  reassembly state machine, including the fragment buckets
                  the self-test fills out of order.

   This is not a public interface; xaios/ipv6.h is, and both files include it.
   The byte-order helpers live in one place rather than being duplicated,
   because a second copy could drift from the one the self-test checks.
   Every symbol below is defined once, in the file named beside it. */
#ifndef XAIOS_IPV6_INTERNAL_H
#define XAIOS_IPV6_INTERNAL_H

#include <xaios/ipv6.h>

/* Byte-order and block-copy helpers. Defined in ipv6.c; used by ipv6.c and
   ipv6_ext.c. */
void ipv6_put_be16(uint8_t *dst, uint16_t value);
void ipv6_put_be32(uint8_t *dst, uint32_t value);
uint16_t ipv6_get_be16(const uint8_t *src);
uint32_t ipv6_get_be32(const uint8_t *src);
void ipv6_bytes_copy(void *dst, const void *src, uint64_t size);
void ipv6_bytes_zero(void *dst, uint64_t size);

#endif /* XAIOS_IPV6_INTERNAL_H */
