/* Private interface of the DHCPv6 client, shared by the translation units it
   is split across:

     dhcpv6.c         the client state machine: the SOLICIT, ADVERTISE,
                      REQUEST, REPLY exchange, its retry policy and its
                      deadlines, driving the codec below;
     dhcpv6_codec.c   the message codec -- options, DUID and IA_NA encoding,
                      reply parsing -- the client identity both halves consult,
                      and the deterministic self-test that drives every path of
                      it without a network.

   This is not a public interface; xaios/dhcpv6.h is, and both files include
   it. Every symbol below is defined once, in the file named beside it. The
   frame layout constants live here rather than in either file so the encoder
   and the exchange cannot drift apart on what a message costs. */
#ifndef XAIOS_DHCPV6_INTERNAL_H
#define XAIOS_DHCPV6_INTERNAL_H

#include <xaios/dhcpv6.h>
#include <xaios/ip_addr.h>

#define DHCPV6_CLIENT_PORT UINT16_C(546)
#define DHCPV6_SERVER_PORT UINT16_C(547)

#define DHCPV6_SOLICIT UINT8_C(1)
#define DHCPV6_ADVERTISE UINT8_C(2)
#define DHCPV6_REQUEST UINT8_C(3)
#define DHCPV6_REPLY UINT8_C(7)

#define DHCPV6_OPT_CLIENTID UINT16_C(1)
#define DHCPV6_OPT_SERVERID UINT16_C(2)
#define DHCPV6_OPT_IA_NA UINT16_C(3)
#define DHCPV6_OPT_IAADDR UINT16_C(5)
#define DHCPV6_OPT_ORO UINT16_C(6)
#define DHCPV6_OPT_ELAPSED_TIME UINT16_C(8)
#define DHCPV6_OPT_STATUS_CODE UINT16_C(13)
#define DHCPV6_OPT_RAPID_COMMIT UINT16_C(14)
#define DHCPV6_OPT_DNS_SERVERS UINT16_C(23)

#define DHCPV6_DUID_LL UINT16_C(3)
#define DHCPV6_HWTYPE_ETHERNET UINT16_C(1)

#define DHCPV6_STATUS_SUCCESS UINT16_C(0)

#define DHCPV6_ETHERNET_BYTES 14U
#define DHCPV6_IPV6_BYTES 40U
#define DHCPV6_UDP_BYTES 8U
#define DHCPV6_HEADER_BYTES (DHCPV6_ETHERNET_BYTES + DHCPV6_IPV6_BYTES + \
                             DHCPV6_UDP_BYTES)
#define DHCPV6_FRAME_CAPACITY 512U
#define DHCPV6_RX_CAPACITY 2048U

/* A server identifier is opaque and variable length; RFC 8415 caps a DUID at
   128 octets, and one longer than that is malformed rather than interesting. */
#define DHCPV6_MAX_DUID 128U

#define DHCPV6_RETRY_INTERVAL_NS UINT64_C(1000000000)
#define DHCPV6_RETRY_MAX_INTERVAL_NS UINT64_C(4000000000)

/* What one reply carried, after the codec has walked it. Defined in
   dhcpv6_codec.c and filled in there; read by the exchange in dhcpv6.c. */
typedef struct dhcpv6_response {
  uint8_t message_type;
  uint8_t server_duid[DHCPV6_MAX_DUID];
  uint32_t server_duid_len;
  xaios_ip_addr_t address;
  xaios_ip_addr_t dns;
  uint32_t preferred_lifetime_s;
  uint32_t valid_lifetime_s;
  uint32_t have_address;
  uint32_t have_dns;
  uint16_t status;
} dhcpv6_response_t;

/* Byte-order and block helpers. Defined in dhcpv6_codec.c; used by both files,
   so they exist once rather than drifting as two copies. */
void dhcpv6_zero_bytes(uint8_t *out, uint32_t length);
void dhcpv6_copy_bytes(uint8_t *out, const uint8_t *in, uint32_t length);

/* Client identity. Defined in dhcpv6_codec.c, called by dhcpv6_acquire()
   before the first exchange; the codec's parser compares against them. */
void dhcpv6_build_client_duid(const uint8_t mac[6]);
void dhcpv6_new_transaction_id(void);

/* Message codec. Defined in dhcpv6_codec.c. */
uint32_t dhcpv6_build_message(uint8_t frame[DHCPV6_FRAME_CAPACITY],
                              uint8_t message_type, const uint8_t mac[6],
                              const uint8_t *server_duid,
                              uint32_t server_duid_len,
                              const xaios_ip_addr_t *requested,
                              uint64_t elapsed_ns);
int dhcpv6_parse_response(const uint8_t *frame, uint32_t length,
                          const uint8_t mac[6], dhcpv6_response_t *response);

#endif /* XAIOS_DHCPV6_INTERNAL_H */
