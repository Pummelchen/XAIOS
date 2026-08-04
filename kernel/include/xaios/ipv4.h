#ifndef XAIOS_IPV4_H
#define XAIOS_IPV4_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_IPV4_PROTO_ICMP 1U
#define XAIOS_IPV4_PROTO_TCP 6U
#define XAIOS_IPV4_PROTO_UDP 17U
#define XAIOS_IPV4_HEADER_SIZE 20U
#define XAIOS_IPV4_VERSION_IHL 0x45U

/* Static IP configuration for QEMU SLIRP */
#define XAIOS_IPV4_GUEST_IP  0x0a00020fU /* 10.0.2.15 */
#define XAIOS_IPV4_GATEWAY   0x0a000202U /* 10.0.2.2 */
#define XAIOS_IPV4_NETMASK   0xffffff00U /* 255.255.255.0 */

/* B1: IP fragmentation/reassembly */
#define XAIOS_IPV4_FRAG_TIMEOUT_NS UINT64_C(30000000000)
#define XAIOS_IPV4_MAX_REASSEMBLED_PAYLOAD 1480U

/* IP flag bits */
#define XAIOS_IPV4_FLAG_MF    0x2000U  /* more fragments */
#define XAIOS_IPV4_FLAG_DF    0x4000U  /* don't fragment */
#define XAIOS_IPV4_OFFSET_MASK 0x1FFFU /* fragment offset (in 8-byte units) */

/* Fragment buffer for reassembly tracking */
typedef struct ipv4_frag_bucket {
  uint32_t active;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t id;
  uint8_t protocol;
  uint8_t have_first;
  uint64_t first_arrival_ns;
  uint32_t total_len;
  uint32_t received_count;
  uint8_t ethernet_header[14];
  uint8_t ip_header[XAIOS_IPV4_HEADER_SIZE];
  uint8_t payload[XAIOS_IPV4_MAX_REASSEMBLED_PAYLOAD];
  uint8_t received[XAIOS_IPV4_MAX_REASSEMBLED_PAYLOAD];
} ipv4_frag_bucket_t;

void ipv4_build_header(uint8_t *hdr, uint16_t total_length, uint8_t protocol,
                       uint32_t src_ip, uint32_t dst_ip);
uint16_t ipv4_checksum(const uint8_t *data, uint32_t length);
uint16_t ipv4_pseudo_checksum(uint32_t src_ip, uint32_t dst_ip,
                               uint8_t protocol, uint16_t payload_length,
                               const uint8_t *payload, uint32_t payload_len);
int ipv4_validate_incoming(const uint8_t *frame, uint64_t frame_len);

/* B1: fragmentation/reassembly */
xaios_status_t ipv4_fragment(const uint8_t *frame, uint64_t frame_len,
                              uint8_t *out_buf, uint64_t *out_len,
                              uint64_t out_capacity);
int ipv4_is_fragment(const uint8_t *frame, uint64_t frame_len);
xaios_status_t ipv4_reassemble(uint8_t *frame, uint64_t *frame_len);
void ipv4_frag_self_test(void);
void ipv4_self_test(void);

/* Fragment reassembly init */
void ipv4_frag_init(void);

#endif
