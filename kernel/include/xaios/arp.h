#ifndef XAIOS_ARP_H
#define XAIOS_ARP_H

#include <xaios/status.h>
#include <xaios/types.h>

/* B3-B4: Cache size increased 4→32, with LRU aging */
#define XAIOS_ARP_CACHE_SIZE 32U
#define XAIOS_ARP_TIMEOUT_SEC 300
#define XAIOS_ARP_ETHERNET 0x0001U
#define XAIOS_ARP_IPV4 0x0800U
#define XAIOS_ARP_OP_REQUEST 1U
#define XAIOS_ARP_OP_REPLY 2U

typedef struct xaios_arp_entry {
  uint32_t ip;
  uint8_t mac[6];
  uint32_t active;
  uint64_t age_ns;       /* timestamp of last update */
  uint64_t last_use_ns;  /* LRU: timestamp of last lookup */
} xaios_arp_entry_t;

void arp_init(void);
xaios_status_t arp_cache_lookup(uint32_t ip, uint8_t mac[6]);
xaios_status_t arp_cache_insert(uint32_t ip, const uint8_t mac[6]);
xaios_status_t arp_build_request(uint8_t *frame, uint64_t *frame_len,
                                 const uint8_t src_mac[6], uint32_t src_ip,
                                 uint32_t target_ip);
xaios_status_t arp_process_reply(const uint8_t *frame, uint64_t frame_len);
xaios_status_t arp_build_reply(uint8_t *frame, uint64_t *frame_len,
                               const uint8_t src_mac[6], uint32_t src_ip,
                               const uint8_t dst_mac[6], uint32_t dst_ip);
uint64_t arp_cache_count(void);
xaios_status_t arp_cache_snapshot(uint32_t index, xaios_arp_entry_t *entry);

/* B3-B4: Cache aging and gratuitous ARP */
void arp_cache_age(void);
xaios_status_t arp_send_gratuitous(const uint8_t local_mac[6], uint32_t local_ip);

void arp_self_test(void);

#endif
