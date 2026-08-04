#ifndef XAIOS_NDP_H
#define XAIOS_NDP_H

#include <xaios/ip_addr.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* C4: Cache expanded from 8 to 32 */
#define XAIOS_NDP_CACHE_SIZE 32U

/* ---- C3: NUD (Neighbor Unreachability Detection) ---- */
/* RFC 4861 Section 7.3 states */
#define XAIOS_NDP_REACHABLE_TIME_NS UINT64_C(30000000000)  /* 30 seconds */
#define XAIOS_NDP_DELAY_FIRST_PROBE_NS UINT64_C(5000000000)  /* 5 seconds */
#define XAIOS_NDP_RETRANS_TIMER_NS UINT64_C(1000000000)    /* 1 second */
#define XAIOS_NDP_MAX_PROBES 3U

/* NUD states as per RFC 4861 Section 7.3.2 */
typedef enum {
  XAIOS_NDP_NUD_INCOMPLETE = 0,
  XAIOS_NDP_NUD_REACHABLE = 1,
  XAIOS_NDP_NUD_STALE = 2,
  XAIOS_NDP_NUD_DELAY = 3,
  XAIOS_NDP_NUD_PROBE = 4,
} xaios_ndp_nud_state_t;

/* NDP cache entry with NUD state and timestamps */
typedef struct xaios_ndp_entry {
  xaios_ip_addr_t ip;
  uint8_t mac[6];
  uint32_t active;
  uint8_t nud_state;         /* NUD state */
  uint64_t nud_timestamp_ns; /* when NUD state was entered */
  uint64_t last_used_ns;     /* LRU timestamp */
  uint64_t insert_ns;        /* insertion time for aging */
  uint32_t probe_count;      /* number of probes sent in PROBE state */
} xaios_ndp_entry_t;

/* ---- C6: DAD (Duplicate Address Detection) ---- */
typedef struct {
  xaios_ip_addr_t tentative_addr;
  uint64_t start_ns;
  int active;
  int duplicate_found;
} xaios_dad_state_t;

/* ---- C7: Router Discovery ---- */
/* Default gateway stored from RA processing */
extern xaios_ip_addr_t ndp_default_gateway;

/* ---- Public NDP API ---- */
void ndp_init(void);
xaios_status_t ndp_cache_lookup(const xaios_ip_addr_t *ip, uint8_t mac[6]);
xaios_status_t ndp_cache_insert(const xaios_ip_addr_t *ip, const uint8_t mac[6]);

xaios_status_t ndp_build_neighbor_solicitation(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6],
    const xaios_ip_addr_t *src_ip,
    const xaios_ip_addr_t *target_ip);

xaios_status_t ndp_process_neighbor_solicitation(
    const uint8_t *frame, uint64_t frame_len);

xaios_status_t ndp_process_neighbor_advertisement(
    const uint8_t *frame, uint64_t frame_len);

/* ---- NUD ---- */
/* Called periodically (e.g. every 100ms or 1s timer tick) */
void ndp_nud_tick(uint64_t now_ns);
/* Called when sending traffic to a neighbor */
void ndp_nud_update_on_traffic(const xaios_ip_addr_t *target);
/* Check entry age, transition REACHABLE -> STALE after timeout */
void ndp_cache_age(uint64_t now_ns);

/* ---- DAD ---- */
void ndp_dad_init(xaios_dad_state_t *dad, const xaios_ip_addr_t *addr);
/* Returns: 1 = unique (no duplicate found), 0 = still probing, -1 = duplicate detected */
int ndp_dad_tick(xaios_dad_state_t *dad, uint64_t now_ns);

/* ---- Router Discovery ---- */
xaios_status_t ndp_send_router_solicitation(const uint8_t src_mac[6],
                                              const xaios_ip_addr_t *src_ip);
/* Process Router Advertisement (ICMPv6 type 134) */
xaios_status_t ndp_process_router_advertisement(const uint8_t *frame,
                                                 uint64_t frame_len);

uint64_t ndp_cache_count(void);
void ndp_self_test(void);

#endif /* XAIOS_NDP_H */
