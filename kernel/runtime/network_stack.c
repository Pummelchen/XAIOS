#include <xaios/arp.h>
#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/ntp.h>
#include <xaios/operations.h>
#include <xaios/network_stack.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/routing.h>
#include <xaios/socket_buffer.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>

/* Janeway — “Break off your pursuit or we'll open fire.” */

#define NETWORK_ETHERTYPE_IPV4 UINT16_C(0x0800)
#define NETWORK_ETHERTYPE_IPV6 UINT16_C(0x86DD)
#define NETWORK_IP_PROTO_UDP UINT8_C(17)
#define NETWORK_IP_PROTO_TCP UINT8_C(6)

#define NETWORK_BUFFER_SIZE 1520U
/* Twice the receive ring depth, so one poll can clear a full ring and the
   refills that land while it works. */
#define NETWORK_POLL_RX_BUDGET 16U
#define NETWORK_MAX_SAMPLES 64U

#define NETWORK_TCP_CONNECTIONS 128U
#define NETWORK_UDP_FLOWS 32U
#define NETWORK_PACKET_DESCRIPTORS 32U
#define NETWORK_QUEUE_RING_SIZE 8U
#define NETWORK_UDP_IDLE_TIMEOUT_NS UINT64_C(30000000000)
#define NETWORK_TCP_RETRANSMIT_NS UINT64_C(1000000000)
#define NETWORK_TCP_SYN_TIMEOUT_NS UINT64_C(10000000000)
#define NETWORK_TCP_MAX_RETRANSMITS 5U

#define NETWORK_TCP_FLAG_FIN 0x01U
#define NETWORK_TCP_FLAG_SYN 0x02U
#define NETWORK_TCP_FLAG_RST 0x04U
#define NETWORK_TCP_FLAG_PSH 0x08U
#define NETWORK_TCP_FLAG_ACK 0x10U

/* TCP options kind bytes */
#define TCP_OPT_END       0U
#define TCP_OPT_NOP       1U
#define TCP_OPT_MSS       2U
#define TCP_OPT_WSCALE    3U
#define TCP_OPT_SACK_PERMITTED 4U
#define TCP_OPT_SACK      5U

#define NETWORK_TCP_MSS 1400U
#define NETWORK_TCP_IPV6_MSS 1200U
#define NETWORK_TCP_IPV4_RX_MAX 1460U
#define NETWORK_TCP_IPV6_RX_MAX 1440U
#define NETWORK_TCP_WSCALE_OK 1U
#define TCP_OOO_BUF_ENTRIES 4U
#define TCP_TX_WINDOW_SEGMENTS 8U

/* Congestion control constants */
#define TCP_INIT_CWND     1U
#define TCP_INIT_SSTHRESH 16U
#define TCP_MAX_DUP_ACK   3U

/* Keepalive defaults (in seconds, converted to ns elsewhere) */
#define TCP_KEEPALIVE_IDLE_NS     UINT64_C(7200000000000)  /* 2 hours */
#define TCP_KEEPALIVE_INTERVAL_NS UINT64_C(10000000000)    /* 10 seconds */
#define TCP_KEEPALIVE_PROBES     3U

typedef struct network_queue_binding {
  uint32_t queue_id;
  uint32_t cell_id;
  uint32_t core_mask;
  uint32_t in_use;
} network_queue_binding_t;

typedef struct network_queue_ring {
  uint32_t queue_id;
  uint32_t rx_depth;
  uint32_t tx_depth;
  uint64_t completed;
  uint64_t drops;
} network_queue_ring_t;

typedef enum network_packet_state {
  NETWORK_PACKET_FREE = 0,
  NETWORK_PACKET_RX_OWNED = 1,
  NETWORK_PACKET_TX_QUEUED = 2,
  NETWORK_PACKET_COMPLETE = 3,
  NETWORK_PACKET_DROPPED = 4,
} network_packet_state_t;

typedef struct network_packet_desc {
  network_packet_state_t state;
  uint32_t queue_id;
  uint32_t cell_id;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t src_address;
  uint32_t dst_address;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  uint64_t length;
  uint64_t created_ns;
} network_packet_desc_t;

typedef struct network_udp_flow {
  uint8_t active;
  uint32_t flow_id;
  uint32_t queue_id;
  uint32_t cell_id;
  uint16_t local_port;
  uint16_t remote_port;
  uint32_t local_address;
  uint32_t remote_address;
  xaios_ip_addr_t local_addr;
  xaios_ip_addr_t remote_addr;
  uint64_t packets_rx;
  uint64_t packets_tx;
  uint64_t last_seen_ns;
  uint8_t remote_mac[6];
  uint8_t remote_mac_valid;
  /* Data plane */
  socket_buffer_t *rx_buf;
} network_udp_flow_t;

typedef struct network_tcp_flow {
  xaios_network_flow_state_t state;
  uint32_t flow_id;
  uint32_t queue_id;
  uint32_t cell_id;
  uint16_t local_port;
  uint16_t remote_port;
  uint32_t remote_address;
  uint32_t local_address;
  xaios_ip_addr_t remote_addr;
  xaios_ip_addr_t local_addr;
  uint32_t remote_seq;
  uint32_t local_seq;
  uint64_t last_seen_ns;
  uint32_t retransmits;
  uint64_t packets_rx;
  uint64_t packets_tx;
  /* Data plane fields */
  socket_buffer_t *rx_buf;
  socket_buffer_t *tx_buf;
  uint32_t expected_seq;      /* next expected seq from peer */
  uint32_t next_send_seq;     /* next seq we send */
  uint16_t window_size;        /* advertised receive window */
  uint8_t  pending_synack;     /* SYN-ACK needs to be sent */
  uint8_t  pending_syn;        /* active-open SYN needs to be sent */
  uint8_t  pending_fin;        /* FIN needs to be sent */
  uint8_t  pending_ack;        /* ACK needs to be sent */
  uint8_t  close_requested;    /* local side called close */
  uint8_t  remote_mac[6];      /* cached peer MAC */
  uint8_t  remote_mac_valid;
  /* TCP retransmission state. */
  uint64_t rto_ns;             /* current retransmission timeout */
  uint8_t  in_retransmit;      /* currently in retransmission */
  /* Bounded out-of-order data buffering. */
  struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  in_use;
    uint8_t  data[NETWORK_TCP_IPV4_RX_MAX];
  } ooo_buf[TCP_OOO_BUF_ENTRIES];
  /* TCP MSS negotiation. */
  uint16_t peer_mss;           /* received from peer */
  uint8_t  mss_parsed;         /* we parsed peer MSS */
  /* TCP window scaling. */
  uint8_t  ws_parsed;          /* peer sent window scale */
  uint8_t  peer_sack_permitted;
  uint8_t  peer_ws;            /* peer's window scale factor */
  uint8_t  our_ws;             /* our window scale factor */
  uint32_t peer_window;        /* latest scaled peer receive window */
  /* TCP congestion control. */
  uint32_t cwnd;               /* congestion window (bytes) */
  uint32_t ssthresh;           /* slow start threshold (bytes) */
  uint32_t dup_ack_count;      /* duplicate ACK counter */
  uint32_t highest_acked;      /* highest seq acked by peer */
  uint32_t in_flight;          /* bytes sent but not yet acked */
  uint8_t zero_window_probe;
  struct {
    uint32_t seq;
    uint16_t len;
    uint8_t in_use;
    uint8_t pending;
    uint8_t retransmitted;
    uint8_t retries;
    uint64_t first_tx_ns;
    uint64_t last_tx_ns;
    uint8_t data[NETWORK_TCP_MSS];
  } tx_segments[TCP_TX_WINDOW_SEGMENTS];
  uint64_t srtt_ns;
  uint64_t rttvar_ns;
  /* TCP keepalive. */
  uint64_t keepalive_last_rx_ns;
  uint64_t keepalive_last_tx_ns;
  uint32_t keepalive_probes_sent;
  uint8_t pending_keepalive;
  /* Reliable close handshake. */
  uint32_t fin_seq;
  uint32_t peer_fin_seq;
  uint64_t fin_last_tx_ns;
  uint32_t fin_retries;
  uint8_t fin_outstanding;
  uint8_t peer_fin_pending;
  uint8_t peer_fin_received;
} network_tcp_flow_t;

typedef struct tcp_parsed_options {
  uint16_t mss;
  uint8_t window_scale;
  uint8_t sack_permitted;
  uint8_t sack_count;
  uint32_t sack_left[TCP_OOO_BUF_ENTRIES];
  uint32_t sack_right[TCP_OOO_BUF_ENTRIES];
} tcp_parsed_options_t;

typedef struct network_ip4_header {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fragment_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t source;
  uint32_t destination;
} network_ip4_header_t;

typedef struct network_ip6_header {
  uint8_t  version_tc_flow[4];
  uint16_t payload_length;
  uint8_t  next_header;
  uint8_t  hop_limit;
  uint8_t  source[16];
  uint8_t  destination[16];
} network_ip6_header_t;

typedef struct network_udp_header {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
} network_udp_header_t;

typedef struct network_tcp_header {
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset_reserved;
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
} network_tcp_header_t;

static network_queue_binding_t g_queue_bindings[XAIOS_NETWORK_MAX_QUEUE_BINDINGS];
static network_queue_ring_t g_queue_rings[XAIOS_NETWORK_MAX_QUEUE_BINDINGS];
static uint64_t g_next_flow_id = 1U;
static network_packet_desc_t g_packet_descs[NETWORK_PACKET_DESCRIPTORS];
static network_udp_flow_t g_udp_flows[NETWORK_UDP_FLOWS];
static network_tcp_flow_t g_tcp_flows[NETWORK_TCP_CONNECTIONS];

/* VirtIO RX/TX and the TCP table are shared by service and child CPUs. */

/* C-01. This stack was written when one CPU ran the whole kernel, so its flow
   and listener tables carry roughly a hundred and seventy field writes and
   almost no serialisation. That held while secondaries never came online. Now
   a syscall runs on whichever CPU the calling thread occupies, so two threads
   in one process can be inside these tables at the same time.
   
   A plain spinlock at each entry point would deadlock: ten of the exported
   functions call other exported ones -- external_session calls
   app_tcp_connect, tcp_close_flow calls tcp_abort_flow, and so on. So the
   guard counts depth per CPU. The first acquisition on a CPU takes the lock
   and nested ones only count, which leaves every internal call site and every
   table write exactly as it was.
   
   Reading owner and depth outside the lock is safe in the only direction that
   matters: a CPU can conclude it does *not* already hold the guard and fall
   through to the real lock, which blocks correctly. It cannot wrongly conclude
   that it does, because a CPU only ever writes its own id there while holding
   the lock, and clears it before releasing. */
static xaios_spinlock_t g_network_lock = XAIOS_SPINLOCK_INIT;
static uint32_t g_network_lock_owner = UINT32_MAX;
static uint32_t g_network_lock_depth;

static void network_lock(void) {
  uint32_t cpu = smp_cpu_id();
  if (__atomic_load_n(&g_network_lock_depth, __ATOMIC_ACQUIRE) != 0U &&
      __atomic_load_n(&g_network_lock_owner, __ATOMIC_ACQUIRE) == cpu) {
    ++g_network_lock_depth;
    return;
  }
  xaios_spin_lock(&g_network_lock);
  __atomic_store_n(&g_network_lock_owner, cpu, __ATOMIC_RELEASE);
  __atomic_store_n(&g_network_lock_depth, 1U, __ATOMIC_RELEASE);
}

static void network_unlock(void) {
  if (g_network_lock_depth == 0U) return;
  if (--g_network_lock_depth != 0U) return;
  __atomic_store_n(&g_network_lock_owner, UINT32_MAX, __ATOMIC_RELEASE);
  __atomic_store_n(&g_network_lock_depth, 0U, __ATOMIC_RELEASE);
  xaios_spin_unlock(&g_network_lock);
}

/* Bound half-open state so SYN floods cannot exhaust the flow table. */
#define NETWORK_TCP_MAX_HALF_OPEN 16U

static uint32_t g_half_open_count = 0;

static uint8_t g_local_mac[6];
static uint32_t g_persistent_initialized;
static uint64_t g_poll_tick_count;
static uint32_t g_tcp_drain_cursor;
static uint64_t g_icmp_reply_count;
static uint64_t g_arp_reply_count;
static uint64_t g_icmpv6_reply_count;
static uint64_t g_ndp_reply_count;
static uint64_t g_ipv6_rx_count;
static xaios_ip_addr_t g_link_local_v6;
static xaios_ip_addr_t g_public_v6;
static uint64_t g_public_v6_valid_until_ns;
/* The address actually configured from a router advertisement, which may be a
   unique-local prefix rather than a globally routable one. A host on such a
   network still has working IPv6 within it, so this is what packets are sent
   from; g_public_v6 stays reserved for genuinely global addresses. */
static xaios_ip_addr_t g_slaac_v6;
static uint64_t g_slaac_valid_until_ns;
static xaios_network_ping_status_t g_ping;
static uint64_t g_ping_sent_ns;
static uint16_t g_ping_sequence;

#define NETWORK_PING_IDENTIFIER UINT16_C(0x5841)
#define NETWORK_PING_TIMEOUT_NS UINT64_C(3000000000)

/* ---- Socket-to-Flow Mapping ---- */
#define NETWORK_SOCK_FLOW_MAP_SIZE \
  (NETWORK_TCP_CONNECTIONS + NETWORK_UDP_FLOWS)
static socket_flow_mapping_t g_socket_flow_map[NETWORK_SOCK_FLOW_MAP_SIZE];

static uint64_t g_udp_tx_count;
static uint64_t g_udp_rx_count;
static uint64_t g_udp_malformed_count;
static uint64_t g_udp_dropped_count;
static uint64_t g_udp_flow_hit_count;
static uint64_t g_udp_expired_count;
static uint64_t g_tcp_handshake_count;
static uint64_t g_tcp_reset_count;
static uint64_t g_tcp_timeout_count;
static uint64_t g_tcp_retransmit_count;
static uint64_t g_tcp_established_count;
static uint64_t g_tcp_closed_count;
static uint64_t g_queue_binding_count;
static uint64_t g_rx_packet_count;
static uint64_t g_tx_packet_count;
static uint64_t g_packet_drop_count;
static uint64_t g_packet_lifecycle_count;
static uint64_t g_queue_rx_enqueue_count;
static uint64_t g_queue_tx_enqueue_count;
static uint64_t g_queue_completion_count;
static uint64_t g_queue_backpressure_drop_count;
static uint64_t g_flow_core_mismatch_count;

static uint64_t g_udp_latency_samples[NETWORK_MAX_SAMPLES];
static uint64_t g_tcp_latency_samples[NETWORK_MAX_SAMPLES];
static uint32_t g_udp_latency_count;
static uint32_t g_tcp_latency_count;

static int tcp_seq_before(uint32_t left, uint32_t right) {
  return (int32_t)(left - right) < 0;
}

static int tcp_seq_after(uint32_t left, uint32_t right) {
  return tcp_seq_before(right, left);
}

/* Buffer an out-of-order TCP segment within the current receive window. */
static uint32_t ooo_buffer_store(network_tcp_flow_t *flow, uint32_t seq,
                                   const uint8_t *data, uint32_t len,
                                   uint32_t expected_seq) {
  uint32_t distance = seq - expected_seq;
  if (len == 0U || len > NETWORK_TCP_IPV4_RX_MAX ||
      !tcp_seq_after(seq, expected_seq) ||
      distance >= flow->window_size) return 0;
  uint32_t available = flow->window_size - distance;
  if (len > available) len = available;
  if (len == 0U) return 0;
  for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (flow->ooo_buf[i].in_use != 0U && flow->ooo_buf[i].seq == seq) return 0;
  }
  for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (!flow->ooo_buf[i].in_use) {
      uint32_t copy_len = len;
      for (uint32_t j = 0; j < copy_len; ++j)
        flow->ooo_buf[i].data[j] = data[j];
      flow->ooo_buf[i].seq = seq;
      flow->ooo_buf[i].len = (uint16_t)copy_len;
      flow->ooo_buf[i].in_use = 1;
      flow->pending_ack = 1U;
      return copy_len;
    }
  }
  return 0;
}

/* Drain in-order or overlapping buffered segments without losing a short tail. */
static uint32_t ooo_buffer_drain(network_tcp_flow_t *flow) {
  uint32_t total = 0;
  int progress = 1;
  while (progress) {
    progress = 0;
    for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
      if (flow->ooo_buf[i].in_use &&
          !tcp_seq_after(flow->ooo_buf[i].seq, flow->expected_seq)) {
        uint32_t overlap = flow->expected_seq - flow->ooo_buf[i].seq;
        if (overlap >= flow->ooo_buf[i].len) {
          flow->ooo_buf[i].in_use = 0U;
          progress = 1;
          continue;
        }
        uint32_t remaining = flow->ooo_buf[i].len - overlap;
        uint32_t written = sockbuf_write(flow->rx_buf,
                            flow->ooo_buf[i].data + overlap, remaining);
        flow->expected_seq += written;
        flow->pending_ack = 1;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        if (written == remaining) {
          flow->ooo_buf[i].in_use = 0U;
        } else if (written != 0U) {
          uint32_t consumed = overlap + written;
          uint32_t tail = flow->ooo_buf[i].len - consumed;
          for (uint32_t j = 0; j < tail; ++j) {
            flow->ooo_buf[i].data[j] = flow->ooo_buf[i].data[consumed + j];
          }
          flow->ooo_buf[i].seq = flow->expected_seq;
          flow->ooo_buf[i].len = (uint16_t)tail;
        }
        total += written;
        progress = written != 0U;
      }
    }
  }
  return total;
}

/* Per-listener accept backlog. */
#define NETWORK_MAX_LISTENERS 16U
#define NETWORK_LISTENER_BACKLOG NETWORK_TCP_CONNECTIONS
typedef struct listener_accept_entry {
  uint32_t flow_id;
  uint32_t peer_ip;         /* IPv4 (host order) */
  xaios_ip_addr_t peer_addr; /* full address (IPv4 or IPv6) */
  uint16_t peer_port;
  uint16_t local_port;
  uint16_t payload_len;
  uint32_t active;
} listener_accept_entry_t;

typedef struct network_listener_ex {
  uint16_t port;
  uint8_t protocol;
  uint64_t sockfd;
  uint32_t active;
  listener_accept_entry_t backlog[NETWORK_LISTENER_BACKLOG];
  uint32_t backlog_count;
} network_listener_ex_t;

static network_listener_ex_t g_listeners_ex[NETWORK_MAX_LISTENERS];

static void release_tcp_flow(network_tcp_flow_t *flow) {
  if (flow == 0 || flow->state == XAIOS_NETWORK_FLOW_FREE) return;
  uint32_t flow_id = flow->flow_id;
  if (flow->rx_buf != 0) sockbuf_free(flow->rx_buf);
  if (flow->tx_buf != 0) sockbuf_free(flow->tx_buf);
  for (uint32_t listener_index = 0;
       listener_index < NETWORK_MAX_LISTENERS; ++listener_index) {
    network_listener_ex_t *listener = &g_listeners_ex[listener_index];
    uint32_t write_index = 0;
    for (uint32_t read_index = 0;
         read_index < listener->backlog_count; ++read_index) {
      if (listener->backlog[read_index].flow_id != flow_id) {
        if (write_index != read_index) {
          listener->backlog[write_index] = listener->backlog[read_index];
        }
        ++write_index;
      }
    }
    listener->backlog_count = write_index;
  }
  flow->rx_buf = 0;
  flow->tx_buf = 0;
  flow->flow_id = 0;
  flow->pending_synack = 0;
  flow->pending_syn = 0;
  flow->pending_fin = 0;
  flow->pending_ack = 0;
  flow->close_requested = 0;
  flow->in_flight = 0;
  flow->in_retransmit = 0;
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    flow->tx_segments[i].in_use = 0U;
    flow->tx_segments[i].pending = 0U;
  }
  flow->fin_outstanding = 0;
  flow->peer_fin_pending = 0;
  flow->peer_fin_received = 0;
  flow->pending_keepalive = 0;
  flow->state = XAIOS_NETWORK_FLOW_FREE;
}

static void tcp_enter_time_wait(network_tcp_flow_t *flow, uint64_t now_ns) {
  if (flow->rx_buf != 0) sockbuf_free(flow->rx_buf);
  if (flow->tx_buf != 0) sockbuf_free(flow->tx_buf);
  flow->rx_buf = 0;
  flow->tx_buf = 0;
  flow->state = XAIOS_NETWORK_FLOW_TIME_WAIT;
  flow->last_seen_ns = now_ns;
}

static void release_udp_flow(network_udp_flow_t *flow) {
  if (flow == 0 || flow->active == 0U) return;
  uint32_t flow_id = flow->flow_id;
  if (flow->rx_buf != 0) sockbuf_free(flow->rx_buf);
  for (uint32_t listener_index = 0;
       listener_index < NETWORK_MAX_LISTENERS; ++listener_index) {
    network_listener_ex_t *listener = &g_listeners_ex[listener_index];
    uint32_t write_index = 0;
    for (uint32_t read_index = 0;
         read_index < listener->backlog_count; ++read_index) {
      if (listener->backlog[read_index].flow_id != flow_id) {
        if (write_index != read_index) {
          listener->backlog[write_index] = listener->backlog[read_index];
        }
        ++write_index;
      }
    }
    listener->backlog_count = write_index;
  }
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0U &&
        g_socket_flow_map[i].protocol == NETWORK_IP_PROTO_UDP &&
        g_socket_flow_map[i].flow_id == flow_id) {
      g_socket_flow_map[i].active = 0U;
    }
  }
  flow->rx_buf = 0;
  flow->flow_id = 0U;
  flow->active = 0U;
}

static void tcp_update_rto(network_tcp_flow_t *flow, uint64_t sample_ns) {
  if (sample_ns == 0U) sample_ns = 1U;
  if (flow->srtt_ns == 0U) {
    flow->srtt_ns = sample_ns;
    flow->rttvar_ns = sample_ns / 2U;
  } else {
    uint64_t error = flow->srtt_ns > sample_ns ?
                         flow->srtt_ns - sample_ns : sample_ns - flow->srtt_ns;
    flow->rttvar_ns = (3U * flow->rttvar_ns + error) / 4U;
    flow->srtt_ns = (7U * flow->srtt_ns + sample_ns) / 8U;
  }
  uint64_t variation = 4U * flow->rttvar_ns;
  flow->rto_ns = flow->srtt_ns + variation;
  if (flow->rto_ns < NETWORK_TCP_RETRANSMIT_NS) {
    flow->rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  } else if (flow->rto_ns > UINT64_C(60000000000)) {
    flow->rto_ns = UINT64_C(60000000000);
  }
}

static void tcp_backoff_rto(network_tcp_flow_t *flow) {
  if (flow->rto_ns > UINT64_C(30000000000)) {
    flow->rto_ns = UINT64_C(60000000000);
  } else {
    flow->rto_ns *= 2U;
  }
  flow->ssthresh = flow->cwnd > 1U ? flow->cwnd >> 1U : 1U;
  flow->cwnd = NETWORK_TCP_MSS;
}

static uint32_t tcp_tx_segment_count(const network_tcp_flow_t *flow) {
  uint32_t count = 0U;
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    count += flow->tx_segments[i].in_use != 0U ? 1U : 0U;
  }
  return count;
}

static int tcp_tx_has_pending(const network_tcp_flow_t *flow) {
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    if (flow->tx_segments[i].in_use != 0U &&
        flow->tx_segments[i].pending != 0U) {
      return 1;
    }
  }
  return 0;
}

static uint32_t tcp_tx_oldest_index(const network_tcp_flow_t *flow) {
  uint32_t oldest = TCP_TX_WINDOW_SEGMENTS;
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    if (flow->tx_segments[i].in_use == 0U) continue;
    if (oldest == TCP_TX_WINDOW_SEGMENTS ||
        tcp_seq_before(flow->tx_segments[i].seq,
                       flow->tx_segments[oldest].seq)) {
      oldest = i;
    }
  }
  return oldest;
}

static uint32_t tcp_tx_free_index(const network_tcp_flow_t *flow) {
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    if (flow->tx_segments[i].in_use == 0U) return i;
  }
  return TCP_TX_WINDOW_SEGMENTS;
}

static void tcp_queue_send_window(network_tcp_flow_t *flow) {
  if (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0U) return;
  uint32_t allowed = flow->cwnd;
  if (flow->peer_window < allowed) allowed = flow->peer_window;
  flow->zero_window_probe = allowed == 0U ? 1U : 0U;
  if (allowed == 0U) allowed = 1U;
  while (flow->in_flight < allowed && sockbuf_used(flow->tx_buf) != 0U) {
    uint32_t slot = tcp_tx_free_index(flow);
    if (slot == TCP_TX_WINDOW_SEGMENTS) break;
    uint32_t send_limit = flow->peer_mss != 0U ?
                              flow->peer_mss : NETWORK_TCP_MSS;
    if (send_limit > NETWORK_TCP_MSS) send_limit = NETWORK_TCP_MSS;
    uint32_t window_remaining = allowed - flow->in_flight;
    if (send_limit > window_remaining) send_limit = window_remaining;
    uint32_t bytes = sockbuf_read(flow->tx_buf,
                                  flow->tx_segments[slot].data, send_limit);
    if (bytes == 0U) break;
    flow->tx_segments[slot].seq = flow->next_send_seq;
    flow->tx_segments[slot].len = (uint16_t)bytes;
    flow->tx_segments[slot].in_use = 1U;
    flow->tx_segments[slot].pending = 1U;
    flow->tx_segments[slot].retransmitted = 0U;
    flow->tx_segments[slot].retries = 0U;
    flow->tx_segments[slot].first_tx_ns = 0U;
    flow->tx_segments[slot].last_tx_ns = 0U;
    flow->next_send_seq += bytes;
    flow->in_flight += bytes;
  }
}

static void tcp_accept_peer_fin(network_tcp_flow_t *flow, uint64_t now_ns) {
  if (flow->peer_fin_pending == 0U ||
      flow->peer_fin_seq != flow->expected_seq) return;
  flow->expected_seq++;
  flow->peer_fin_pending = 0U;
  flow->peer_fin_received = 1U;
  flow->pending_ack = 1U;
  if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
    flow->state = XAIOS_NETWORK_FLOW_CLOSE_WAIT;
  } else if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2) {
    tcp_enter_time_wait(flow, now_ns);
  }
}

/* Returns 1 if the flow was released, -1 for an invalid ACK, and 0 otherwise. */
static int acknowledge_tcp_flow(network_tcp_flow_t *flow, uint32_t ack,
                                uint64_t now_ns) {
  if (flow == 0) return 0;
  if (tcp_seq_after(ack, flow->next_send_seq)) return -1;
  if (flow->state == XAIOS_NETWORK_FLOW_LAST_ACK &&
      flow->fin_outstanding != 0U &&
      !tcp_seq_before(ack, flow->fin_seq + 1U)) {
    ++g_tcp_closed_count;
    release_tcp_flow(flow);
    return 1;
  }
  if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT &&
      flow->fin_outstanding != 0U &&
      !tcp_seq_before(ack, flow->fin_seq + 1U)) {
    flow->fin_outstanding = 0U;
    if (flow->peer_fin_received == 0U) {
      flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT_2;
      flow->last_seen_ns = now_ns;
    } else {
      tcp_enter_time_wait(flow, now_ns);
    }
  }
  if (tcp_seq_after(ack, flow->local_seq)) {
    flow->local_seq = ack;
    flow->highest_acked = ack;
    uint32_t released = 0U;
    for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
      if (flow->tx_segments[i].in_use == 0U) continue;
      uint32_t end = flow->tx_segments[i].seq + flow->tx_segments[i].len;
      if (!tcp_seq_before(ack, end)) {
        if (flow->tx_segments[i].retransmitted == 0U &&
            flow->tx_segments[i].first_tx_ns != 0U &&
            now_ns > flow->tx_segments[i].first_tx_ns) {
          tcp_update_rto(flow, now_ns - flow->tx_segments[i].first_tx_ns);
        }
        released += flow->tx_segments[i].len;
        flow->tx_segments[i].in_use = 0U;
        flow->tx_segments[i].pending = 0U;
      } else if (tcp_seq_after(ack, flow->tx_segments[i].seq)) {
        uint32_t prefix = ack - flow->tx_segments[i].seq;
        if (prefix > flow->tx_segments[i].len) {
          prefix = flow->tx_segments[i].len;
        }
        uint32_t tail = flow->tx_segments[i].len - prefix;
        for (uint32_t j = 0U; j < tail; ++j) {
          flow->tx_segments[i].data[j] =
              flow->tx_segments[i].data[prefix + j];
        }
        flow->tx_segments[i].seq = ack;
        flow->tx_segments[i].len = (uint16_t)tail;
        released += prefix;
      }
    }
    if (released > flow->in_flight) released = flow->in_flight;
    flow->in_flight -= released;
    if (tcp_tx_segment_count(flow) == 0U) {
      flow->in_retransmit = 0U;
      flow->zero_window_probe = 0U;
    }
    flow->dup_ack_count = 0;
    uint32_t mss = flow->peer_mss > 0U ? flow->peer_mss : NETWORK_TCP_MSS;
    if (flow->cwnd < flow->ssthresh) {
      flow->cwnd += mss;
    } else {
      flow->cwnd += (mss * mss) / (flow->cwnd > 0U ? flow->cwnd : 1U);
    }
  } else if (ack == flow->local_seq && flow->in_flight > 0U) {
    if (flow->zero_window_probe != 0U) {
      if (flow->peer_window != 0U) {
        uint32_t oldest = tcp_tx_oldest_index(flow);
        if (oldest != TCP_TX_WINDOW_SEGMENTS) {
          flow->tx_segments[oldest].pending = 1U;
        }
      }
      return 0;
    }
    ++flow->dup_ack_count;
    if (flow->dup_ack_count >= TCP_MAX_DUP_ACK &&
        flow->in_retransmit == 0U) {
      flow->ssthresh = flow->cwnd > 1U ? flow->cwnd >> 1U : 1U;
      flow->cwnd = flow->ssthresh + TCP_MAX_DUP_ACK * NETWORK_TCP_MSS;
      flow->in_retransmit = 1;
      uint32_t oldest = tcp_tx_oldest_index(flow);
      if (oldest != TCP_TX_WINDOW_SEGMENTS) {
        flow->tx_segments[oldest].pending = 1U;
        flow->tx_segments[oldest].retransmitted = 1U;
        flow->tx_segments[oldest].last_tx_ns = now_ns;
        ++flow->retransmits;
        ++g_tcp_retransmit_count;
      }
    }
  }
  return 0;
}

static uint32_t tcp_apply_sack_blocks(
    network_tcp_flow_t *flow, const tcp_parsed_options_t *options) {
  uint32_t released = 0U;
  for (uint32_t block = 0U; block < options->sack_count; ++block) {
    uint32_t left = options->sack_left[block];
    uint32_t right = options->sack_right[block];
    if (!tcp_seq_before(left, right) || tcp_seq_before(left, flow->local_seq) ||
        tcp_seq_after(right, flow->next_send_seq)) {
      continue;
    }
    for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
      if (flow->tx_segments[i].in_use == 0U) continue;
      uint32_t end = flow->tx_segments[i].seq + flow->tx_segments[i].len;
      if (!tcp_seq_before(flow->tx_segments[i].seq, left) &&
          !tcp_seq_after(end, right)) {
        released += flow->tx_segments[i].len;
        flow->tx_segments[i].in_use = 0U;
        flow->tx_segments[i].pending = 0U;
      }
    }
  }
  if (released > flow->in_flight) released = flow->in_flight;
  flow->in_flight -= released;
  return released;
}

static network_listener_ex_t *find_listener_ex(uint16_t port,
                                                uint8_t protocol) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active && g_listeners_ex[i].port == port &&
        g_listeners_ex[i].protocol == protocol)
      return &g_listeners_ex[i];
  }
  return 0;
}

static network_listener_ex_t *find_listener_by_socket(uint64_t sockfd,
                                                       uint8_t protocol) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active && g_listeners_ex[i].sockfd == sockfd &&
        g_listeners_ex[i].protocol == protocol) {
      return &g_listeners_ex[i];
    }
  }
  return 0;
}

static int listener_enqueue_backlog(uint16_t port, uint32_t flow_id,
                                     uint32_t peer_ip, uint16_t peer_port,
                                     const xaios_ip_addr_t *peer_addr) {
  network_listener_ex_t *l = find_listener_ex(port, NETWORK_IP_PROTO_TCP);
  if (!l) return 0;
  if (l->backlog_count >= NETWORK_LISTENER_BACKLOG) return 0;
  listener_accept_entry_t *e = &l->backlog[l->backlog_count++];
  e->flow_id = flow_id;
  e->peer_ip = peer_ip;
  if (peer_addr) e->peer_addr = *peer_addr;
  else { xaios_ip_addr_zero(&e->peer_addr); e->peer_addr.family = XAIOS_IP_FAMILY_V4; }
  e->peer_port = peer_port;
  e->local_port = port;
  e->payload_len = 0;
  e->active = 1;
  return 1;
}

static int listener_dequeue_backlog(uint16_t port, uint32_t *out_flow_id,
                                     uint32_t *out_peer_ip,
                                     uint16_t *out_peer_port,
                                     xaios_ip_addr_t *out_peer_addr) {
  network_listener_ex_t *l = find_listener_ex(port, NETWORK_IP_PROTO_TCP);
  if (!l || l->backlog_count == 0) return 0;
  listener_accept_entry_t *e = &l->backlog[0];
  if (out_flow_id) *out_flow_id = e->flow_id;
  if (out_peer_ip) *out_peer_ip = e->peer_ip;
  if (out_peer_port) *out_peer_port = e->peer_port;
  if (out_peer_addr) *out_peer_addr = e->peer_addr;
  for (uint32_t i = 1; i < l->backlog_count; ++i)
    l->backlog[i - 1] = l->backlog[i];
  l->backlog_count--;
  return 1;
}

static int udp_listener_enqueue(uint16_t port, uint32_t flow_id,
                                uint16_t peer_port,
                                const xaios_ip_addr_t *peer_addr,
                                uint16_t payload_len) {
  network_listener_ex_t *listener =
      find_listener_ex(port, NETWORK_IP_PROTO_UDP);
  if (listener == 0) {
    return 0;
  }
  if (listener->backlog_count >= NETWORK_LISTENER_BACKLOG) {
    return 0;
  }
  listener_accept_entry_t *entry =
      &listener->backlog[listener->backlog_count++];
  entry->flow_id = flow_id;
  entry->peer_ip = 0;
  entry->peer_addr = *peer_addr;
  entry->peer_port = peer_port;
  entry->local_port = port;
  entry->payload_len = payload_len;
  entry->active = 1;
  return 1;
}

static uint16_t read_u16_be(const uint8_t *bytes) {
  return (uint16_t)(((uint16_t)bytes[0] << 8U) | (uint16_t)bytes[1]);
}

static uint32_t read_u32_be(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static void write_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)(value);
}

static void write_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

static int network_ipv6_is_global_unicast(const xaios_ip_addr_t *address) {
  return address != 0 && address->family == XAIOS_IP_FAMILY_V6 &&
         (address->addr[0] & UINT8_C(0xe0)) == UINT8_C(0x20);
}

static int network_ipv6_is_unique_local(const xaios_ip_addr_t *address) {
  return address != 0 && address->family == XAIOS_IP_FAMILY_V6 &&
         (address->addr[0] & UINT8_C(0xfe)) == UINT8_C(0xfc);
}

static void network_ipv6_slaac_from_prefix(xaios_ip_addr_t *address,
                                           const uint8_t prefix[16]) {
  address->family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0U; i < 8U; ++i) address->addr[i] = prefix[i];
  address->addr[8] = g_local_mac[0] ^ UINT8_C(0x02);
  address->addr[9] = g_local_mac[1];
  address->addr[10] = g_local_mac[2];
  address->addr[11] = UINT8_C(0xff);
  address->addr[12] = UINT8_C(0xfe);
  address->addr[13] = g_local_mac[3];
  address->addr[14] = g_local_mac[4];
  address->addr[15] = g_local_mac[5];
}

static void network_ipv6_apply_router_advertisement(const uint8_t *frame,
                                                     uint32_t frame_len,
                                                     uint64_t now_ns) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_OFFSET + 16U) return;
  uint32_t payload_len = read_u16_be(frame + 18U);
  if (payload_len < 16U || payload_len > frame_len - XAIOS_ICMPV6_OFFSET) return;

  const uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  for (uint32_t offset = 16U; offset + 2U <= payload_len;) {
    uint32_t option_len = (uint32_t)icmpv6[offset + 1U] * 8U;
    if (option_len == 0U || option_len > payload_len - offset) return;
    if (icmpv6[offset] == 3U && option_len == 32U &&
        icmpv6[offset + 2U] == 64U &&
        (icmpv6[offset + 3U] & UINT8_C(0x40)) != 0U) {
      uint32_t valid_lifetime_s = read_u32_be(icmpv6 + offset + 4U);
      xaios_ip_addr_t candidate;
      network_ipv6_slaac_from_prefix(&candidate, icmpv6 + offset + 16U);
      int global = network_ipv6_is_global_unicast(&candidate);
      int unique_local = network_ipv6_is_unique_local(&candidate);
      if (valid_lifetime_s != 0U && (global != 0 || unique_local != 0)) {
        uint64_t lifetime_ns = (uint64_t)valid_lifetime_s * UINT64_C(1000000000);
        uint64_t valid_until =
            lifetime_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + lifetime_ns;
        if (xaios_ip_addr_equal(&g_slaac_v6, &candidate) == 0) {
          klog("network: IPv6 address configured from advertised %x%x:%x%x::/64"
               " (%s)\n",
               candidate.addr[0], candidate.addr[1], candidate.addr[2],
               candidate.addr[3], global != 0 ? "global" : "unique-local");
        }
        g_slaac_v6 = candidate;
        g_slaac_valid_until_ns = valid_until;
        if (global != 0) {
          g_public_v6 = candidate;
          g_public_v6_valid_until_ns = valid_until;
          klog("network: public IPv6 SLAAC address configured\n");
        }
      }
      return;
    }
    offset += option_len;
  }
}

static uint32_t tcp_generate_isn(uint32_t flow_id) {
  uint32_t sequence = 0;
  if (entropy_read(&sequence, sizeof(sequence)) == XAIOS_OK) {
    return sequence;
  }
  return (uint32_t)(timer_now_ns() ^ ((uint64_t)flow_id << 16U));
}

static uint32_t tcp_scaled_window(uint16_t window, uint8_t shift) {
  if (shift > 14U) shift = 14U;
  return (uint32_t)window << shift;
}

static void bytes_zero(void *buffer, uint64_t size);

static int parse_tcp_options(const uint8_t *tcp_hdr, uint32_t hdr_bytes,
                             tcp_parsed_options_t *options) {
  bytes_zero(options, sizeof(*options));
  if (tcp_hdr == 0 || hdr_bytes < 20U || hdr_bytes > 60U) return 0;
  uint32_t offset = 20; /* skip fixed header */
  while (offset + 1U <= hdr_bytes) {
    uint8_t kind = tcp_hdr[offset];
    if (kind == TCP_OPT_END) break;
    if (kind == TCP_OPT_NOP) { offset += 1; continue; }
    if (offset + 2U > hdr_bytes) return 0;
    uint8_t len = tcp_hdr[offset + 1U];
    if (len < 2U || offset + (uint32_t)len > hdr_bytes) return 0;
    if (kind == TCP_OPT_MSS && len == 4U && offset + 4U <= hdr_bytes) {
      options->mss = read_u16_be(tcp_hdr + offset + 2U);
    } else if (kind == TCP_OPT_WSCALE && len == 3U) {
      uint8_t shift = tcp_hdr[offset + 2U];
      options->window_scale = shift > 14U ? 14U : shift;
    } else if (kind == TCP_OPT_SACK_PERMITTED && len == 2U) {
      options->sack_permitted = 1U;
    } else if (kind == TCP_OPT_SACK) {
      if (len < 10U || ((uint32_t)len - 2U) % 8U != 0U) return 0;
      uint32_t count = ((uint32_t)len - 2U) / 8U;
      if (count > TCP_OOO_BUF_ENTRIES) count = TCP_OOO_BUF_ENTRIES;
      for (uint32_t i = 0U; i < count; ++i) {
        options->sack_left[i] =
            read_u32_be(tcp_hdr + offset + 2U + i * 8U);
        options->sack_right[i] =
            read_u32_be(tcp_hdr + offset + 6U + i * 8U);
      }
      options->sack_count = (uint8_t)count;
    }
    offset += (uint32_t)len;
  }
  return 1;
}

static uint32_t build_tcp_options(const network_tcp_flow_t *flow,
                                  uint8_t flags, uint8_t options[40]) {
  bytes_zero(options, 40U);
  if ((flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    options[0] = TCP_OPT_MSS;
    options[1] = 4U;
    write_be16(options + 2U,
               flow != 0 && flow->local_addr.family == XAIOS_IP_FAMILY_V6
                   ? NETWORK_TCP_IPV6_MSS : NETWORK_TCP_MSS);
    options[4] = TCP_OPT_SACK_PERMITTED;
    options[5] = 2U;
    options[6] = TCP_OPT_NOP;
    options[7] = TCP_OPT_WSCALE;
    options[8] = 3U;
    options[9] = 0U;
    options[10] = TCP_OPT_END;
    return 12U;
  }
  if ((flags & NETWORK_TCP_FLAG_ACK) == 0U || flow == 0 ||
      flow->peer_sack_permitted == 0U) {
    return 0U;
  }
  uint32_t count = 0U;
  for (uint32_t i = 0U; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (flow->ooo_buf[i].in_use != 0U) ++count;
  }
  if (count == 0U) return 0U;
  options[0] = TCP_OPT_SACK;
  options[1] = (uint8_t)(2U + count * 8U);
  uint32_t written = 0U;
  for (uint32_t i = 0U; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (flow->ooo_buf[i].in_use == 0U) continue;
    write_be32(options + 2U + written * 8U, flow->ooo_buf[i].seq);
    write_be32(options + 6U + written * 8U,
               flow->ooo_buf[i].seq + flow->ooo_buf[i].len);
    ++written;
  }
  return 2U + count * 8U;
}

static uint64_t percentile(uint64_t *samples, uint32_t count, uint32_t p) {
  if (count == 0U) {
    return 0;
  }
  uint64_t sorted[NETWORK_MAX_SAMPLES];
  for (uint32_t i = 0; i < count; ++i) {
    sorted[i] = samples[i];
  }

  for (uint32_t i = 0; i < count; ++i) {
    for (uint32_t j = i + 1U; j < count; ++j) {
      if (sorted[j] < sorted[i]) {
        uint64_t tmp = sorted[i];
        sorted[i] = sorted[j];
        sorted[j] = tmp;
      }
    }
  }

  uint32_t divisor = (p > 100U) ? 1000U : 100U;
  uint32_t index = (count * p) / divisor;
  if (index >= count) {
    index = count - 1U;
  }

  return sorted[index];
}

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void record_latency(uint64_t *samples, uint32_t *count, uint64_t value) {
  if (*count < NETWORK_MAX_SAMPLES) {
    samples[*count] = value;
    ++(*count);
  }
}

static network_queue_binding_t *find_binding(uint32_t queue_id) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id) {
      return &g_queue_bindings[i];
    }
  }
  return 0;
}

static network_queue_ring_t *find_queue_ring(uint32_t queue_id) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_rings[i].queue_id == queue_id) {
      return &g_queue_rings[i];
    }
  }
  return 0;
}

static uint32_t active_binding_count(void) {
  uint32_t active = 0;
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0) {
      ++active;
    }
  }
  return active;
}

static network_queue_binding_t *binding_by_active_index(uint32_t index) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0) {
      if (index == 0U) {
        return &g_queue_bindings[i];
      }
      --index;
    }
  }
  return 0;
}

static network_queue_binding_t *select_binding_for_flow(uint16_t local_port,
                                                        uint16_t remote_port,
                                                        uint32_t local_address,
                                                        uint32_t remote_address) {
  uint32_t active = active_binding_count();
  if (active == 0U) {
    return 0;
  }
  uint32_t hash = (uint32_t)local_port ^ ((uint32_t)remote_port << 3U) ^
                  local_address ^ (remote_address >> 8U);
  return binding_by_active_index(hash % active);
}

static void queue_ring_reset(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring == 0) {
    return;
  }
  ring->rx_depth = 0;
  ring->tx_depth = 0;
  ring->completed = 0;
  ring->drops = 0;
}

static int queue_ring_rx_enqueue(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring == 0 || ring->rx_depth >= NETWORK_QUEUE_RING_SIZE) {
    ++g_queue_backpressure_drop_count;
    if (ring != 0) {
      ++ring->drops;
    }
    return 0;
  }
  ++ring->rx_depth;
  ++g_queue_rx_enqueue_count;
  return 1;
}

static void queue_ring_rx_complete(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring != 0 && ring->rx_depth > 0U) {
    --ring->rx_depth;
  }
}

static int queue_ring_tx_enqueue(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring == 0 || ring->tx_depth >= NETWORK_QUEUE_RING_SIZE) {
    ++g_queue_backpressure_drop_count;
    if (ring != 0) {
      ++ring->drops;
    }
    return 0;
  }
  ++ring->tx_depth;
  ++g_queue_tx_enqueue_count;
  return 1;
}

static void queue_ring_tx_complete(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring != 0) {
    if (ring->tx_depth > 0U) {
      --ring->tx_depth;
    }
    ++ring->completed;
    ++g_queue_completion_count;
  }
}

static network_packet_desc_t *alloc_packet_desc(uint32_t queue_id,
                                                uint64_t length,
                                                uint64_t now_ns) {
  network_queue_binding_t *binding = find_binding(queue_id);
  if (binding == 0 || length == 0 || length > NETWORK_BUFFER_SIZE) {
    ++g_packet_drop_count;
    return 0;
  }
  if (queue_ring_rx_enqueue(queue_id) == 0) {
    ++g_packet_drop_count;
    return 0;
  }

  for (uint32_t i = 0; i < NETWORK_PACKET_DESCRIPTORS; ++i) {
    if (g_packet_descs[i].state == NETWORK_PACKET_FREE ||
        g_packet_descs[i].state == NETWORK_PACKET_COMPLETE ||
        g_packet_descs[i].state == NETWORK_PACKET_DROPPED) {
      g_packet_descs[i].state = NETWORK_PACKET_RX_OWNED;
      g_packet_descs[i].queue_id = queue_id;
      g_packet_descs[i].cell_id = binding->cell_id;
      g_packet_descs[i].src_port = 0;
      g_packet_descs[i].dst_port = 0;
      g_packet_descs[i].src_address = 0;
      g_packet_descs[i].dst_address = 0;
      g_packet_descs[i].length = length;
      g_packet_descs[i].created_ns = now_ns;
      ++g_rx_packet_count;
      ++g_packet_lifecycle_count;
      return &g_packet_descs[i];
    }
  }

  queue_ring_rx_complete(queue_id);
  ++g_packet_drop_count;
  return 0;
}

static void packet_mark_dropped(network_packet_desc_t *packet);

static void packet_mark_tx(network_packet_desc_t *packet) {
  if (packet != 0 && packet->state == NETWORK_PACKET_RX_OWNED) {
    if (queue_ring_tx_enqueue(packet->queue_id) == 0) {
      packet_mark_dropped(packet);
      return;
    }
    queue_ring_rx_complete(packet->queue_id);
    packet->state = NETWORK_PACKET_TX_QUEUED;
    ++g_tx_packet_count;
    ++g_packet_lifecycle_count;
  }
}

static void packet_mark_complete(network_packet_desc_t *packet) {
  if (packet != 0 && packet->state == NETWORK_PACKET_TX_QUEUED) {
    queue_ring_tx_complete(packet->queue_id);
    packet->state = NETWORK_PACKET_COMPLETE;
    ++g_packet_lifecycle_count;
  }
}

static void packet_mark_dropped(network_packet_desc_t *packet) {
  if (packet != 0 && packet->state != NETWORK_PACKET_DROPPED) {
    if (packet->state == NETWORK_PACKET_RX_OWNED) {
      queue_ring_rx_complete(packet->queue_id);
    } else if (packet->state == NETWORK_PACKET_TX_QUEUED) {
      queue_ring_tx_complete(packet->queue_id);
    }
    packet->state = NETWORK_PACKET_DROPPED;
    ++g_packet_drop_count;
    ++g_packet_lifecycle_count;
  }
}

static uint32_t ip4_addr_host_order(uint32_t network_order_address) {
  const uint8_t *src = (const uint8_t *)&network_order_address;
  return (uint32_t)src[0] | ((uint32_t)src[1] << 8U) |
         ((uint32_t)src[2] << 16U) | ((uint32_t)src[3] << 24U);
}

static int eth_frame_has_ipv4(const uint8_t *frame, uint64_t frame_len) {
  const network_ip4_header_t *ip = (const network_ip4_header_t *)(frame + 14U);
  if (frame_len < (14U + 20U)) {
    return 0;
  }
  if (read_u16_be(frame + 12U) != NETWORK_ETHERTYPE_IPV4) {
    return 0;
  }
  if ((ip->version_ihl >> 4U) != 4U) {
    return 0;
  }
  return 1;
}

static int parse_udp(const uint8_t *frame, uint64_t frame_len,
                     uint16_t *src_port, uint16_t *dst_port,
                     uint16_t *payload_len, uint32_t *src_address,
                     uint32_t *dst_address) {
  if (!eth_frame_has_ipv4(frame, frame_len)) {
    return 0;
  }
  if (!ipv4_validate_incoming(frame, frame_len) ||
      ipv4_is_fragment(frame, frame_len)) {
    return 0;
  }

  const network_ip4_header_t *ip = (const network_ip4_header_t *)(frame + 14U);
  const uint16_t ip_header_words = (uint16_t)(ip->version_ihl & 0x0fU);
  const uint64_t ip_len = (uint64_t)read_u16_be((const uint8_t *)&ip->total_length);
  const uint32_t ip_header_bytes = (uint32_t)ip_header_words * 4U;
  if (ip->protocol != NETWORK_IP_PROTO_UDP) {
    return 0;
  }
  if (ip_header_bytes < 20U || ip_len < ip_header_bytes) {
    return 0;
  }

  const network_udp_header_t *udp =
      (const network_udp_header_t *)((const uint8_t *)ip + ip_header_bytes);
  const uint64_t udp_start = 14U + (uint64_t)ip_header_bytes;
  const uint64_t udp_end = 14U + ip_len;
  if (udp_end > frame_len || ip_len < ip_header_bytes + 8U) {
    return 0;
  }

  const uint16_t udp_length = read_u16_be((const uint8_t *)&udp->length);
  if (udp_length < 8U || udp_start + 8U > udp_end || udp_start + (uint64_t)udp_length > udp_end) {
    return 0;
  }

  uint16_t wire_checksum = read_u16_be((const uint8_t *)&udp->checksum);
  if (wire_checksum != 0U) {
    uint32_t source = read_u32_be((const uint8_t *)&ip->source);
    uint32_t destination = read_u32_be((const uint8_t *)&ip->destination);
    if (ipv4_pseudo_checksum(source, destination, NETWORK_IP_PROTO_UDP,
                             udp_length, (const uint8_t *)udp,
                             udp_length) != 0U) return 0;
  }

  *src_port = read_u16_be((const uint8_t *)&udp->source_port);
  *dst_port = read_u16_be((const uint8_t *)&udp->dest_port);
  *payload_len = udp_length;
  *src_address = ip4_addr_host_order(ip->source);
  *dst_address = ip4_addr_host_order(ip->destination);
  return 1;
}

static int parse_tcp(const uint8_t *frame, uint64_t frame_len, uint16_t *src_port,
                    uint16_t *dst_port, uint32_t *seq, uint32_t *ack,
                    uint8_t *flags) {
  if (!eth_frame_has_ipv4(frame, frame_len)) {
    return 0;
  }
  if (!ipv4_validate_incoming(frame, frame_len) ||
      ipv4_is_fragment(frame, frame_len)) {
    return 0;
  }

  const network_ip4_header_t *ip = (const network_ip4_header_t *)(frame + 14U);
  const uint16_t ip_header_words = (uint16_t)(ip->version_ihl & 0x0fU);
  const uint64_t ip_len = (uint64_t)read_u16_be((const uint8_t *)&ip->total_length);
  const uint64_t ip_header_bytes = (uint64_t)ip_header_words * 4U;
  if (ip->protocol != NETWORK_IP_PROTO_TCP) {
    return 0;
  }
  if (ip_header_bytes < 20U || ip_len < ip_header_bytes + 20U) {
    return 0;
  }
  if (14U + ip_len > frame_len) {
    return 0;
  }

  const network_tcp_header_t *tcp =
      (const network_tcp_header_t *)((const uint8_t *)ip + ip_header_bytes);
  const uint16_t data_offset_words = (uint16_t)(tcp->data_offset_reserved >> 4U);
  
  /* TCP options are bounded by both the protocol and the IP payload. */
  if (data_offset_words < 5U) {
    return 0;  /* TCP header too small */
  }
  if (data_offset_words > 15U) {
    return 0;  /* TCP header too large (max 60 bytes) */
  }
  
  const uint64_t tcp_header_bytes = (uint64_t)data_offset_words * 4U;
  
  if (tcp_header_bytes > ip_len - ip_header_bytes) {
    return 0;  /* TCP header extends beyond IP payload */
  }
  
  if (tcp_header_bytes > 60) {
    return 0;  /* TCP options exceed 40 byte limit */
  }
  
  const uint64_t tcp_payload_len =
      ip_len - ip_header_bytes - (uint64_t)tcp_header_bytes;
  const uint16_t tcp_len = (uint16_t)(tcp_header_bytes + tcp_payload_len);

  if (tcp_header_bytes > ip_len) {
    return 0;
  }

  /* TCP checksums are mandatory on this receive path. */
  uint32_t src_ip_be = read_u32_be((const uint8_t *)&ip->source);
  uint32_t dst_ip_be = read_u32_be((const uint8_t *)&ip->destination);
  uint16_t wire_cksum = read_u16_be((const uint8_t *)&tcp->checksum);
  if (wire_cksum == 0U ||
      ipv4_pseudo_checksum(src_ip_be, dst_ip_be, NETWORK_IP_PROTO_TCP,
                           tcp_len, (const uint8_t *)tcp, tcp_len) != 0U) {
    return 0;
  }

  *src_port = read_u16_be((const uint8_t *)&tcp->source_port);
  *dst_port = read_u16_be((const uint8_t *)&tcp->dest_port);
  *seq = read_u32_be((const uint8_t *)&tcp->seq);
  *ack = read_u32_be((const uint8_t *)&tcp->ack);
  *flags = tcp->flags;
  return 1;
}

static int eth_frame_has_ipv6(const uint8_t *frame, uint64_t frame_len) {
  if (frame_len < (14U + XAIOS_IPV6_HEADER_SIZE)) {
    return 0;
  }
  if (read_u16_be(frame + 12U) != NETWORK_ETHERTYPE_IPV6) {
    return 0;
  }
  if ((frame[14U] >> 4U) != 6U) {
    return 0;
  }
  return 1;
}

static int parse_udp_v6(const uint8_t *frame, uint64_t frame_len,
                        uint16_t *src_port, uint16_t *dst_port,
                        uint16_t *payload_len,
                        xaios_ip_addr_t *src_addr, xaios_ip_addr_t *dst_addr) {
  if (!eth_frame_has_ipv6(frame, frame_len)) {
    return 0;
  }
  const uint8_t *ip6 = frame + 14U;
  uint16_t plen = read_u16_be(ip6 + 4U);
  uint8_t next_hdr = ip6[6U];
  if (next_hdr != NETWORK_IP_PROTO_UDP) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + 8U > frame_len) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + plen > frame_len) {
    return 0;
  }
  const uint8_t *udp = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t udp_len = read_u16_be(udp + 4U);
  if (udp_len < 8U || udp_len > plen) {
    return 0;
  }
  *src_port = read_u16_be(udp);
  *dst_port = read_u16_be(udp + 2U);
  *payload_len = udp_len;

  /* IPv6 UDP checksums are mandatory. */
  uint16_t wire_udp_cksum = read_u16_be(udp + 6U);
  if (wire_udp_cksum != 0) {
    xaios_ip_addr_t usrc, udst;
    xaios_ip_addr_from_raw_ipv6(&usrc, ip6 + 8U);
    xaios_ip_addr_from_raw_ipv6(&udst, ip6 + 24U);
    uint16_t computed_cksum = ipv6_pseudo_checksum(&usrc, &udst,
                                  NETWORK_IP_PROTO_UDP, udp_len,
                                  udp, udp_len);
    if (computed_cksum != 0) {
      return 0; /* bad checksum */
    }
  } else {
    return 0; /* RFC 2460: IPv6 UDP must have non-zero checksum */
  }

  xaios_ip_addr_from_raw_ipv6(src_addr, ip6 + 8U);
  xaios_ip_addr_from_raw_ipv6(dst_addr, ip6 + 24U);
  return 1;
}

static int parse_tcp_v6(const uint8_t *frame, uint64_t frame_len,
                        uint16_t *src_port, uint16_t *dst_port,
                        uint32_t *seq, uint32_t *ack_val, uint8_t *flags,
                        xaios_ip_addr_t *src_addr, xaios_ip_addr_t *dst_addr) {
  if (!eth_frame_has_ipv6(frame, frame_len)) {
    return 0;
  }
  const uint8_t *ip6 = frame + 14U;
  uint16_t plen = read_u16_be(ip6 + 4U);
  uint8_t next_hdr = ip6[6U];
  if (next_hdr != NETWORK_IP_PROTO_TCP) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + 20U > frame_len) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + plen > frame_len) {
    return 0;
  }
  const uint8_t *tcp = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t data_offset_words = (uint16_t)(tcp[12U] >> 4U);
  if (data_offset_words < 5U || data_offset_words > 15U) {
    return 0;
  }
  uint32_t tcp_hdr_bytes = (uint32_t)data_offset_words * 4U;
  if (tcp_hdr_bytes > (uint32_t)plen) {
    return 0;
  }
  *src_port = read_u16_be(tcp);
  *dst_port = read_u16_be(tcp + 2U);
  *seq = read_u32_be(tcp + 4U);
  *ack_val = read_u32_be(tcp + 8U);
  *flags = tcp[13U];

  /* TCP checksums are mandatory for IPv6. */
  uint32_t tcp_total = tcp_hdr_bytes + ((uint32_t)plen - tcp_hdr_bytes);
  uint16_t wire_cksum = read_u16_be(tcp + 16U);
  xaios_ip_addr_t src, dst;
  xaios_ip_addr_from_raw_ipv6(&src, ip6 + 8U);
  xaios_ip_addr_from_raw_ipv6(&dst, ip6 + 24U);
  if (wire_cksum == 0U ||
      ipv6_pseudo_checksum(&src, &dst, NETWORK_IP_PROTO_TCP, tcp_total,
                           tcp, tcp_total) != 0U) return 0;

  xaios_ip_addr_from_raw_ipv6(src_addr, ip6 + 8U);
  xaios_ip_addr_from_raw_ipv6(dst_addr, ip6 + 24U);
  return 1;
}

static network_tcp_flow_t *find_flow_by_ports_v6(
    uint16_t local_port, uint16_t remote_port,
    const xaios_ip_addr_t *remote_addr) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state != XAIOS_NETWORK_FLOW_FREE &&
        g_tcp_flows[i].local_port == local_port &&
        g_tcp_flows[i].remote_port == remote_port &&
        xaios_ip_addr_equal(&g_tcp_flows[i].remote_addr, remote_addr)) {
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *find_udp_flow_v6(
    uint16_t local_port, uint16_t remote_port,
    const xaios_ip_addr_t *local_addr, const xaios_ip_addr_t *remote_addr) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        g_udp_flows[i].local_port == local_port &&
        g_udp_flows[i].remote_port == remote_port &&
        xaios_ip_addr_equal(&g_udp_flows[i].local_addr, local_addr) &&
        xaios_ip_addr_equal(&g_udp_flows[i].remote_addr, remote_addr)) {
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static network_tcp_flow_t *find_flow_by_ports(uint16_t local_port,
                                              uint16_t remote_port,
                                              uint32_t remote_address) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state != XAIOS_NETWORK_FLOW_FREE &&
        g_tcp_flows[i].local_port == local_port &&
        g_tcp_flows[i].remote_port == remote_port &&
        g_tcp_flows[i].remote_address == remote_address) {
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *find_udp_flow(uint16_t local_port,
                                         uint16_t remote_port,
                                         uint32_t local_address,
                                         uint32_t remote_address) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        g_udp_flows[i].local_port == local_port &&
        g_udp_flows[i].remote_port == remote_port &&
        g_udp_flows[i].local_address == local_address &&
        g_udp_flows[i].remote_address == remote_address) {
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *alloc_udp_flow(uint32_t queue_id, uint32_t cell_id,
                                          uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t local_address,
                                          uint32_t remote_address,
                                          uint64_t now_ns) {
  network_udp_flow_t *flow = find_udp_flow(local_port, remote_port,
                                           local_address, remote_address);
  if (flow != 0) {
    ++g_udp_flow_hit_count;
    flow->last_seen_ns = now_ns;
    return flow;
  }
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active == 0) {
      g_udp_flows[i].active = 1;
      g_udp_flows[i].flow_id = (uint32_t)(g_next_flow_id++);
      if (g_udp_flows[i].flow_id == 0U) {
        g_udp_flows[i].flow_id = 1U;
        g_next_flow_id = 2U;
      }
      g_udp_flows[i].queue_id = queue_id;
      g_udp_flows[i].cell_id = cell_id;
      g_udp_flows[i].local_port = local_port;
      g_udp_flows[i].remote_port = remote_port;
      g_udp_flows[i].local_address = local_address;
      g_udp_flows[i].remote_address = remote_address;
      g_udp_flows[i].packets_rx = 0;
      g_udp_flows[i].packets_tx = 0;
      g_udp_flows[i].rx_buf = sockbuf_alloc();
      if (g_udp_flows[i].rx_buf == 0) {
        g_udp_flows[i].flow_id = 0U;
        g_udp_flows[i].active = 0U;
        return 0;
      }
      g_udp_flows[i].last_seen_ns = now_ns;
      g_udp_flows[i].remote_mac_valid = 0;
      xaios_ip_addr_zero(&g_udp_flows[i].local_addr);
      xaios_ip_addr_zero(&g_udp_flows[i].remote_addr);
      klog("network: udp flow id=%u queue=%u cell=%u local=%u remote=%u\n",
           g_udp_flows[i].flow_id, queue_id, cell_id, local_port, remote_port);
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static int tcp_flow_has_remote_tuple(const network_tcp_flow_t *flow,
                                     uint16_t local_port,
                                     uint16_t remote_port,
                                     uint32_t remote_address,
                                     const xaios_ip_addr_t *remote_addr) {
  if (flow->local_port != local_port || flow->remote_port != remote_port) {
    return 0;
  }
  if (remote_addr != 0) {
    return xaios_ip_addr_equal(&flow->remote_addr, remote_addr);
  }
  return flow->remote_address == remote_address;
}

static network_tcp_flow_t *alloc_tcp_flow(
    uint16_t local_port, uint16_t remote_port, uint32_t remote_address,
    const xaios_ip_addr_t *remote_addr) {
  /* Limit half-open connections before reserving a flow slot. */
  if (g_half_open_count >= NETWORK_TCP_MAX_HALF_OPEN) {
    klog("network: SYN flood protection: rejecting connection (half-open: %u)\n", g_half_open_count);
    return 0;
  }

  uint32_t has_free = 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_FREE) {
      has_free = 1U;
      break;
    }
  }
  if (has_free == 0U) {
    network_tcp_flow_t *oldest = 0;
    for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
      network_tcp_flow_t *candidate = &g_tcp_flows[i];
      if (candidate->state != XAIOS_NETWORK_FLOW_TIME_WAIT ||
          tcp_flow_has_remote_tuple(candidate, local_port, remote_port,
                                    remote_address, remote_addr)) {
        continue;
      }
      if (oldest == 0 || candidate->last_seen_ns < oldest->last_seen_ns) {
        oldest = candidate;
      }
    }
    if (oldest != 0) {
      klog("network: recycling TIME_WAIT flow id=%u for new tuple\n",
           oldest->flow_id);
      release_tcp_flow(oldest);
    }
  }

  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_FREE) {
      g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_SYN_RECV;
      g_tcp_flows[i].retransmits = 0;
      g_tcp_flows[i].packets_rx = 0;
      g_tcp_flows[i].packets_tx = 0;
      /* Zero data plane fields */
      g_tcp_flows[i].rx_buf = 0;
      g_tcp_flows[i].tx_buf = 0;
      g_tcp_flows[i].expected_seq = 0;
      g_tcp_flows[i].next_send_seq = 0;
      g_tcp_flows[i].window_size = 0;
      g_tcp_flows[i].pending_synack = 0;
      g_tcp_flows[i].pending_syn = 0;
      g_tcp_flows[i].pending_fin = 0;
      g_tcp_flows[i].pending_ack = 0;
      g_tcp_flows[i].close_requested = 0;
      g_tcp_flows[i].remote_mac_valid = 0;
      g_tcp_flows[i].remote_address = 0;
      g_tcp_flows[i].local_address = 0;
      xaios_ip_addr_zero(&g_tcp_flows[i].remote_addr);
      xaios_ip_addr_zero(&g_tcp_flows[i].local_addr);
      /* Retransmission state. */
      g_tcp_flows[i].rto_ns = NETWORK_TCP_RETRANSMIT_NS;
      g_tcp_flows[i].in_retransmit = 0;
      /* Out-of-order receive state. */
      for (uint32_t j = 0; j < TCP_OOO_BUF_ENTRIES; ++j) {
        g_tcp_flows[i].ooo_buf[j].in_use = 0;
        g_tcp_flows[i].ooo_buf[j].seq = 0;
        g_tcp_flows[i].ooo_buf[j].len = 0;
      }
      /* MSS negotiation. */
      g_tcp_flows[i].peer_mss = 0;
      g_tcp_flows[i].mss_parsed = 0;
      /* Window scaling. */
      g_tcp_flows[i].ws_parsed = 0;
      g_tcp_flows[i].peer_sack_permitted = 0;
      g_tcp_flows[i].peer_ws = 0;
      g_tcp_flows[i].our_ws = 0;
      g_tcp_flows[i].peer_window = 0;
      /* Congestion control. */
      g_tcp_flows[i].cwnd = TCP_INIT_CWND * NETWORK_TCP_MSS;
      g_tcp_flows[i].ssthresh = TCP_INIT_SSTHRESH * NETWORK_TCP_MSS;
      g_tcp_flows[i].dup_ack_count = 0;
      g_tcp_flows[i].highest_acked = 0;
      g_tcp_flows[i].in_flight = 0;
      g_tcp_flows[i].zero_window_probe = 0;
      for (uint32_t j = 0U; j < TCP_TX_WINDOW_SEGMENTS; ++j) {
        g_tcp_flows[i].tx_segments[j].seq = 0U;
        g_tcp_flows[i].tx_segments[j].len = 0U;
        g_tcp_flows[i].tx_segments[j].in_use = 0U;
        g_tcp_flows[i].tx_segments[j].pending = 0U;
        g_tcp_flows[i].tx_segments[j].retransmitted = 0U;
        g_tcp_flows[i].tx_segments[j].retries = 0U;
        g_tcp_flows[i].tx_segments[j].first_tx_ns = 0U;
        g_tcp_flows[i].tx_segments[j].last_tx_ns = 0U;
      }
      g_tcp_flows[i].srtt_ns = 0;
      g_tcp_flows[i].rttvar_ns = 0;
      /* Keepalive. */
      g_tcp_flows[i].keepalive_last_rx_ns = 0;
      g_tcp_flows[i].keepalive_last_tx_ns = 0;
      g_tcp_flows[i].keepalive_probes_sent = 0;
      g_tcp_flows[i].pending_keepalive = 0;
      g_tcp_flows[i].fin_seq = 0;
      g_tcp_flows[i].peer_fin_seq = 0;
      g_tcp_flows[i].fin_last_tx_ns = 0;
      g_tcp_flows[i].fin_retries = 0;
      g_tcp_flows[i].fin_outstanding = 0;
      g_tcp_flows[i].peer_fin_pending = 0;
      g_tcp_flows[i].peer_fin_received = 0;
      g_half_open_count++;
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

static xaios_status_t network_stack_tcp_open_unlocked(const xaios_ip_addr_t *remote_addr,
                                      uint16_t remote_port,
                                      uint16_t local_port,
                                      uint32_t *out_flow_id) {
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (remote_addr == 0 || out_flow_id == 0 || remote_port == 0U ||
      local_port == 0U ||
      (remote_addr->family != XAIOS_IP_FAMILY_V4 &&
       remote_addr->family != XAIOS_IP_FAMILY_V6))
    return XAIOS_ERR_INVALID;
  network_lock();
  uint32_t remote_address = 0U;
  uint32_t local_address = 0U;
  if (remote_addr->family == XAIOS_IP_FAMILY_V4) {
    remote_address = (uint32_t)remote_addr->addr[0] |
                     ((uint32_t)remote_addr->addr[1] << 8U) |
                     ((uint32_t)remote_addr->addr[2] << 16U) |
                     ((uint32_t)remote_addr->addr[3] << 24U);
    local_address = network_config_local_ipv4();
    if (find_flow_by_ports(local_port, remote_port, remote_address) != 0)
      goto busy;
  } else if (find_flow_by_ports_v6(local_port, remote_port, remote_addr) != 0) {
    goto busy;
  }
  network_queue_binding_t *binding = select_binding_for_flow(
      local_port, remote_port,
      remote_addr->family == XAIOS_IP_FAMILY_V4
          ? local_address : xaios_ip_addr_hash(&g_link_local_v6),
      remote_addr->family == XAIOS_IP_FAMILY_V4
          ? remote_address : xaios_ip_addr_hash(remote_addr));
  if (binding == 0) {
    status = XAIOS_ERR_NOT_FOUND;
    goto out;
  }
  network_tcp_flow_t *flow = alloc_tcp_flow(local_port, remote_port,
                                            remote_address, remote_addr);
  if (flow == 0) {
    status = XAIOS_ERR_NO_MEMORY;
    goto out;
  }
  flow->flow_id = (uint32_t)(g_next_flow_id++);
  if (flow->flow_id == 0U) {
    flow->flow_id = 1U;
    g_next_flow_id = 2U;
  }
  flow->local_port = local_port;
  flow->remote_port = remote_port;
  flow->queue_id = binding->queue_id;
  flow->cell_id = binding->cell_id;
  flow->remote_address = remote_address;
  flow->local_address = local_address;
  flow->remote_addr = *remote_addr;
  if (remote_addr->family == XAIOS_IP_FAMILY_V4) {
    flow->local_addr = xaios_ip_addr_from_ipv4(network_config_local_ipv4());
  } else if (remote_addr->addr[0] == 0xfeU &&
             (remote_addr->addr[1] & 0xc0U) == 0x80U) {
    flow->local_addr = g_link_local_v6;
  } else if (g_slaac_valid_until_ns != 0U &&
             timer_now_ns() < g_slaac_valid_until_ns) {
    /* Send from the address a router actually gave us. */
    flow->local_addr = g_slaac_v6;
  } else {
    /* No advertisement has been accepted, so assume the peer's prefix is ours
       and derive an interface identifier. That is a guess, and only right when
       the peer is on the same link. */
    xaios_ip_addr_zero(&flow->local_addr);
    flow->local_addr.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0U; i < 8U; ++i)
      flow->local_addr.addr[i] = remote_addr->addr[i];
    flow->local_addr.addr[8] = g_local_mac[0] ^ 0x02U;
    flow->local_addr.addr[9] = g_local_mac[1];
    flow->local_addr.addr[10] = g_local_mac[2];
    flow->local_addr.addr[11] = 0xffU;
    flow->local_addr.addr[12] = 0xfeU;
    flow->local_addr.addr[13] = g_local_mac[3];
    flow->local_addr.addr[14] = g_local_mac[4];
    flow->local_addr.addr[15] = g_local_mac[5];
  }
  flow->local_seq = tcp_generate_isn(flow->flow_id);
  flow->next_send_seq = flow->local_seq + 1U;
  flow->expected_seq = 0U;
  flow->window_size = (uint16_t)SOCKET_BUFFER_SIZE;
  flow->pending_syn = 1U;
  flow->last_seen_ns = timer_now_ns();
  flow->rx_buf = sockbuf_alloc();
  flow->tx_buf = sockbuf_alloc();
  if (flow->rx_buf == 0 || flow->tx_buf == 0) {
    if (g_half_open_count > 0U) --g_half_open_count;
    release_tcp_flow(flow);
    status = XAIOS_ERR_NO_MEMORY;
    goto out;
  }
  flow->state = XAIOS_NETWORK_FLOW_SYN_SENT;
  if (remote_addr->family == XAIOS_IP_FAMILY_V6) {
    uint8_t solicitation[128];
    uint64_t solicitation_length = 0U;
    if (ndp_build_neighbor_solicitation(
            solicitation, &solicitation_length, g_local_mac,
            &flow->local_addr, remote_addr) != XAIOS_OK ||
        network_device_tx(solicitation, solicitation_length) != XAIOS_OK) {
      if (g_half_open_count > 0U) --g_half_open_count;
      release_tcp_flow(flow);
      status = XAIOS_ERR_IO;
      goto out;
    }
  }
  *out_flow_id = flow->flow_id;
  klog("network: active TCP open flow=%u local=%u remote=%u\n",
       flow->flow_id, local_port, remote_port);
  status = XAIOS_OK;
  goto out;

busy:
  status = XAIOS_ERR_BUSY;
out:
  network_unlock();
  return status;
}

xaios_status_t network_stack_tcp_open(const xaios_ip_addr_t *remote_addr,
                                      uint16_t remote_port,
                                      uint16_t local_port,
                                      uint32_t *out_flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_open_unlocked(remote_addr, remote_port, local_port, out_flow_id);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_tcp_open_status_unlocked(uint32_t flow_id) {
  xaios_status_t status = XAIOS_ERR_NOT_FOUND;
  network_lock();
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id != flow_id) continue;
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
      status = XAIOS_OK;
    } else if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) {
      status = XAIOS_ERR_BUSY;
    } else {
      status = XAIOS_ERR_IO;
    }
    break;
  }
  network_unlock();
  return status;
}

xaios_status_t network_stack_tcp_open_status(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_open_status_unlocked(flow_id);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_tcp_abort_flow_unlocked(uint32_t flow_id) {
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &g_tcp_flows[i];
    if (flow->flow_id != flow_id) continue;
    if ((flow->state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         flow->state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        g_half_open_count > 0U) {
      --g_half_open_count;
    }
    ++g_tcp_closed_count;
    release_tcp_flow(flow);
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_tcp_abort_flow(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_abort_flow_unlocked(flow_id);
  network_unlock();
  return result;
}

void network_stack_init(void) {
  g_tcp_drain_cursor = 0U;
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    g_queue_bindings[i].cell_id = 0;
    g_queue_bindings[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_queue_bindings[i].core_mask = 0;
    g_queue_bindings[i].in_use = 0;
    g_queue_rings[i].queue_id = i;
    g_queue_rings[i].rx_depth = 0;
    g_queue_rings[i].tx_depth = 0;
    g_queue_rings[i].completed = 0;
    g_queue_rings[i].drops = 0;
  }

  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_FREE;
    g_tcp_flows[i].flow_id = 0;
    g_tcp_flows[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_tcp_flows[i].cell_id = 0;
    g_tcp_flows[i].local_port = 0;
    g_tcp_flows[i].remote_port = 0;
    g_tcp_flows[i].remote_address = 0;
    g_tcp_flows[i].local_address = 0;
    g_tcp_flows[i].remote_seq = 0;
    g_tcp_flows[i].local_seq = 0;
    g_tcp_flows[i].last_seen_ns = 0;
    g_tcp_flows[i].retransmits = 0;
    g_tcp_flows[i].packets_rx = 0;
    g_tcp_flows[i].packets_tx = 0;
  }

  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    g_udp_flows[i].active = 0;
    g_udp_flows[i].flow_id = 0;
    g_udp_flows[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_udp_flows[i].cell_id = 0;
    g_udp_flows[i].local_port = 0;
    g_udp_flows[i].remote_port = 0;
    g_udp_flows[i].local_address = 0;
    g_udp_flows[i].remote_address = 0;
    g_udp_flows[i].packets_rx = 0;
    g_udp_flows[i].packets_tx = 0;
    g_udp_flows[i].last_seen_ns = 0;
  }

  for (uint32_t i = 0; i < NETWORK_PACKET_DESCRIPTORS; ++i) {
    g_packet_descs[i].state = NETWORK_PACKET_FREE;
    g_packet_descs[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_packet_descs[i].cell_id = 0;
    g_packet_descs[i].src_port = 0;
    g_packet_descs[i].dst_port = 0;
    g_packet_descs[i].src_address = 0;
    g_packet_descs[i].dst_address = 0;
    g_packet_descs[i].length = 0;
    g_packet_descs[i].created_ns = 0;
  }

  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    g_listeners_ex[i].active = 0;
    g_listeners_ex[i].port = 0;
    g_listeners_ex[i].sockfd = 0;
    g_listeners_ex[i].backlog_count = 0;
  }

  g_next_flow_id = 1U;
  g_udp_tx_count = 0;
  g_udp_rx_count = 0;
  g_udp_malformed_count = 0;
  g_udp_dropped_count = 0;
  g_udp_flow_hit_count = 0;
  g_udp_expired_count = 0;
  g_tcp_handshake_count = 0;
  g_tcp_reset_count = 0;
  g_tcp_timeout_count = 0;
  g_tcp_retransmit_count = 0;
  g_tcp_established_count = 0;
  g_tcp_closed_count = 0;
  g_udp_latency_count = 0;
  g_tcp_latency_count = 0;
  g_queue_binding_count = 0;
  g_rx_packet_count = 0;
  g_tx_packet_count = 0;
  g_packet_drop_count = 0;
  g_packet_lifecycle_count = 0;
  g_queue_rx_enqueue_count = 0;
  g_queue_tx_enqueue_count = 0;
  g_queue_completion_count = 0;
  g_queue_backpressure_drop_count = 0;
  g_flow_core_mismatch_count = 0;

  for (uint32_t i = 0; i < NETWORK_MAX_SAMPLES; ++i) {
    g_udp_latency_samples[i] = 0;
    g_tcp_latency_samples[i] = 0;
  }

  klog("network: stack initialized\n");
}

xaios_status_t network_stack_bind_queue(uint32_t cell_id, uint32_t queue_id,
                                       uint32_t core_mask) {
  if (queue_id >= XAIOS_NETWORK_MAX_QUEUE_BINDINGS || core_mask == 0 ||
      cell_id == UINT32_C(0xffffffff)) {
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id) {
      return XAIOS_ERR_BUSY;
    }
  }

  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use == 0) {
      g_queue_bindings[i].in_use = 1;
      g_queue_bindings[i].cell_id = cell_id;
      g_queue_bindings[i].queue_id = queue_id;
      g_queue_bindings[i].core_mask = core_mask;
      queue_ring_reset(queue_id);
      ++g_queue_binding_count;
      klog("network: bound queue=%u cell=%u core_mask=0x%x\n", queue_id,
           cell_id, core_mask);
      return XAIOS_OK;
    }
  }

  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t network_stack_release_queue(uint32_t queue_id, uint32_t cell_id) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id &&
        g_queue_bindings[i].cell_id == cell_id) {
      g_queue_bindings[i].in_use = 0;
      g_queue_bindings[i].cell_id = 0;
      g_queue_bindings[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
      g_queue_bindings[i].core_mask = 0;
      queue_ring_reset(queue_id);
      g_queue_binding_count =
          (g_queue_binding_count == 0U) ? 0U : (g_queue_binding_count - 1U);
      klog("network: released queue=%u cell=%u\n", queue_id, cell_id);
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_process_udp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  if (frame == 0 || frame_len < 34U) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t payload_len = 0;
  uint32_t src_address = 0;
  uint32_t dst_address = 0;

  if (parse_udp(frame, frame_len, &src_port, &dst_port, &payload_len,
                &src_address, &dst_address) == 0) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t *existing =
      find_udp_flow(dst_port, src_port, dst_address, src_address);
  network_queue_binding_t *binding =
      existing != 0 ? find_binding(existing->queue_id)
                    : select_binding_for_flow(dst_port, src_port, dst_address,
                                              src_address);
  if (binding == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_udp_dropped_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_address = src_address;
  packet->dst_address = dst_address;
  network_udp_flow_t *flow =
      alloc_udp_flow(binding->queue_id, binding->cell_id, dst_port, src_port,
                     dst_address, src_address, start);
  if (flow == 0) {
    ++g_udp_dropped_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  if (flow->queue_id != binding->queue_id || flow->cell_id != binding->cell_id) {
    ++g_flow_core_mismatch_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow->packets_rx;
  ++g_udp_rx_count;
  for (uint32_t i = 0; i < 6U; ++i) {
    flow->remote_mac[i] = frame[6U + i];
  }
  flow->remote_mac_valid = 1;
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow->rx_buf != 0 && payload_len > 8) {
    const network_ip4_header_t *ip4 =
        (const network_ip4_header_t *)(frame + 14U);
    uint64_t ip_hdr_bytes = (uint64_t)(ip4->version_ihl & 0x0FU) * 4U;
    const uint8_t *udp_payload = frame + 14U + ip_hdr_bytes + 8U;
    uint32_t data_len = (uint32_t)(payload_len - 8U);
    xaios_ip_addr_t peer_addr;
    peer_addr.family = XAIOS_IP_FAMILY_V4;
    for (uint32_t i = 0; i < 4U; ++i) {
      peer_addr.addr[i] = frame[26U + i];
    }
    for (uint32_t i = 4U; i < 16U; ++i) {
      peer_addr.addr[i] = 0;
    }
    network_listener_ex_t *listener =
        find_listener_ex(dst_port, NETWORK_IP_PROTO_UDP);
    if (listener != 0) {
      if (listener->backlog_count >= NETWORK_LISTENER_BACKLOG ||
          data_len > sockbuf_available(flow->rx_buf) ||
          sockbuf_write(flow->rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow->flow_id, src_port, &peer_addr,
                                (uint16_t)data_len)) {
        ++g_udp_dropped_count;
        packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
  }
  
  packet_mark_tx(packet);
  ++flow->packets_tx;
  ++g_udp_tx_count;
  packet_mark_complete(packet);
  record_latency(g_udp_latency_samples, &g_udp_latency_count, timer_now_ns() - start);
  return XAIOS_OK;
}

/* ================================================================
 * TCP Segment Builder and Data Plane Functions
 * ================================================================ */

static xaios_status_t tcp_build_and_send_segment(
    const network_tcp_flow_t *flow,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack_val,
    uint8_t flags, uint16_t window,
    const uint8_t *payload, uint32_t payload_len) {
  uint8_t tcp_opts[40];
  uint32_t tcp_opt_len = build_tcp_options(flow, flags, tcp_opts);
  /* Align options to 4-byte boundary */
  uint32_t opt_padded = (tcp_opt_len + 3U) & ~3U;
  uint8_t tcp_hdr_bytes = (uint8_t)(20U + opt_padded);
  uint8_t data_offset_val = (uint8_t)((tcp_hdr_bytes >> 2U) << 4U);

  uint8_t frame[NETWORK_BUFFER_SIZE];
  uint64_t frame_len = 14U + 20U + tcp_hdr_bytes + payload_len;
  if (frame_len > NETWORK_BUFFER_SIZE) {
    return XAIOS_ERR_INVALID;
  }
  /* Ethernet header */
  for (uint32_t i = 0; i < 6; ++i) { frame[i] = dst_mac[i]; }
  for (uint32_t i = 0; i < 6; ++i) { frame[6U + i] = src_mac[i]; }
  write_be16(frame + 12, 0x0800U);
  /* IPv4 header */
  uint16_t ip_total = (uint16_t)(20U + tcp_hdr_bytes + payload_len);
  ipv4_build_header(frame + 14, ip_total, 6, src_ip, dst_ip);
  /* TCP header */
  uint8_t *tcp = frame + 34U;
  write_be16(tcp, src_port);
  write_be16(tcp + 2, dst_port);
  write_be32(tcp + 4, seq);
  write_be32(tcp + 8, ack_val);
  tcp[12] = data_offset_val;
  tcp[13] = flags;
  write_be16(tcp + 14, window);
  write_be16(tcp + 16, 0);
  write_be16(tcp + 18, 0); /* urgent pointer */
  /* Copy options */
  for (uint32_t i = 0; i < tcp_opt_len; ++i) {
    tcp[20U + i] = tcp_opts[i];
  }
  /* Zero padding between options and payload */
  for (uint32_t i = tcp_opt_len; i < opt_padded; ++i) {
    tcp[20U + i] = 0;
  }
  /* Copy payload */
  if (payload != 0 && payload_len > 0) {
    uint64_t data_off = 34U + tcp_hdr_bytes;
    for (uint32_t i = 0; i < payload_len; ++i) {
      frame[data_off + i] = payload[i];
    }
  }
  /* Compute TCP checksum */
  uint16_t tcp_seg_len = (uint16_t)(tcp_hdr_bytes + payload_len);
  uint16_t cksum = ipv4_pseudo_checksum(src_ip, dst_ip, 6, tcp_seg_len,
                                           tcp, (uint32_t)tcp_seg_len);
  write_be16(tcp + 16, cksum);
  return network_device_tx(frame, frame_len);
}

static int tcp_resolve_mac(uint32_t dest_ip_net_order, uint8_t out_mac[6],
                            const uint8_t local_mac[6]) {
  uint32_t next_hop = routing_lookup(dest_ip_net_order);
  if (next_hop == 0) {
    return 0; /* no route */
  }
  if (arp_cache_lookup(next_hop, out_mac) == XAIOS_OK) {
    return 1;
  }
  /* Send ARP request and retry later */
  uint8_t arp_frame[42];
  uint64_t arp_len = 0;
  if (arp_build_request(arp_frame, &arp_len, local_mac,
                         network_config_local_ipv4(), next_hop) == XAIOS_OK) {
    network_device_tx(arp_frame, arp_len);
  }
  return 0;
}

/* Build and send a TCP segment over IPv6 */
static xaios_status_t tcp_build_and_send_segment_v6(
    const network_tcp_flow_t *flow,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack_val,
    uint8_t flags, uint16_t window,
    const uint8_t *payload, uint32_t payload_len) {
  uint8_t tcp_opts[40];
  uint32_t tcp_opt_len = build_tcp_options(flow, flags, tcp_opts);
  uint32_t opt_padded = (tcp_opt_len + 3U) & ~3U;
  uint8_t tcp_hdr_bytes = (uint8_t)(20U + opt_padded);
  uint8_t data_offset_val = (uint8_t)((tcp_hdr_bytes >> 2U) << 4U);

  uint8_t frame[NETWORK_BUFFER_SIZE];
  uint64_t frame_len = 14U + 40U + tcp_hdr_bytes + payload_len;
  if (frame_len > NETWORK_BUFFER_SIZE) {
    return XAIOS_ERR_INVALID;
  }
  /* Ethernet header */
  for (uint32_t i = 0; i < 6; ++i) { frame[i] = dst_mac[i]; }
  for (uint32_t i = 0; i < 6; ++i) { frame[6U + i] = src_mac[i]; }
  write_be16(frame + 12, 0x86DDU); /* IPv6 ethertype */
  /* IPv6 header (40 bytes) */
  uint8_t *ip6 = frame + 14U;
  write_be32(ip6, 0x60000000U); /* version=6, TC=0, flow=0 */
  write_be16(ip6 + 4, (uint16_t)(tcp_hdr_bytes + payload_len)); /* payload length */
  ip6[6] = 6U; /* next header = TCP */
  ip6[7] = 64U; /* hop limit */
  for (uint32_t i = 0; i < 16; ++i) { ip6[8U + i] = src_ip->addr[i]; }
  for (uint32_t i = 0; i < 16; ++i) { ip6[24U + i] = dst_ip->addr[i]; }
  /* TCP header */
  uint8_t *tcp = frame + 54U;
  write_be16(tcp, src_port);
  write_be16(tcp + 2, dst_port);
  write_be32(tcp + 4, seq);
  write_be32(tcp + 8, ack_val);
  tcp[12] = data_offset_val;
  tcp[13] = flags;
  write_be16(tcp + 14, window);
  write_be16(tcp + 16, 0);
  write_be16(tcp + 18, 0); /* urgent */
  /* Copy options */
  for (uint32_t i = 0; i < tcp_opt_len; ++i) {
    tcp[20U + i] = tcp_opts[i];
  }
  for (uint32_t i = tcp_opt_len; i < opt_padded; ++i) {
    tcp[20U + i] = 0;
  }
  /* Copy payload */
  if (payload != 0 && payload_len > 0) {
    uint64_t data_off = 54U + tcp_hdr_bytes;
    for (uint32_t i = 0; i < payload_len; ++i) {
      frame[data_off + i] = payload[i];
    }
  }
  /* Compute TCP checksum over IPv6 pseudo-header + TCP + payload */
  uint16_t tcp_total = (uint16_t)(tcp_hdr_bytes + payload_len);
  uint16_t cksum = ipv6_pseudo_checksum(src_ip, dst_ip, 6, tcp_total,
                                           tcp, (uint32_t)tcp_total);
  write_be16(tcp + 16, cksum);
  return network_device_tx(frame, frame_len);
}

static xaios_status_t tcp_send_flow_segment(network_tcp_flow_t *flow,
                                            uint32_t seq, uint8_t flags,
                                            const uint8_t *payload,
                                            uint16_t payload_len) {
  if (flow->local_addr.family == XAIOS_IP_FAMILY_V6) {
    return tcp_build_and_send_segment_v6(
        flow, g_local_mac, flow->remote_mac, &flow->local_addr, &flow->remote_addr,
        flow->local_port, flow->remote_port, seq, flow->expected_seq, flags,
        flow->window_size, payload, payload_len);
  }
  uint32_t destination = flow->remote_address;
  uint32_t destination_be = ((destination & 0xFFU) << 24U) |
                            (((destination >> 8U) & 0xFFU) << 16U) |
                            (((destination >> 16U) & 0xFFU) << 8U) |
                            ((destination >> 24U) & 0xFFU);
  return tcp_build_and_send_segment(
      flow, g_local_mac, flow->remote_mac, network_config_local_ipv4(), destination_be,
      flow->local_port, flow->remote_port, seq, flow->expected_seq, flags,
      flow->window_size, payload, payload_len);
}

static void tcp_drain_pending(void) {
  uint32_t start_index = g_tcp_drain_cursor;
  g_tcp_drain_cursor =
      (g_tcp_drain_cursor + 1U) % NETWORK_TCP_CONNECTIONS;
  for (uint32_t offset = 0; offset < NETWORK_TCP_CONNECTIONS; ++offset) {
    uint32_t index = (start_index + offset) % NETWORK_TCP_CONNECTIONS;
    network_tcp_flow_t *flow = &g_tcp_flows[index];
    if (flow->state == XAIOS_NETWORK_FLOW_FREE ||
        flow->state == XAIOS_NETWORK_FLOW_CLOSED) {
      continue;
    }
    /* Resolve MAC if needed */
    if (!flow->remote_mac_valid) {
      if (flow->local_addr.family == XAIOS_IP_FAMILY_V6) {
        /* IPv6: use NDP cache for MAC resolution */
        if (ndp_cache_lookup(&flow->remote_addr, flow->remote_mac) != XAIOS_OK) {
          continue; /* MAC not yet resolved via NDP */
        }
        flow->remote_mac_valid = 1;
      } else {
        /* IPv4: use ARP */
        uint32_t dest_net = flow->remote_address;
        uint32_t dest_ip_be = ((dest_net & 0xFFU) << 24U) |
                               (((dest_net >> 8U) & 0xFFU) << 16U) |
                               (((dest_net >> 16U) & 0xFFU) << 8U) |
                               ((dest_net >> 24U) & 0xFFU);
        if (!tcp_resolve_mac(dest_ip_be, flow->remote_mac, g_local_mac)) {
          continue;
        }
        flow->remote_mac_valid = 1;
      }
    }
    uint64_t now_ns = timer_now_ns();
    if (flow->pending_syn != 0U) {
      xaios_status_t syn_status = tcp_send_flow_segment(
          flow, flow->local_seq, NETWORK_TCP_FLAG_SYN, 0, 0);
      if (syn_status == XAIOS_OK) {
        flow->pending_syn = 0U;
        ++flow->packets_tx;
      } else if (flow->packets_tx == 0U) {
        klog("network: active TCP flow id=%u SYN send failed status=%d\n",
             flow->flow_id, syn_status);
      }
    }
    if (flow->pending_synack != 0U) {
      xaios_status_t synack_status = tcp_send_flow_segment(
          flow, flow->local_seq,
          NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK, 0, 0);
      if (synack_status == XAIOS_OK) {
        flow->pending_synack = 0U;
        ++flow->packets_tx;
      } else if (flow->packets_tx == 0U) {
        klog("network: tcp flow id=%u SYN-ACK send failed status=%d\n",
             flow->flow_id, synack_status);
      }
    }

    if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
        flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) {
      tcp_queue_send_window(flow);
    }

    for (uint32_t tx = 0U; tx < TCP_TX_WINDOW_SEGMENTS; ++tx) {
      if (flow->tx_segments[tx].in_use == 0U ||
          flow->tx_segments[tx].pending == 0U) {
        continue;
      }
      if (tcp_send_flow_segment(flow, flow->tx_segments[tx].seq,
                                NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_PSH,
                                flow->tx_segments[tx].data,
                                flow->tx_segments[tx].len) == XAIOS_OK) {
        if (flow->tx_segments[tx].first_tx_ns == 0U) {
          flow->tx_segments[tx].first_tx_ns = now_ns;
        }
        flow->tx_segments[tx].last_tx_ns = now_ns;
        flow->tx_segments[tx].pending = 0U;
        flow->pending_ack = 0U;
        flow->pending_keepalive = 0U;
        ++flow->packets_tx;
      }
    }

    if ((flow->pending_ack != 0U || flow->pending_keepalive != 0U) &&
        tcp_tx_has_pending(flow) == 0) {
      uint32_t ack_seq = flow->pending_keepalive != 0U ?
                             flow->next_send_seq - 1U : flow->next_send_seq;
      if (tcp_send_flow_segment(flow, ack_seq, NETWORK_TCP_FLAG_ACK,
                                0, 0) == XAIOS_OK) {
        flow->pending_ack = 0U;
        flow->pending_keepalive = 0U;
        ++flow->packets_tx;
      }
    }

    if (flow->pending_fin != 0U &&
        (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0U) &&
        flow->in_flight == 0U && tcp_tx_segment_count(flow) == 0U) {
      uint32_t fin_seq = flow->fin_outstanding != 0U ?
                             flow->fin_seq : flow->next_send_seq;
      if (tcp_send_flow_segment(flow, fin_seq,
                                NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_ACK,
                                0, 0) == XAIOS_OK) {
        if (flow->fin_outstanding == 0U) {
          flow->fin_seq = fin_seq;
          flow->fin_outstanding = 1U;
          flow->fin_retries = 0U;
          flow->next_send_seq++;
          if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
            flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT;
          } else if (flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) {
            flow->state = XAIOS_NETWORK_FLOW_LAST_ACK;
          }
        }
        flow->fin_last_tx_ns = now_ns;
        flow->pending_fin = 0U;
        ++flow->packets_tx;
      }
    }
  }
}

/* ---- Listener Registry Functions ---- */

static void network_stack_register_listener_unlocked(uint16_t port, uint64_t sockfd) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (!g_listeners_ex[i].active) {
      g_listeners_ex[i].port = port;
      g_listeners_ex[i].protocol = NETWORK_IP_PROTO_TCP;
      g_listeners_ex[i].sockfd = sockfd;
      g_listeners_ex[i].active = 1;
      g_listeners_ex[i].backlog_count = 0;
      return;
    }
  }
  klog("network: listener registry full (port=%u)\n", port);
}

void network_stack_register_listener(uint16_t port, uint64_t sockfd) {
  network_lock();
  network_stack_register_listener_unlocked(port, sockfd);
  network_unlock();
}

static void network_stack_register_udp_listener_unlocked(uint16_t port, uint64_t sockfd) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (!g_listeners_ex[i].active) {
      g_listeners_ex[i].port = port;
      g_listeners_ex[i].protocol = NETWORK_IP_PROTO_UDP;
      g_listeners_ex[i].sockfd = sockfd;
      g_listeners_ex[i].active = 1;
      g_listeners_ex[i].backlog_count = 0;
      return;
    }
  }
  klog("network: UDP listener registry full (port=%u)\n", port);
}

void network_stack_register_udp_listener(uint16_t port, uint64_t sockfd) {
  network_lock();
  network_stack_register_udp_listener_unlocked(port, sockfd);
  network_unlock();
}

static void network_stack_unregister_listener_unlocked(uint16_t port) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active && g_listeners_ex[i].port == port &&
        g_listeners_ex[i].protocol == NETWORK_IP_PROTO_TCP) {
      g_listeners_ex[i].active = 0;
      g_listeners_ex[i].backlog_count = 0;
      return;
    }
  }
}

void network_stack_unregister_listener(uint16_t port) {
  network_lock();
  network_stack_unregister_listener_unlocked(port);
  network_unlock();
}

static void network_stack_unregister_udp_listener_unlocked(uint16_t port) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active && g_listeners_ex[i].port == port &&
        g_listeners_ex[i].protocol == NETWORK_IP_PROTO_UDP) {
      g_listeners_ex[i].active = 0;
      g_listeners_ex[i].backlog_count = 0;
      return;
    }
  }
}

void network_stack_unregister_udp_listener(uint16_t port) {
  network_lock();
  network_stack_unregister_udp_listener_unlocked(port);
  network_unlock();
}

int network_stack_has_listener(uint16_t port) {
  return find_listener_ex(port, NETWORK_IP_PROTO_TCP) != 0;
}

/* ---- Accept Queue Functions ---- */

static int accept_queue_enqueue(uint32_t flow_id, uint32_t peer_ip,
                                 uint16_t peer_port, uint16_t local_port,
                                 const xaios_ip_addr_t *peer_addr) {
  return listener_enqueue_backlog(local_port, flow_id, peer_ip, peer_port,
                                  peer_addr);
}

static xaios_status_t network_stack_accept_connection_unlocked(uint16_t listen_port,
                                                uint32_t *out_flow_id,
                                                uint32_t *out_peer_ip,
                                                uint16_t *out_peer_port,
                                                xaios_ip_addr_t *out_peer_addr) {
  if (!out_flow_id || !out_peer_ip || !out_peer_port || !out_peer_addr)
    return XAIOS_ERR_INVALID;
  if (listener_dequeue_backlog(listen_port, out_flow_id, out_peer_ip,
                               out_peer_port, out_peer_addr))
    return XAIOS_OK;
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_accept_connection(uint16_t listen_port,
                                                uint32_t *out_flow_id,
                                                uint32_t *out_peer_ip,
                                                uint16_t *out_peer_port,
                                                xaios_ip_addr_t *out_peer_addr) {
  network_lock();
  xaios_status_t result = network_stack_accept_connection_unlocked(listen_port, out_flow_id, out_peer_ip, out_peer_port, out_peer_addr);
  network_unlock();
  return result;
}

/* ---- Socket-to-Flow Mapping Functions ---- */

static void network_stack_map_socket_unlocked(uint64_t sockfd, uint32_t flow_id,
                                uint8_t protocol) {
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0 &&
        g_socket_flow_map[i].sockfd == sockfd) {
      g_socket_flow_map[i].flow_id = flow_id;
      g_socket_flow_map[i].protocol = protocol;
      return;
    }
  }
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active == 0) {
      g_socket_flow_map[i].sockfd = sockfd;
      g_socket_flow_map[i].flow_id = flow_id;
      g_socket_flow_map[i].protocol = protocol;
      g_socket_flow_map[i].active = 1;
      return;
    }
  }
}

void network_stack_map_socket(uint64_t sockfd, uint32_t flow_id,
                                uint8_t protocol) {
  network_lock();
  network_stack_map_socket_unlocked(sockfd, flow_id, protocol);
  network_unlock();
}

static socket_flow_mapping_t *network_stack_get_socket_mapping_unlocked(uint64_t sockfd) {
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0 &&
        g_socket_flow_map[i].sockfd == sockfd) {
      return &g_socket_flow_map[i];
    }
  }
  return 0;
}

socket_flow_mapping_t * network_stack_get_socket_mapping(uint64_t sockfd) {
  network_lock();
  socket_flow_mapping_t * result = network_stack_get_socket_mapping_unlocked(sockfd);
  network_unlock();
  return result;
}

static void network_stack_unmap_socket_unlocked(uint64_t sockfd) {
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0 &&
        g_socket_flow_map[i].sockfd == sockfd) {
      g_socket_flow_map[i].active = 0;
      return;
    }
  }
}

void network_stack_unmap_socket(uint64_t sockfd) {
  network_lock();
  network_stack_unmap_socket_unlocked(sockfd);
  network_unlock();
}

/* ---- TCP Send / Close API ---- */

static xaios_status_t network_stack_tcp_send_unlocked(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  if (data == 0 || bytes_written == 0 || len == 0U) return XAIOS_ERR_INVALID;
  *bytes_written = 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id &&
        (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT)) {
      if (g_tcp_flows[i].tx_buf == 0) {
        return XAIOS_ERR_INVALID;
      }
      *bytes_written = sockbuf_write(g_tcp_flows[i].tx_buf, data, len);
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_tcp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  network_lock();
  xaios_status_t result = network_stack_tcp_send_unlocked(flow_id, data, len, bytes_written);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_tcp_close_flow_unlocked(uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id) {
      if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV ||
          g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) {
        return network_stack_tcp_abort_flow(flow_id);
      }
      g_tcp_flows[i].close_requested = 1;
      g_tcp_flows[i].pending_fin = 1;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_tcp_close_flow(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_close_flow_unlocked(flow_id);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_udp_send_unlocked(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  if (data == 0 || bytes_written == 0 || len == 0U) return XAIOS_ERR_INVALID;
  *bytes_written = 0U;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].flow_id == flow_id && g_udp_flows[i].active != 0) {
      uint8_t frame[NETWORK_BUFFER_SIZE];
      if (g_udp_flows[i].remote_addr.family == XAIOS_IP_FAMILY_V6) {
        if (len > NETWORK_BUFFER_SIZE - 62U) return XAIOS_ERR_INVALID;
        uint16_t udp_len = (uint16_t)(8U + len);
        uint64_t frame_len = 14U + 40U + (uint64_t)udp_len;
        if (g_udp_flows[i].remote_mac_valid == 0U) return XAIOS_ERR_BUSY;
        for (uint32_t j = 0; j < 6U; ++j) {
          frame[j] = g_udp_flows[i].remote_mac[j];
          frame[6U + j] = g_local_mac[j];
        }
        write_be16(frame + 12U, NETWORK_ETHERTYPE_IPV6);
        uint8_t *ip6 = frame + 14U;
        for (uint32_t j = 0; j < 40U; ++j) ip6[j] = 0U;
        ip6[0] = 0x60U;
        write_be16(ip6 + 4U, udp_len);
        ip6[6] = NETWORK_IP_PROTO_UDP;
        ip6[7] = 64U;
        for (uint32_t j = 0; j < 16U; ++j) {
          ip6[8U + j] = g_udp_flows[i].local_addr.addr[j];
          ip6[24U + j] = g_udp_flows[i].remote_addr.addr[j];
        }
        uint8_t *udp = ip6 + 40U;
        write_be16(udp, g_udp_flows[i].local_port);
        write_be16(udp + 2U, g_udp_flows[i].remote_port);
        write_be16(udp + 4U, udp_len);
        write_be16(udp + 6U, 0U);
        for (uint32_t j = 0; j < len; ++j) udp[8U + j] = data[j];
        uint16_t checksum = ipv6_pseudo_checksum(
            &g_udp_flows[i].local_addr, &g_udp_flows[i].remote_addr,
            NETWORK_IP_PROTO_UDP, udp_len, udp, udp_len);
        write_be16(udp + 6U, checksum == 0U ? UINT16_MAX : checksum);
        *bytes_written = len;
        return network_device_tx(frame, frame_len);
      }

      /* Build Ethernet + IPv4 + UDP frame. */
      if (len > NETWORK_BUFFER_SIZE - 42U) return XAIOS_ERR_INVALID;
      uint16_t udp_len = (uint16_t)(8U + len);
      uint16_t ip_total = (uint16_t)(20U + udp_len);
      uint64_t frame_len = 14U + (uint64_t)ip_total;
      if (frame_len > NETWORK_BUFFER_SIZE) {
        return XAIOS_ERR_INVALID;
      }
      uint32_t dst_ip_be = ((g_udp_flows[i].remote_address & 0xFFU) << 24U) |
                            (((g_udp_flows[i].remote_address >> 8U) & 0xFFU) << 16U) |
                            (((g_udp_flows[i].remote_address >> 16U) & 0xFFU) << 8U) |
                            ((g_udp_flows[i].remote_address >> 24U) & 0xFFU);
      uint8_t dst_mac[6];
      if (g_udp_flows[i].remote_mac_valid != 0) {
        for (uint32_t j = 0; j < 6U; ++j) {
          dst_mac[j] = g_udp_flows[i].remote_mac[j];
        }
      } else if (!tcp_resolve_mac(dst_ip_be, dst_mac, g_local_mac)) {
        return XAIOS_ERR_BUSY;
      }
      /* Ethernet */
      for (uint32_t j = 0; j < 6; ++j) { frame[j] = dst_mac[j]; }
      for (uint32_t j = 0; j < 6; ++j) { frame[6U + j] = g_local_mac[j]; }
      write_be16(frame + 12, 0x0800U);
      /* IPv4 */
      ipv4_build_header(frame + 14, ip_total, 17,
                         network_config_local_ipv4(), dst_ip_be);
      /* UDP header */
      uint8_t *udp = frame + 34U;
      write_be16(udp, g_udp_flows[i].local_port);
      write_be16(udp + 2, g_udp_flows[i].remote_port);
      write_be16(udp + 4, udp_len);
      write_be16(udp + 6, 0U);
      /* Payload */
      for (uint32_t j = 0; j < len; ++j) {
        frame[42U + j] = data[j];
      }
      uint16_t checksum = ipv4_pseudo_checksum(
          network_config_local_ipv4(), dst_ip_be, NETWORK_IP_PROTO_UDP, udp_len,
          udp, udp_len);
      write_be16(udp + 6U, checksum == 0U ? UINT16_MAX : checksum);
      *bytes_written = len;
      return network_device_tx(frame, frame_len);
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_udp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  network_lock();
  xaios_status_t result = network_stack_udp_send_unlocked(flow_id, data, len, bytes_written);
  network_unlock();
  return result;
}

static uint32_t network_stack_tcp_recv_unlocked(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size) {
  if (buffer == 0 || buffer_size == 0U) return 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id &&
        g_tcp_flows[i].rx_buf != 0) {
      uint32_t bytes_read = sockbuf_read(g_tcp_flows[i].rx_buf,
                                            buffer, buffer_size);
      g_tcp_flows[i].window_size =
          (uint16_t)sockbuf_available(g_tcp_flows[i].rx_buf);
      if (bytes_read != 0U) {
        g_tcp_flows[i].pending_ack = 1;
      }
      return bytes_read;
    }
  }
  return 0;
}

uint32_t network_stack_tcp_recv(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size) {
  network_lock();
  uint32_t result = network_stack_tcp_recv_unlocked(flow_id, buffer, buffer_size);
  network_unlock();
  return result;
}

static int network_stack_tcp_peer_closed_unlocked(uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id) {
      return g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
             g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSED ||
             g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_TIME_WAIT;
    }
  }
  return 1;
}

int network_stack_tcp_peer_closed(uint32_t flow_id) {
  network_lock();
  int result = network_stack_tcp_peer_closed_unlocked(flow_id);
  network_unlock();
  return result;
}

static uint32_t network_stack_udp_recv_unlocked(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id) {
  network_listener_ex_t *listener =
      find_listener_by_socket(sockfd, NETWORK_IP_PROTO_UDP);
  if (listener == 0 || listener->backlog_count == 0 || buffer == 0 ||
      buffer_size == 0) {
    return 0;
  }

  listener_accept_entry_t entry = listener->backlog[0];
  for (uint32_t i = 1; i < listener->backlog_count; ++i) {
    listener->backlog[i - 1U] = listener->backlog[i];
  }
  --listener->backlog_count;

  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    network_udp_flow_t *udp_flow = &g_udp_flows[i];
    if (udp_flow->active != 0 && udp_flow->flow_id == entry.flow_id &&
        udp_flow->rx_buf != 0) {
      uint32_t read_limit = entry.payload_len;
      if (read_limit > buffer_size) {
        read_limit = buffer_size;
      }
      uint32_t bytes_read = sockbuf_read(udp_flow->rx_buf, buffer, read_limit);
      if (entry.payload_len > bytes_read) {
        sockbuf_discard(udp_flow->rx_buf,
                        (uint32_t)entry.payload_len - bytes_read);
      }
      if (source_addr != 0) {
        *source_addr = entry.peer_addr;
      }
      if (source_port != 0) {
        *source_port = entry.peer_port;
      }
      if (flow_id != 0) {
        *flow_id = entry.flow_id;
      }
      network_stack_map_socket(sockfd, entry.flow_id, NETWORK_IP_PROTO_UDP);
      return bytes_read;
    }
  }
  return 0;
}

uint32_t network_stack_udp_recv(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id) {
  network_lock();
  uint32_t result = network_stack_udp_recv_unlocked(sockfd, buffer, buffer_size, source_addr, source_port, flow_id);
  network_unlock();
  return result;
}

xaios_status_t network_stack_process_tcp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  if (frame == 0 || frame_len < 54U) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t flags = 0;

  if (parse_tcp(frame, frame_len, &src_port, &dst_port, &seq, &ack, &flags) ==
      0) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  const network_ip4_header_t *ip =
      (const network_ip4_header_t *)(frame + 14U);
  uint32_t parsed_ip_header_bytes = (uint32_t)(ip->version_ihl & 0x0fU) * 4U;
  const uint8_t *parsed_tcp_header = frame + 14U + parsed_ip_header_bytes;
  uint16_t peer_window_raw = read_u16_be(parsed_tcp_header + 14U);
  uint32_t remote_address = ip4_addr_host_order(ip->source);
  uint32_t local_address = ip4_addr_host_order(ip->destination);

  network_tcp_flow_t *flow = find_flow_by_ports(dst_port, src_port, remote_address);
  network_queue_binding_t *binding =
      flow != 0 ? find_binding(flow->queue_id)
                : select_binding_for_flow(dst_port, src_port, local_address,
                                          remote_address);
  if (binding == 0) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_tcp_reset_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_address = remote_address;
  packet->dst_address = local_address;

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_SENT &&
      (flags & (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK)) ==
          (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK) &&
      (flags & (NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_RST)) == 0U) {
    if (ack != flow->next_send_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t tcp_header_bytes = (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
    tcp_parsed_options_t options;
    if (!parse_tcp_options(parsed_tcp_header, tcp_header_bytes, &options)) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->remote_seq = seq;
    flow->expected_seq = seq + 1U;
    flow->local_seq = ack;
    flow->next_send_seq = ack;
    flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_MSS
                         ? options.mss
                         : NETWORK_TCP_MSS;
    flow->mss_parsed = 1U;
    flow->peer_ws = options.window_scale;
    flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
    flow->peer_sack_permitted = options.sack_permitted;
    flow->peer_window = tcp_scaled_window(peer_window_raw, flow->peer_ws);
    for (uint32_t i = 0U; i < 6U; ++i) flow->remote_mac[i] = frame[6U + i];
    flow->remote_mac_valid = 1U;
    flow->pending_syn = 0U;
    flow->pending_ack = 1U;
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->last_seen_ns = start;
    flow->keepalive_last_rx_ns = start;
    if (g_half_open_count > 0U) --g_half_open_count;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                   timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      xaios_network_flow_state_t prev_state = flow->state;
      ++g_tcp_reset_count;
      ++g_tcp_closed_count;
      if ((prev_state == XAIOS_NETWORK_FLOW_SYN_RECV ||
           prev_state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
          g_half_open_count > 0) {
        g_half_open_count--;
      }
      release_tcp_flow(flow);
    }
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 &&
      ((flags & NETWORK_TCP_FLAG_SYN) == 0U ||
       (flags & (NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_FIN)) != 0U)) {
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow(dst_port, src_port, remote_address, 0);
    if (flow == 0) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = (uint32_t)(g_next_flow_id++);
    if (flow->flow_id == 0U) {
      flow->flow_id = 1U;
      g_next_flow_id = 2U;
    }
    flow->local_port = dst_port;
    flow->remote_port = src_port;
    flow->queue_id = binding->queue_id;
    flow->cell_id = binding->cell_id;
    flow->remote_address = remote_address;
    flow->local_address = local_address;
    flow->remote_seq = seq;
    /* Data plane: set expected_seq (SYN consumes 1 seq number) */
    flow->expected_seq = seq + 1U;
    /* Generate ISN from timer and flow ID */
    flow->local_seq = tcp_generate_isn(flow->flow_id);
    flow->next_send_seq = flow->local_seq + 1U;
    flow->window_size = (uint16_t)SOCKET_BUFFER_SIZE;
    flow->pending_synack = 1;
    flow->pending_fin = 0;
    flow->pending_ack = 0;
    flow->close_requested = 0;
    for (uint32_t i = 0; i < 6U; ++i) {
      flow->remote_mac[i] = frame[6U + i];
    }
    flow->remote_mac_valid = 1;
    /* Allocate socket buffers */
    flow->rx_buf = sockbuf_alloc();
    flow->tx_buf = sockbuf_alloc();
    if (flow->rx_buf == 0 || flow->tx_buf == 0) {
      if (g_half_open_count > 0U) --g_half_open_count;
      release_tcp_flow(flow);
      packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->last_seen_ns = start;
    flow->state = XAIOS_NETWORK_FLOW_SYN_RECV;
    flow->retransmits = 0;
    flow->packets_rx = 1;
    flow->packets_tx = 0;

    /* Parse MSS and window scale from the peer SYN. */
    {
      const network_ip4_header_t *iph4 =
          (const network_ip4_header_t *)(frame + 14U);
      uint32_t ip_hdr_b = (uint32_t)(iph4->version_ihl & 0x0fU) * 4U;
      const uint8_t *thdr = frame + 14U + ip_hdr_b;
      uint32_t thdr_b = (uint32_t)(thdr[12] >> 4U) * 4U;
      tcp_parsed_options_t options;
      if (!parse_tcp_options(thdr, thdr_b, &options)) {
        release_tcp_flow(flow);
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_MSS ?
                           options.mss : NETWORK_TCP_MSS;
      flow->mss_parsed = 1;
      flow->peer_ws = options.window_scale;
      flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
      flow->peer_sack_permitted = options.sack_permitted;
      flow->our_ws = 0;
      flow->peer_window = peer_window_raw;
    }

    ++g_tcp_handshake_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack != flow->next_send_seq || seq != flow->expected_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t peer_ip_be = ((remote_address & 0xFFU) << 24U) |
                           (((remote_address >> 8U) & 0xFFU) << 16U) |
                           (((remote_address >> 16U) & 0xFFU) << 8U) |
                           ((remote_address >> 24U) & 0xFFU);
    if (g_half_open_count > 0U) --g_half_open_count;
    if (!accept_queue_enqueue(flow->flow_id, peer_ip_be, src_port, dst_port,
                              0)) {
      release_tcp_flow(flow);
      packet_mark_dropped(packet);
      return XAIOS_ERR_BUSY;
    }
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->pending_synack = 0;
    flow->local_seq = ack;
    flow->next_send_seq = ack; /* peer confirmed our ISN+1 */
    flow->last_seen_ns = start;
    flow->keepalive_last_rx_ns = start;
    flow->peer_window = tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
                     flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
                     flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
                     flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2 ||
                     flow->state == XAIOS_NETWORK_FLOW_LAST_ACK ||
                     flow->state == XAIOS_NETWORK_FLOW_TIME_WAIT)) {
    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U &&
        tcp_seq_after(ack, flow->next_send_seq)) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->last_seen_ns = start;
    flow->peer_window = tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;

    /* Extract TCP payload */
    const network_ip4_header_t *iph =
        (const network_ip4_header_t *)(frame + 14U);
    uint64_t ip_hdr_bytes = (uint64_t)(iph->version_ihl & 0x0FU) * 4U;
    uint16_t ip_total = read_u16_be((const uint8_t *)&iph->total_length);
    const uint8_t *tcp_hdr = frame + 14U + ip_hdr_bytes;
    uint64_t tcp_hdr_bytes = (uint64_t)(tcp_hdr[12] >> 4U) * 4U;
    uint32_t payload_len = (uint32_t)(ip_total) - (uint32_t)ip_hdr_bytes -
                            (uint32_t)tcp_hdr_bytes;

    if (payload_len > NETWORK_TCP_IPV4_RX_MAX) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (payload_len > 0U && flow->rx_buf != 0) {
      const uint8_t *payload = tcp_hdr + tcp_hdr_bytes;
      uint32_t payload_seq = seq;
      uint32_t deliver_len = payload_len;
      if (tcp_seq_before(payload_seq, flow->expected_seq)) {
        uint32_t overlap = flow->expected_seq - payload_seq;
        if (overlap >= deliver_len) deliver_len = 0U;
        else {
          payload += overlap;
          payload_seq += overlap;
          deliver_len -= overlap;
        }
      }
      if (deliver_len != 0U && payload_seq == flow->expected_seq) {
        uint32_t written = sockbuf_write(flow->rx_buf, payload, deliver_len);
        flow->expected_seq += written;
        flow->pending_ack = 1U;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        /* Drain any newly contiguous out-of-order data. */
        ooo_buffer_drain(flow);
      } else if (deliver_len != 0U &&
                 tcp_seq_after(payload_seq, flow->expected_seq)) {
        /* Retain future data for bounded reordering recovery. */
        ooo_buffer_store(flow, payload_seq, payload, deliver_len,
                         flow->expected_seq);
      } else {
        flow->pending_ack = 1U;
      }
    }

    if ((flags & NETWORK_TCP_FLAG_FIN) != 0U) {
      uint32_t fin_seq = seq + payload_len;
      flow->pending_ack = 1U;
      if (!tcp_seq_before(fin_seq, flow->expected_seq)) {
        flow->peer_fin_seq = fin_seq;
        flow->peer_fin_pending = 1U;
        tcp_accept_peer_fin(flow, start);
      }
    }
    flow->keepalive_last_rx_ns = start;
    flow->keepalive_probes_sent = 0U;
    flow->pending_keepalive = 0U;
    tcp_accept_peer_fin(flow, start);

    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U) {
      tcp_parsed_options_t options;
      if (!parse_tcp_options(tcp_hdr, (uint32_t)tcp_hdr_bytes, &options)) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      (void)tcp_apply_sack_blocks(flow, &options);
      int ack_result = acknowledge_tcp_flow(flow, ack, start);
      if (ack_result < 0) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      if (ack_result > 0) {
        packet_mark_tx(packet);
        packet_mark_complete(packet);
        record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                       timer_now_ns() - start);
        return XAIOS_OK;
      }
    }

    /* If close was requested and all data sent, mark FIN pending */
    if (flow->close_requested && flow->fin_outstanding == 0U &&
        (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0)) {
      flow->pending_fin = 1;
    }

    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  ++g_tcp_reset_count;
  packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
}

xaios_status_t network_stack_process_udp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 62U) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t payload_len = 0;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  xaios_ip_addr_zero(&src_addr);
  xaios_ip_addr_zero(&dst_addr);

  if (parse_udp_v6(frame, frame_len, &src_port, &dst_port, &payload_len,
                   &src_addr, &dst_addr) == 0) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t *existing =
      find_udp_flow_v6(dst_port, src_port, &dst_addr, &src_addr);
  network_queue_binding_t *binding =
      existing != 0 ? find_binding(existing->queue_id)
                    : select_binding_for_flow(dst_port, src_port,
                                              xaios_ip_addr_hash(&dst_addr),
                                              xaios_ip_addr_hash(&src_addr));
  if (binding == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_udp_dropped_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_addr = src_addr;
  packet->dst_addr = dst_addr;
  /* Also set legacy fields for backward compat */
  if (src_addr.family == XAIOS_IP_FAMILY_V4) {
    packet->src_address = xaios_ip_addr_to_ipv4(&src_addr);
    packet->dst_address = xaios_ip_addr_to_ipv4(&dst_addr);
  }

  network_udp_flow_t *flow =
      alloc_udp_flow(binding->queue_id, binding->cell_id, dst_port, src_port,
                     packet->dst_address, packet->src_address, start);
  if (flow == 0) {
    ++g_udp_dropped_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* Set IPv6 address fields on the flow */
  flow->local_addr = dst_addr;
  flow->remote_addr = src_addr;

  if (flow->queue_id != binding->queue_id || flow->cell_id != binding->cell_id) {
    ++g_flow_core_mismatch_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow->packets_rx;
  ++g_udp_rx_count;
  ++g_ipv6_rx_count;
  for (uint32_t i = 0; i < 6U; ++i) {
    flow->remote_mac[i] = frame[6U + i];
  }
  flow->remote_mac_valid = 1;
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow->rx_buf != 0 && payload_len > 8) {
    /* IPv6 header is 40 bytes at offset 14 */
    const uint8_t *udp_payload = frame + 14U + 40U + 8U;
    uint32_t data_len = (uint32_t)(payload_len - 8U);
    network_listener_ex_t *listener =
        find_listener_ex(dst_port, NETWORK_IP_PROTO_UDP);
    if (listener != 0) {
      if (listener->backlog_count >= NETWORK_LISTENER_BACKLOG ||
          data_len > sockbuf_available(flow->rx_buf) ||
          sockbuf_write(flow->rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow->flow_id, src_port, &src_addr,
                                (uint16_t)data_len)) {
        ++g_udp_dropped_count;
        packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
  }
  
  packet_mark_tx(packet);
  ++flow->packets_tx;
  ++g_udp_tx_count;
  packet_mark_complete(packet);
  record_latency(g_udp_latency_samples, &g_udp_latency_count,
                timer_now_ns() - start);
  return XAIOS_OK;
}

xaios_status_t network_stack_process_tcp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 74U) { /* 14 + 40 + 20 minimum */
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq = 0;
  uint32_t ack_v = 0;
  uint8_t flags = 0;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  xaios_ip_addr_zero(&src_addr);
  xaios_ip_addr_zero(&dst_addr);

  if (parse_tcp_v6(frame, frame_len, &src_port, &dst_port, &seq, &ack_v,
                   &flags, &src_addr, &dst_addr) == 0) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *parsed_tcp_header = frame + 14U + XAIOS_IPV6_HEADER_SIZE;
  uint16_t peer_window_raw = read_u16_be(parsed_tcp_header + 14U);

  network_tcp_flow_t *flow =
      find_flow_by_ports_v6(dst_port, src_port, &src_addr);
  network_queue_binding_t *binding =
      flow != 0 ? find_binding(flow->queue_id)
                : select_binding_for_flow(dst_port, src_port,
                                          xaios_ip_addr_hash(&dst_addr),
                                          xaios_ip_addr_hash(&src_addr));
  if (binding == 0) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_tcp_reset_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_addr = src_addr;
  packet->dst_addr = dst_addr;

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_SENT &&
      (flags & (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK)) ==
          (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK) &&
      (flags & (NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_RST)) == 0U) {
    if (ack_v != flow->next_send_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t tcp_header_bytes =
        (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
    tcp_parsed_options_t options;
    if (!parse_tcp_options(parsed_tcp_header, tcp_header_bytes, &options)) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->remote_seq = seq;
    flow->expected_seq = seq + 1U;
    flow->local_seq = ack_v;
    flow->next_send_seq = ack_v;
    flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_IPV6_MSS
                         ? options.mss
                         : NETWORK_TCP_IPV6_MSS;
    flow->mss_parsed = 1U;
    flow->peer_ws = options.window_scale;
    flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
    flow->peer_sack_permitted = options.sack_permitted;
    flow->peer_window = tcp_scaled_window(peer_window_raw, flow->peer_ws);
    for (uint32_t i = 0U; i < 6U; ++i) flow->remote_mac[i] = frame[6U + i];
    flow->remote_mac_valid = 1U;
    flow->pending_syn = 0U;
    flow->pending_ack = 1U;
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->last_seen_ns = start;
    flow->keepalive_last_rx_ns = start;
    if (g_half_open_count > 0U) --g_half_open_count;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    ++g_ipv6_rx_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                   timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      xaios_network_flow_state_t prev_state = flow->state;
      ++g_tcp_reset_count;
      ++g_tcp_closed_count;
      if (prev_state == XAIOS_NETWORK_FLOW_SYN_RECV && g_half_open_count > 0) {
        g_half_open_count--;
      }
      release_tcp_flow(flow);
    }
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 &&
      ((flags & NETWORK_TCP_FLAG_SYN) == 0U ||
       (flags & (NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_FIN)) != 0U)) {
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow(dst_port, src_port, 0, &src_addr);
    if (flow == 0) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = (uint32_t)(g_next_flow_id++);
    if (flow->flow_id == 0U) {
      flow->flow_id = 1U;
      g_next_flow_id = 2U;
    }
    flow->local_port = dst_port;
    flow->remote_port = src_port;
    flow->queue_id = binding->queue_id;
    flow->cell_id = binding->cell_id;
    flow->remote_addr = src_addr;
    flow->local_addr = dst_addr;
    flow->remote_seq = seq;
    flow->expected_seq = seq + 1U;
    flow->local_seq = tcp_generate_isn(flow->flow_id);
    flow->next_send_seq = flow->local_seq + 1U;
    flow->window_size = (uint16_t)SOCKET_BUFFER_SIZE;
    flow->pending_synack = 1;
    flow->pending_fin = 0;
    flow->pending_ack = 0;
    flow->close_requested = 0;
    for (uint32_t i = 0; i < 6U; ++i) {
      flow->remote_mac[i] = frame[6U + i];
    }
    flow->remote_mac_valid = 1;
    flow->rx_buf = sockbuf_alloc();
    flow->tx_buf = sockbuf_alloc();
    if (flow->rx_buf == 0 || flow->tx_buf == 0) {
      if (g_half_open_count > 0U) --g_half_open_count;
      release_tcp_flow(flow);
      packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->last_seen_ns = start;
    flow->state = XAIOS_NETWORK_FLOW_SYN_RECV;
    flow->retransmits = 0;
    flow->packets_rx = 1;
    flow->packets_tx = 0;
    {
      uint32_t header_bytes = (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
      tcp_parsed_options_t options;
      if (!parse_tcp_options(parsed_tcp_header, header_bytes, &options)) {
        release_tcp_flow(flow);
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_IPV6_MSS ?
                           options.mss : NETWORK_TCP_IPV6_MSS;
      flow->mss_parsed = 1U;
      flow->peer_ws = options.window_scale;
      flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
      flow->peer_sack_permitted = options.sack_permitted;
      flow->our_ws = 0U;
      flow->peer_window = peer_window_raw;
    }
    ++g_tcp_handshake_count;
    ++g_ipv6_rx_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack_v != flow->next_send_seq || seq != flow->expected_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (g_half_open_count > 0U) --g_half_open_count;
    if (!accept_queue_enqueue(flow->flow_id, 0, src_port, dst_port,
                              &src_addr)) {
      release_tcp_flow(flow);
      packet_mark_dropped(packet);
      return XAIOS_ERR_BUSY;
    }
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->pending_synack = 0;
    flow->local_seq = ack_v;
    flow->next_send_seq = ack_v;
    flow->last_seen_ns = start;
    flow->keepalive_last_rx_ns = start;
    flow->peer_window = tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
                     flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
                     flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
                     flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2 ||
                     flow->state == XAIOS_NETWORK_FLOW_LAST_ACK ||
                     flow->state == XAIOS_NETWORK_FLOW_TIME_WAIT)) {
    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U &&
        tcp_seq_after(ack_v, flow->next_send_seq)) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->last_seen_ns = start;
    flow->peer_window = tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;

    /* Extract TCP payload from IPv6 frame */
    /* IPv6 header is 40 bytes at offset 14, TCP header starts after that */
    const uint8_t *ip6 = frame + 14U;
    const uint8_t *tcp_hdr = ip6 + 40U;
    uint64_t tcp_hdr_bytes = (uint64_t)(tcp_hdr[12] >> 4U) * 4U;
    uint16_t ip6_payload_len = read_u16_be(ip6 + 4U);
    uint32_t payload_len_v6 = (uint32_t)ip6_payload_len - (uint32_t)tcp_hdr_bytes;

    if (payload_len_v6 > NETWORK_TCP_IPV6_RX_MAX) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (payload_len_v6 > 0U && flow->rx_buf != 0) {
      const uint8_t *payload = tcp_hdr + tcp_hdr_bytes;
      uint32_t payload_seq = seq;
      uint32_t deliver_len = payload_len_v6;
      if (tcp_seq_before(payload_seq, flow->expected_seq)) {
        uint32_t overlap = flow->expected_seq - payload_seq;
        if (overlap >= deliver_len) deliver_len = 0U;
        else {
          payload += overlap;
          payload_seq += overlap;
          deliver_len -= overlap;
        }
      }
      if (deliver_len != 0U && payload_seq == flow->expected_seq) {
        uint32_t written = sockbuf_write(flow->rx_buf, payload, deliver_len);
        flow->expected_seq += written;
        flow->pending_ack = 1U;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        ooo_buffer_drain(flow);
      } else if (deliver_len != 0U &&
                 tcp_seq_after(payload_seq, flow->expected_seq)) {
        ooo_buffer_store(flow, payload_seq, payload, deliver_len,
                         flow->expected_seq);
      } else {
        flow->pending_ack = 1U;
      }
    }

    if ((flags & NETWORK_TCP_FLAG_FIN) != 0U) {
      uint32_t fin_seq = seq + payload_len_v6;
      flow->pending_ack = 1U;
      if (!tcp_seq_before(fin_seq, flow->expected_seq)) {
        flow->peer_fin_seq = fin_seq;
        flow->peer_fin_pending = 1U;
        tcp_accept_peer_fin(flow, start);
      }
    }
    flow->keepalive_last_rx_ns = start;
    flow->keepalive_probes_sent = 0U;
    flow->pending_keepalive = 0U;
    tcp_accept_peer_fin(flow, start);

    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U) {
      tcp_parsed_options_t options;
      if (!parse_tcp_options(tcp_hdr, (uint32_t)tcp_hdr_bytes, &options)) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      (void)tcp_apply_sack_blocks(flow, &options);
      int ack_result = acknowledge_tcp_flow(flow, ack_v, start);
      if (ack_result < 0) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      if (ack_result > 0) {
        packet_mark_tx(packet);
        packet_mark_complete(packet);
        record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                       timer_now_ns() - start);
        return XAIOS_OK;
      }
    }

    if (flow->close_requested && flow->fin_outstanding == 0U &&
        (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0)) {
      flow->pending_fin = 1;
    }

    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  ++g_tcp_reset_count;
  packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
}

uint64_t network_stack_expire_udp_flows(uint64_t now_ns) {
  uint64_t expired = 0;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        now_ns > g_udp_flows[i].last_seen_ns &&
        now_ns - g_udp_flows[i].last_seen_ns >= NETWORK_UDP_IDLE_TIMEOUT_NS) {
      uint32_t flow_id = g_udp_flows[i].flow_id;
      uint32_t queue_id = g_udp_flows[i].queue_id;
      uint32_t cell_id = g_udp_flows[i].cell_id;
      uint64_t packets_rx = g_udp_flows[i].packets_rx;
      uint64_t packets_tx = g_udp_flows[i].packets_tx;
      release_udp_flow(&g_udp_flows[i]);
      ++g_udp_expired_count;
      ++expired;
      klog("network: udp flow id=%u expired queue=%u cell=%u rx=%lu tx=%lu\n",
           flow_id, queue_id, cell_id, packets_rx, packets_tx);
    }
  }
  return expired;
}

uint64_t network_stack_retransmit_tcp_flows(uint64_t now_ns) {
  uint64_t retransmitted = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if ((g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        now_ns > g_tcp_flows[i].last_seen_ns &&
        now_ns - g_tcp_flows[i].last_seen_ns >= NETWORK_TCP_RETRANSMIT_NS &&
        g_tcp_flows[i].retransmits < NETWORK_TCP_MAX_RETRANSMITS) {
      ++g_tcp_flows[i].retransmits;
      ++g_tcp_flows[i].packets_tx;
      g_tcp_flows[i].last_seen_ns = now_ns;
      if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT)
        g_tcp_flows[i].pending_syn = 1U;
      else
        g_tcp_flows[i].pending_synack = 1U;
      ++g_tcp_retransmit_count;
      ++retransmitted;
      klog("network: tcp flow id=%u retransmit=%u queue=%u cell=%u\n",
           g_tcp_flows[i].flow_id, g_tcp_flows[i].retransmits,
           g_tcp_flows[i].queue_id, g_tcp_flows[i].cell_id);
    }
  }
  return retransmitted;
}

uint64_t network_stack_expire_tcp_flows(uint64_t now_ns) {
  uint64_t expired = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &g_tcp_flows[i];

    /* TIME_WAIT expires after 2MSL and returns the slot to the pool. */
    if (flow->state == XAIOS_NETWORK_FLOW_TIME_WAIT &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= UINT64_C(60000000000)) {
      ++g_tcp_closed_count;
      ++expired;
      klog("network: tcp flow id=%u TIME_WAIT expired\n", flow->flow_id);
      release_tcp_flow(flow);
      continue;
    }

    /* Closing states cannot hold a finite flow slot indefinitely. */
    if ((flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
         flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2 ||
         flow->state == XAIOS_NETWORK_FLOW_LAST_ACK) &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= UINT64_C(60000000000)) {
      ++g_tcp_closed_count;
      ++expired;
      klog("network: tcp flow id=%u close timeout\n", flow->flow_id);
      release_tcp_flow(flow);
      continue;
    }

    /* Passive and active handshake timeout. */
    if ((flow->state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         flow->state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= NETWORK_TCP_SYN_TIMEOUT_NS) {
      ++g_tcp_timeout_count;
      ++g_tcp_closed_count;
      ++g_packet_drop_count;
      ++expired;
      if (g_half_open_count > 0) {
        g_half_open_count--;
      }
      klog("network: tcp flow id=%u timeout queue=%u cell=%u\n",
           flow->flow_id, flow->queue_id, flow->cell_id);
      release_tcp_flow(flow);
      continue;
    }

    /* Data retransmission for established or peer-closed flows. */
    if ((flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        flow->in_flight > 0U) {
      uint32_t oldest = tcp_tx_oldest_index(flow);
      if (oldest != TCP_TX_WINDOW_SEGMENTS &&
          flow->tx_segments[oldest].last_tx_ns > 0U &&
          now_ns > flow->tx_segments[oldest].last_tx_ns &&
          now_ns - flow->tx_segments[oldest].last_tx_ns >= flow->rto_ns) {
      if (flow->tx_segments[oldest].retries >= NETWORK_TCP_MAX_RETRANSMITS) {
        ++g_tcp_timeout_count;
        ++g_tcp_closed_count;
        ++expired;
        klog("network: tcp flow id=%u data retransmit limit\n",
             flow->flow_id);
        release_tcp_flow(flow);
        continue;
      }
      flow->retransmits++;
      flow->tx_segments[oldest].retries++;
      /* Retain and resend the authoritative outstanding segment. */
      flow->in_retransmit = 1;
      flow->tx_segments[oldest].pending = 1U;
      flow->tx_segments[oldest].retransmitted = 1U;
      tcp_backoff_rto(flow);
      ++g_tcp_retransmit_count;
      ++expired;
      klog("network: tcp flow id=%u retransmit=%u rto=%lu\n",
           flow->flow_id, flow->retransmits, flow->rto_ns);
      }
    }

    if ((flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
         flow->state == XAIOS_NETWORK_FLOW_LAST_ACK) &&
        flow->fin_outstanding != 0U && flow->fin_last_tx_ns != 0U &&
        now_ns > flow->fin_last_tx_ns &&
        now_ns - flow->fin_last_tx_ns >= flow->rto_ns) {
      if (flow->fin_retries >= NETWORK_TCP_MAX_RETRANSMITS) {
        ++g_tcp_timeout_count;
        ++g_tcp_closed_count;
        ++expired;
        klog("network: tcp flow id=%u FIN retransmit limit\n",
             flow->flow_id);
        release_tcp_flow(flow);
        continue;
      }
      ++flow->fin_retries;
      ++flow->retransmits;
      ++g_tcp_retransmit_count;
      ++expired;
      flow->fin_last_tx_ns = now_ns;
      flow->pending_fin = 1U;
    }

    /* Keepalive is idle-based; subsequent unanswered probes use the interval. */
    uint64_t keepalive_base = flow->keepalive_probes_sent == 0U ?
                                  flow->keepalive_last_rx_ns :
                                  flow->keepalive_last_tx_ns;
    uint64_t keepalive_delay = flow->keepalive_probes_sent == 0U ?
                                   TCP_KEEPALIVE_IDLE_NS :
                                   TCP_KEEPALIVE_INTERVAL_NS;
    if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED &&
        keepalive_base != 0U && now_ns > keepalive_base &&
        now_ns - keepalive_base >= keepalive_delay) {
      if (flow->keepalive_probes_sent < TCP_KEEPALIVE_PROBES) {
        flow->keepalive_probes_sent++;
        flow->keepalive_last_tx_ns = now_ns;
        flow->pending_keepalive = 1U;
      } else {
        /* No response to keepalive probes — close connection */
        ++g_tcp_closed_count;
        ++expired;
        klog("network: tcp flow id=%u keepalive timeout\n", flow->flow_id);
        release_tcp_flow(flow);
        continue;
      }
    }
  }
  return expired;
}

uint64_t network_stack_udp_tx_count(void) {
  return g_udp_tx_count;
}

uint64_t network_stack_udp_rx_count(void) {
  return g_udp_rx_count;
}

uint64_t network_stack_udp_malformed_count(void) {
  return g_udp_malformed_count;
}

uint64_t network_stack_udp_dropped_count(void) {
  return g_udp_dropped_count;
}

uint64_t network_stack_udp_flow_count(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0) {
      ++active;
    }
  }
  return active;
}

uint64_t network_stack_udp_flow_hit_count(void) {
  return g_udp_flow_hit_count;
}

uint64_t network_stack_udp_expired_count(void) {
  return g_udp_expired_count;
}

uint64_t network_stack_tcp_connections(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
      ++active;
    }
  }
  return active;
}

uint64_t network_stack_tcp_handshake_count(void) {
  return g_tcp_handshake_count;
}

uint64_t network_stack_tcp_reset_count(void) {
  return g_tcp_reset_count;
}

uint64_t network_stack_tcp_timeout_count(void) {
  return g_tcp_timeout_count;
}

uint64_t network_stack_tcp_retransmit_count(void) {
  return g_tcp_retransmit_count;
}

uint64_t network_stack_tcp_established_count(void) {
  return g_tcp_established_count;
}

uint64_t network_stack_tcp_closed_count(void) {
  return g_tcp_closed_count;
}

uint64_t network_stack_queue_bindings(void) {
  return g_queue_binding_count;
}

uint64_t network_stack_rx_packet_count(void) {
  return g_rx_packet_count;
}

uint64_t network_stack_tx_packet_count(void) {
  return g_tx_packet_count;
}

uint64_t network_stack_packet_drop_count(void) {
  return g_packet_drop_count;
}

uint64_t network_stack_packet_lifecycle_count(void) {
  return g_packet_lifecycle_count;
}

uint64_t network_stack_queue_rx_enqueue_count(void) {
  return g_queue_rx_enqueue_count;
}

uint64_t network_stack_queue_tx_enqueue_count(void) {
  return g_queue_tx_enqueue_count;
}

uint64_t network_stack_queue_completion_count(void) {
  return g_queue_completion_count;
}

uint64_t network_stack_queue_backpressure_drop_count(void) {
  return g_queue_backpressure_drop_count;
}

uint64_t network_stack_flow_core_mismatch_count(void) {
  return g_flow_core_mismatch_count;
}

uint64_t network_stack_udp_latency_p50_ns(void) {
  return percentile(g_udp_latency_samples, g_udp_latency_count, 50U);
}

uint64_t network_stack_udp_latency_p95_ns(void) {
  return percentile(g_udp_latency_samples, g_udp_latency_count, 95U);
}

uint64_t network_stack_udp_latency_p99_ns(void) {
  return percentile(g_udp_latency_samples, g_udp_latency_count, 99U);
}

uint64_t network_stack_udp_latency_p999_ns(void) {
  return percentile(g_udp_latency_samples, g_udp_latency_count, 999U);
}

uint64_t network_stack_tcp_latency_p50_ns(void) {
  return percentile(g_tcp_latency_samples, g_tcp_latency_count, 50U);
}

uint64_t network_stack_tcp_latency_p95_ns(void) {
  return percentile(g_tcp_latency_samples, g_tcp_latency_count, 95U);
}

uint64_t network_stack_tcp_latency_p99_ns(void) {
  return percentile(g_tcp_latency_samples, g_tcp_latency_count, 99U);
}

uint64_t network_stack_tcp_latency_p999_ns(void) {
  return percentile(g_tcp_latency_samples, g_tcp_latency_count, 999U);
}

static void emit_latency_snapshot(uint64_t *udp50, uint64_t *udp95,
                                 uint64_t *udp99, uint64_t *udp999,
                                 uint64_t *tcp50, uint64_t *tcp95,
                                 uint64_t *tcp99, uint64_t *tcp999) {
  *udp50 = network_stack_udp_latency_p50_ns();
  *udp95 = network_stack_udp_latency_p95_ns();
  *udp99 = network_stack_udp_latency_p99_ns();
  *udp999 = network_stack_udp_latency_p999_ns();
  *tcp50 = network_stack_tcp_latency_p50_ns();
  *tcp95 = network_stack_tcp_latency_p95_ns();
  *tcp99 = network_stack_tcp_latency_p99_ns();
  *tcp999 = network_stack_tcp_latency_p999_ns();
}

static void build_app_udp_frame(uint8_t *frame, uint64_t payload_len) {
  bytes_zero(frame, NETWORK_BUFFER_SIZE);
  frame[12U] = 0x08;
  frame[13U] = 0x00;
  frame[14U] = 0x45;
  frame[15U] = 0x00;
  const uint16_t total = (uint16_t)(20U + 8U + payload_len);
  frame[16U] = (uint8_t)(total >> 8U);
  frame[17U] = (uint8_t)total;
  frame[22U] = 64;
  frame[23U] = NETWORK_IP_PROTO_UDP;
  frame[26U] = 10;
  frame[27U] = 0;
  frame[28U] = 2;
  frame[29U] = 15;
  frame[30U] = 10;
  frame[31U] = 0;
  frame[32U] = 2;
  frame[33U] = 2;
  frame[34U] = 0x60;
  frame[35U] = 0x01;
  frame[36U] = 0x22;
  frame[37U] = 0xB8;
  const uint16_t udp_len = (uint16_t)(8U + payload_len);
  frame[38U] = (uint8_t)(udp_len >> 8U);
  frame[39U] = (uint8_t)udp_len;
  write_be16(frame + 24U, ipv4_checksum(frame + 14U, 20U));
}

static void build_app_tcp_frame(uint8_t *frame, uint8_t flags,
                                uint16_t remote_port) {
  bytes_zero(frame, NETWORK_BUFFER_SIZE);
  frame[12U] = 0x08;
  frame[13U] = 0x00;
  frame[14U] = 0x45;
  frame[15U] = 0x00;
  frame[16U] = 0x00;
  frame[17U] = 0x2c;
  frame[22U] = 64;
  frame[23U] = NETWORK_IP_PROTO_TCP;
  frame[26U] = 10;
  frame[27U] = 0;
  frame[28U] = 2;
  frame[29U] = 15;
  frame[30U] = 10;
  frame[31U] = 0;
  frame[32U] = 2;
  frame[33U] = 2;
  frame[34U] = (uint8_t)(remote_port >> 8U);
  frame[35U] = (uint8_t)remote_port;
  frame[36U] = 0x00;
  frame[37U] = 0x16;
  frame[41U] = 1;
  frame[46U] = 0x60;
  frame[47U] = flags;
}

static void finalize_app_tcp_frame(uint8_t *frame) {
  frame[50U] = 0U;
  frame[51U] = 0U;
  uint16_t checksum =
      ipv4_pseudo_checksum(UINT32_C(0x0a00020f), UINT32_C(0x0a000202),
                           NETWORK_IP_PROTO_TCP, 24U, frame + 34U, 24U);
  write_be16(frame + 50U, checksum == 0U ? UINT16_MAX : checksum);
  frame[24U] = 0U;
  frame[25U] = 0U;
  write_be16(frame + 24U, ipv4_checksum(frame + 14U, 20U));
}

static void tcp_sliding_window_self_test(void) {
  network_tcp_flow_t flow;
  uint8_t payload[10];
  bytes_zero(&flow, sizeof(flow));
  for (uint32_t i = 0U; i < sizeof(payload); ++i) {
    payload[i] = (uint8_t)(i + 1U);
  }
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.tx_buf = sockbuf_alloc();
  kassert(flow.tx_buf != 0);
  flow.local_seq = 100U;
  flow.next_send_seq = 100U;
  flow.highest_acked = 100U;
  flow.peer_mss = 4U;
  flow.peer_window = 12U;
  flow.cwnd = 12U;
  flow.rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  kassert(sockbuf_write(flow.tx_buf, payload, sizeof(payload)) ==
          sizeof(payload));

  tcp_queue_send_window(&flow);
  kassert(tcp_tx_segment_count(&flow) == 3U);
  kassert(flow.in_flight == 10U && flow.next_send_seq == 110U);
  kassert(flow.tx_segments[0].seq == 100U &&
          flow.tx_segments[0].len == 4U);
  kassert(flow.tx_segments[1].seq == 104U &&
          flow.tx_segments[1].len == 4U);
  kassert(flow.tx_segments[2].seq == 108U &&
          flow.tx_segments[2].len == 2U);

  kassert(acknowledge_tcp_flow(&flow, 106U, 1U) == 0);
  kassert(tcp_tx_segment_count(&flow) == 2U);
  kassert(flow.in_flight == 4U && flow.local_seq == 106U);
  kassert(flow.tx_segments[1].seq == 106U &&
          flow.tx_segments[1].len == 2U &&
          flow.tx_segments[1].data[0] == 7U);
  kassert(acknowledge_tcp_flow(&flow, 110U, 2U) == 0);
  kassert(tcp_tx_segment_count(&flow) == 0U && flow.in_flight == 0U);
  sockbuf_free(flow.tx_buf);

  uint8_t option_header[60];
  tcp_parsed_options_t options;
  bytes_zero(option_header, sizeof(option_header));
  option_header[20] = TCP_OPT_SACK_PERMITTED;
  option_header[21] = 2U;
  option_header[22] = TCP_OPT_SACK;
  option_header[23] = 10U;
  write_be32(option_header + 24U, 204U);
  write_be32(option_header + 28U, 208U);
  kassert(parse_tcp_options(option_header, 32U, &options) != 0);
  kassert(options.sack_permitted == 1U && options.sack_count == 1U);

  bytes_zero(&flow, sizeof(flow));
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.local_seq = 200U;
  flow.next_send_seq = 212U;
  flow.in_flight = 12U;
  flow.cwnd = 12U;
  flow.ssthresh = 12U;
  for (uint32_t i = 0U; i < 3U; ++i) {
    flow.tx_segments[i].seq = 200U + i * 4U;
    flow.tx_segments[i].len = 4U;
    flow.tx_segments[i].in_use = 1U;
  }
  kassert(tcp_apply_sack_blocks(&flow, &options) == 4U);
  kassert(flow.tx_segments[1].in_use == 0U && flow.in_flight == 8U);
  uint64_t retransmits_before = g_tcp_retransmit_count;
  kassert(acknowledge_tcp_flow(&flow, 200U, 10U) == 0);
  kassert(acknowledge_tcp_flow(&flow, 200U, 11U) == 0);
  kassert(acknowledge_tcp_flow(&flow, 200U, 12U) == 0);
  kassert(flow.in_retransmit == 1U &&
          flow.tx_segments[0].retransmitted == 1U);
  g_tcp_retransmit_count = retransmits_before;

  bytes_zero(&flow, sizeof(flow));
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.tx_buf = sockbuf_alloc();
  kassert(flow.tx_buf != 0);
  flow.next_send_seq = 300U;
  flow.peer_mss = 8U;
  flow.peer_window = 0U;
  flow.cwnd = 8U;
  kassert(sockbuf_write(flow.tx_buf, payload, 4U) == 4U);
  tcp_queue_send_window(&flow);
  kassert(flow.zero_window_probe == 1U && flow.in_flight == 1U &&
          flow.tx_segments[0].len == 1U);
  sockbuf_free(flow.tx_buf);

  bytes_zero(&flow, sizeof(flow));
  flow.rx_buf = sockbuf_alloc();
  kassert(flow.rx_buf != 0);
  flow.expected_seq = 400U;
  flow.window_size = 32U;
  flow.peer_sack_permitted = 1U;
  kassert(ooo_buffer_store(&flow, 404U, payload + 4U, 4U,
                           flow.expected_seq) == 4U);
  uint8_t generated[40];
  uint32_t generated_len =
      build_tcp_options(&flow, NETWORK_TCP_FLAG_ACK, generated);
  bytes_zero(option_header, sizeof(option_header));
  for (uint32_t i = 0U; i < generated_len; ++i) {
    option_header[20U + i] = generated[i];
  }
  kassert(parse_tcp_options(option_header, 20U + generated_len, &options) != 0);
  kassert(options.sack_count == 1U && options.sack_left[0] == 404U &&
          options.sack_right[0] == 408U);
  kassert(sockbuf_write(flow.rx_buf, payload, 4U) == 4U);
  flow.expected_seq += 4U;
  kassert(ooo_buffer_drain(&flow) == 4U && flow.expected_seq == 408U);
  uint8_t reordered[8];
  kassert(sockbuf_read(flow.rx_buf, reordered, sizeof(reordered)) ==
          sizeof(reordered));
  for (uint32_t i = 0U; i < sizeof(reordered); ++i) {
    kassert(reordered[i] == payload[i]);
  }
  sockbuf_free(flow.rx_buf);

  bytes_zero(&flow, sizeof(flow));
  flow.rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  flow.cwnd = NETWORK_TCP_MSS * 8U;
  tcp_backoff_rto(&flow);
  kassert(flow.rto_ns == NETWORK_TCP_RETRANSMIT_NS * 2U &&
          flow.cwnd == NETWORK_TCP_MSS);
  tcp_backoff_rto(&flow);
  kassert(flow.rto_ns == NETWORK_TCP_RETRANSMIT_NS * 4U);

  option_header[20] = TCP_OPT_SACK;
  option_header[21] = 9U;
  kassert(parse_tcp_options(option_header, 29U, &options) == 0);
  klog("network: TCP sliding-window self-test passed segments=3 cumulative_ack=1 partial_ack=1 sack=1 fast_retransmit=1 zero_window=1 reorder=1 rto_backoff=1\n");
}

static xaios_status_t network_stack_app_udp_echo_unlocked(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes) {
  if (payload == 0 || echoed_bytes == 0 || payload_len == 0 ||
      payload_len > 64U) {
    return XAIOS_ERR_INVALID;
  }

  uint8_t frame[NETWORK_BUFFER_SIZE];
  build_app_udp_frame(frame, payload_len);
  for (uint64_t i = 0; i < payload_len; ++i) {
    frame[42U + i] = payload[i];
  }

  const uint32_t queue_id = 3U;
  const uint32_t cell_id = 3U;
  if (network_stack_bind_queue(cell_id, queue_id, 0x8U) != XAIOS_OK) {
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = network_stack_process_udp_frame(frame, 42U + payload_len);
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (status != XAIOS_OK) {
    return status;
  }
  *echoed_bytes = payload_len;
  klog("network: app udp echo payload=%lu queue=%u cell=%u\n",
       payload_len, queue_id, cell_id);
  return XAIOS_OK;
}

xaios_status_t network_stack_app_udp_echo(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes) {
  network_lock();
  xaios_status_t result = network_stack_app_udp_echo_unlocked(payload, payload_len, echoed_bytes);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_app_tcp_connect_unlocked(uint64_t *round_trips) {
  if (round_trips == 0) {
    return XAIOS_ERR_INVALID;
  }

  const uint32_t queue_id = 3U;
  const uint32_t cell_id = 3U;
  uint8_t syn[NETWORK_BUFFER_SIZE];
  uint8_t ack[NETWORK_BUFFER_SIZE];
  uint8_t rst[NETWORK_BUFFER_SIZE];
  const uint16_t remote_port = 0x6010U;
  const uint16_t local_port = 22U;
  int temporary_listener = 0;

  if (!network_stack_has_listener(local_port)) {
    network_stack_register_listener(local_port, UINT64_MAX);
    if (!network_stack_has_listener(local_port)) {
      return XAIOS_ERR_NO_MEMORY;
    }
    temporary_listener = 1;
  }

  if (network_stack_bind_queue(cell_id, queue_id, 0x8U) != XAIOS_OK) {
    if (temporary_listener != 0) {
      network_stack_unregister_listener(local_port);
    }
    return XAIOS_ERR_BUSY;
  }
  build_app_tcp_frame(syn, NETWORK_TCP_FLAG_SYN, remote_port);
  build_app_tcp_frame(ack, NETWORK_TCP_FLAG_ACK, remote_port);
  build_app_tcp_frame(rst, NETWORK_TCP_FLAG_RST, remote_port);
  ack[48U] = 0x40U;
  rst[48U] = 0x40U;
  finalize_app_tcp_frame(syn);

  xaios_status_t status = network_stack_process_tcp_frame(syn, 58U);
  if (status == XAIOS_OK) {
    network_tcp_flow_t *flow = 0;
    for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
      if (g_tcp_flows[i].local_port == local_port &&
          g_tcp_flows[i].remote_port == remote_port &&
          g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV) {
        flow = &g_tcp_flows[i];
        break;
      }
    }
    if (flow == 0 || flow->state != XAIOS_NETWORK_FLOW_SYN_RECV) {
      status = XAIOS_ERR_NOT_FOUND;
    } else {
      write_be32(ack + 38U, flow->expected_seq);
      write_be32(ack + 42U, flow->next_send_seq);
      write_be32(rst + 38U, flow->expected_seq);
      write_be32(rst + 42U, flow->next_send_seq);
      finalize_app_tcp_frame(ack);
      finalize_app_tcp_frame(rst);
    }
  }
  if (status == XAIOS_OK) {
    status = network_stack_process_tcp_frame(ack, 58U);
  }
  if (status == XAIOS_OK) {
    if (network_stack_process_tcp_frame(rst, 58U) == XAIOS_ERR_INVALID) {
      status = XAIOS_OK;
    } else {
      status = XAIOS_ERR_IO;
    }
  }
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (temporary_listener != 0) {
    network_stack_unregister_listener(local_port);
  }
  if (status != XAIOS_OK) return status;
  *round_trips = 2U;
  klog("network: app tcp connect-close queue=%u cell=%u round_trips=%lu\n",
       queue_id, cell_id, *round_trips);
  return XAIOS_OK;
}

xaios_status_t network_stack_app_tcp_connect(uint64_t *round_trips) {
  network_lock();
  xaios_status_t result = network_stack_app_tcp_connect_unlocked(round_trips);
  network_unlock();
  return result;
}

static void network_append(char *output, uint64_t capacity, uint64_t *offset,
                           const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

static void network_append_u64(char *output, uint64_t capacity,
                               uint64_t *offset, uint64_t value) {
  char digits[20];
  uint64_t count = 0;
  if (value == 0) {
    network_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    network_append(output, capacity, offset, one);
  }
}

static xaios_status_t network_stack_external_session_unlocked(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes) {
  if (payload == 0 || payload_len == 0 || payload_len > 64U ||
      output == 0 || output_capacity < 16U || output_bytes == 0 ||
      port == 0 || port > 65535U) {
    return XAIOS_ERR_INVALID;
  }

  output[0] = '\0';
  uint64_t offset = 0;
  if (protocol == XAIOS_NETWORK_PROTOCOL_UDP) {
    uint64_t echoed = 0;
    if (network_stack_app_udp_echo(payload, payload_len, &echoed) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    network_append(output, output_capacity, &offset, "udp:");
    network_append_u64(output, output_capacity, &offset, port);
    network_append(output, output_capacity, &offset, ":echo:");
    network_append_u64(output, output_capacity, &offset, echoed);
    network_append(output, output_capacity, &offset, "\n");
    *output_bytes = offset;
    klog("network: external host udp session port=%lu bytes=%lu echoed=%lu\n",
         port, payload_len, echoed);
    return XAIOS_OK;
  }

  if (protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
    uint64_t round_trips = 0;
    if (network_stack_app_tcp_connect(&round_trips) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    network_append(output, output_capacity, &offset, "tcp:");
    network_append_u64(output, output_capacity, &offset, port);
    network_append(output, output_capacity, &offset, ":established:");
    network_append_u64(output, output_capacity, &offset, round_trips);
    network_append(output, output_capacity, &offset, "\n");
    *output_bytes = offset;
    klog("network: external host tcp session port=%lu bytes=%lu round_trips=%lu\n",
         port, payload_len, round_trips);
    return XAIOS_OK;
  }

  return XAIOS_ERR_INVALID;
}

xaios_status_t network_stack_external_session(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes) {
  network_lock();
  xaios_status_t result = network_stack_external_session_unlocked(protocol, port, payload, payload_len, output, output_capacity, output_bytes);
  network_unlock();
  return result;
}

void network_stack_self_test(void) {
  uint8_t frame_udp[NETWORK_BUFFER_SIZE];
  uint8_t frame_udp_bad[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_syn[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_syn_ack[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_timeout[NETWORK_BUFFER_SIZE];
  bytes_zero(frame_udp, sizeof(frame_udp));
  bytes_zero(frame_udp_bad, sizeof(frame_udp_bad));
  bytes_zero(frame_tcp_syn, sizeof(frame_tcp_syn));
  bytes_zero(frame_tcp_syn_ack, sizeof(frame_tcp_syn_ack));
  bytes_zero(frame_tcp_timeout, sizeof(frame_tcp_timeout));

  network_stack_init();
  tcp_sliding_window_self_test();

  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_OK);
  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_ERR_BUSY);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);
  kassert(network_stack_bind_queue(2, 2, 0x8U) == XAIOS_ERR_BUSY);

  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);

  kassert(network_stack_queue_bindings() == 2U);
  network_stack_register_listener(80U, 1U);
  network_stack_register_udp_listener(UINT16_C(0x5678), 2U);

  frame_udp[12U] = 0x08;
  frame_udp[13U] = 0x00;
  frame_udp[14U] = 0x45;
  frame_udp[15U] = 0x00;
  frame_udp[16U] = 0x00;
  frame_udp[17U] = 0x20;
  frame_udp[18U] = 0x00;
  frame_udp[19U] = 0x00;
  frame_udp[20U] = 0x00;
  frame_udp[21U] = 0x00;
  frame_udp[22U] = 64;
  frame_udp[23U] = NETWORK_IP_PROTO_UDP;
  frame_udp[24U] = 0x00;
  frame_udp[25U] = 0x00;
  frame_udp[26U] = 10;
  frame_udp[27U] = 0;
  frame_udp[28U] = 2;
  frame_udp[29U] = 15;
  frame_udp[30U] = 10;
  frame_udp[31U] = 0;
  frame_udp[32U] = 2;
  frame_udp[33U] = 2;
  frame_udp[34U] = 0x12;
  frame_udp[35U] = 0x34;
  frame_udp[36U] = 0x56;
  frame_udp[37U] = 0x78;
  frame_udp[38U] = 0x00;
  frame_udp[39U] = 0x0C;
  frame_udp[40U] = 0x00;
  frame_udp[41U] = 0x00;
  frame_udp[42U] = 1;
  frame_udp[43U] = 2;
  frame_udp[44U] = 3;
  frame_udp[45U] = 4;
  write_be16(frame_udp + 24U, ipv4_checksum(frame_udp + 14U, 20U));

  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  {
    uint8_t short_datagram[4];
    kassert(network_stack_udp_recv(2U, short_datagram, 2U, 0, 0, 0) == 2U);
    kassert(short_datagram[0] == 1U && short_datagram[1] == 2U);
    kassert(network_stack_udp_recv(2U, short_datagram, sizeof(short_datagram),
                                   0, 0, 0) == sizeof(short_datagram));
    kassert(short_datagram[0] == 1U && short_datagram[1] == 2U &&
            short_datagram[2] == 3U && short_datagram[3] == 4U);
  }
  kassert(g_udp_rx_count == 2U);
  kassert(network_stack_udp_flow_hit_count() == 1U);
  kassert(network_stack_udp_flow_count() == 1U);
  kassert(network_stack_expire_udp_flows(timer_now_ns() +
                                         NETWORK_UDP_IDLE_TIMEOUT_NS + 1U) ==
          1U);
  kassert(network_stack_udp_expired_count() == 1U);
  kassert(network_stack_udp_flow_count() == 0U);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(g_udp_rx_count == 3U);
  kassert(network_stack_udp_flow_count() == 1U);
  frame_udp_bad[13] = 0x06;
  kassert(network_stack_process_udp_frame(frame_udp_bad, 4U) == XAIOS_ERR_INVALID);
  kassert(g_udp_dropped_count == 1U);
  kassert(g_udp_malformed_count == 1U);

  frame_tcp_syn[12] = 0x08;
  frame_tcp_syn[13] = 0x00;
  frame_tcp_syn[14] = 0x45;
  frame_tcp_syn[15] = 0x00;
  frame_tcp_syn[16] = 0x00;
  frame_tcp_syn[17] = 0x2c;
  frame_tcp_syn[18] = 0x00;
  frame_tcp_syn[19] = 0x00;
  frame_tcp_syn[20] = 0x40;
  frame_tcp_syn[21] = 0x00;
  frame_tcp_syn[22] = 64;
  frame_tcp_syn[23] = NETWORK_IP_PROTO_TCP;
  frame_tcp_syn[26] = 10;
  frame_tcp_syn[27] = 0;
  frame_tcp_syn[28] = 2;
  frame_tcp_syn[29] = 15;
  frame_tcp_syn[30] = 10;
  frame_tcp_syn[31] = 0;
  frame_tcp_syn[32] = 2;
  frame_tcp_syn[33] = 2;

  frame_tcp_syn[34] = 0x1f;
  frame_tcp_syn[35] = 0x90;
  frame_tcp_syn[36] = 0x00;
  frame_tcp_syn[37] = 0x50;
  frame_tcp_syn[38] = 0;
  frame_tcp_syn[39] = 0;
  frame_tcp_syn[40] = 0;
  frame_tcp_syn[41] = 1;
  frame_tcp_syn[42] = 0;
  frame_tcp_syn[43] = 0;
  frame_tcp_syn[44] = 0;
  frame_tcp_syn[45] = 0;
  frame_tcp_syn[46] = 0x60; /* offset 6 words */
  frame_tcp_syn[47] = NETWORK_TCP_FLAG_SYN;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_syn + 34U, 24U);
    frame_tcp_syn[50] = (uint8_t)(tcp_checksum >> 8U);
    frame_tcp_syn[51] = (uint8_t)tcp_checksum;
  }
  write_be16(frame_tcp_syn + 24U,
             ipv4_checksum(frame_tcp_syn + 14U, 20U));

  frame_tcp_timeout[0] = 0U;
  for (uint32_t i = 0; i < 58U; ++i) frame_tcp_timeout[i] = frame_tcp_syn[i];
  frame_tcp_timeout[50U] = 0U;
  frame_tcp_timeout[51U] = 0U;
  kassert(parse_tcp(frame_tcp_timeout, 58U, &(uint16_t){0}, &(uint16_t){0},
                    &(uint32_t){0}, &(uint32_t){0}, &(uint8_t){0}) == 0);

  kassert(network_stack_process_tcp_frame(frame_tcp_syn, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_handshake_count() == 1U);
  kassert(network_stack_tcp_connections() == 0U);

  frame_tcp_syn_ack[14] = 0x45;
  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_syn_ack[i] = frame_tcp_syn[i];
  }
  frame_tcp_syn_ack[14] = frame_tcp_syn[14];
  frame_tcp_syn_ack[23] = NETWORK_IP_PROTO_TCP;
  frame_tcp_syn_ack[34] = 0x1f;
  frame_tcp_syn_ack[35] = 0x90;
  frame_tcp_syn_ack[36] = 0x00;
  frame_tcp_syn_ack[37] = 0x50;
  frame_tcp_syn_ack[38] = 0;
  frame_tcp_syn_ack[39] = 0;
  frame_tcp_syn_ack[40] = 0;
  frame_tcp_syn_ack[41] = 0;
  write_be32(frame_tcp_syn_ack + 38U, g_tcp_flows[0].expected_seq);
  write_be32(frame_tcp_syn_ack + 42U, g_tcp_flows[0].next_send_seq);
  frame_tcp_syn_ack[46] = 0x60; /* offset 6 words */
  frame_tcp_syn_ack[47] = NETWORK_TCP_FLAG_ACK;
  frame_tcp_syn_ack[48] = 0x40;
  frame_tcp_syn_ack[49] = 0x00;
  frame_tcp_syn_ack[50] = 0;
  frame_tcp_syn_ack[51] = 0;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_syn_ack + 34U, 24U);
    write_be16(frame_tcp_syn_ack + 50U,
               tcp_checksum == 0U ? UINT16_MAX : tcp_checksum);
  }

  kassert(network_stack_process_tcp_frame(frame_tcp_syn_ack, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_connections() == 1U);
  kassert(network_stack_tcp_established_count() == 1U);

  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_timeout[i] = frame_tcp_syn[i];
  }
  frame_tcp_timeout[35] = 0x91;
  frame_tcp_timeout[50] = 0;
  frame_tcp_timeout[51] = 0;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_timeout + 34U, 24U);
    write_be16(frame_tcp_timeout + 50U,
               tcp_checksum == 0U ? UINT16_MAX : tcp_checksum);
  }
  kassert(network_stack_process_tcp_frame(frame_tcp_timeout, 58U) == XAIOS_OK);
  kassert(network_stack_retransmit_tcp_flows(timer_now_ns() +
                                             NETWORK_TCP_RETRANSMIT_NS + 1U) ==
          1U);
  kassert(network_stack_tcp_retransmit_count() == 1U);
  kassert(network_stack_expire_tcp_flows(timer_now_ns() +
                                         NETWORK_TCP_RETRANSMIT_NS +
                                         NETWORK_TCP_SYN_TIMEOUT_NS + 2U) ==
          1U);
  kassert(network_stack_tcp_timeout_count() == 1U);
  kassert(network_stack_tcp_closed_count() == 1U);
  kassert(network_stack_tcp_connections() == 1U);

  kassert(network_stack_release_queue(1, 0) == XAIOS_OK);
  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  network_stack_unregister_udp_listener(UINT16_C(0x5678));
  kassert(network_stack_queue_bindings() == 0U);

  {
    uint8_t ra_frame[14U + 40U + 16U + 32U] = {0};
    uint8_t saved_mac[6];
    const uint8_t test_mac[6] = {0x02U, 0x11U, 0x22U,
                                 0x33U, 0x44U, 0x55U};
    for (uint32_t i = 0U; i < 6U; ++i) {
      saved_mac[i] = g_local_mac[i];
      g_local_mac[i] = test_mac[i];
    }
    write_be16(ra_frame + 18U, 48U);
    uint8_t *ra_icmpv6 = ra_frame + XAIOS_ICMPV6_OFFSET;
    ra_icmpv6[0] = XAIOS_ICMPV6_ROUTER_ADVERT;
    ra_icmpv6[16] = 3U; /* Prefix Information option */
    ra_icmpv6[17] = 4U; /* 32 bytes */
    ra_icmpv6[18] = 64U;
    ra_icmpv6[19] = UINT8_C(0x40); /* Autonomous address configuration */
    write_be32(ra_icmpv6 + 20U, 60U);
    ra_icmpv6[32] = UINT8_C(0x20);
    ra_icmpv6[33] = UINT8_C(0x01);
    ra_icmpv6[34] = UINT8_C(0x0d);
    ra_icmpv6[35] = UINT8_C(0xb8);
    xaios_ip_addr_zero(&g_public_v6);
    g_public_v6_valid_until_ns = 0U;
    network_ipv6_apply_router_advertisement(ra_frame, sizeof(ra_frame), 10U);
    kassert(network_ipv6_is_global_unicast(&g_public_v6));
    kassert(g_public_v6.addr[0] == UINT8_C(0x20));
    kassert(g_public_v6.addr[8] == 0U);
    kassert(g_public_v6.addr[11] == UINT8_C(0xff));
    kassert(g_public_v6.addr[12] == UINT8_C(0xfe));
    kassert(g_public_v6.addr[15] == UINT8_C(0x55));
    kassert(g_public_v6_valid_until_ns == UINT64_C(60000000010));
    ra_icmpv6[17] = 0U;
    xaios_ip_addr_zero(&g_public_v6);
    network_ipv6_apply_router_advertisement(ra_frame, sizeof(ra_frame), 10U);
    kassert(!network_ipv6_is_global_unicast(&g_public_v6));
    for (uint32_t i = 0U; i < 6U; ++i) g_local_mac[i] = saved_mac[i];
    klog("network: public IPv6 SLAAC self-test passed\n");
  }

  kassert(network_stack_udp_tx_count() == 3U);
  kassert(network_stack_udp_rx_count() == 3U);
  kassert(network_stack_tcp_reset_count() == 0U);
  kassert(network_stack_rx_packet_count() == 6U);
  kassert(network_stack_tx_packet_count() == 6U);
  kassert(network_stack_packet_drop_count() == 2U);
  kassert(network_stack_packet_lifecycle_count() == 18U);
  kassert(network_stack_queue_rx_enqueue_count() == 6U);
  kassert(network_stack_queue_tx_enqueue_count() == 6U);
  kassert(network_stack_queue_completion_count() == 6U);
  kassert(network_stack_queue_backpressure_drop_count() == 0U);
  kassert(network_stack_flow_core_mismatch_count() == 0U);

  uint64_t udp50;
  uint64_t udp95;
  uint64_t udp99;
  uint64_t udp999;
  uint64_t tcp50;
  uint64_t tcp95;
  uint64_t tcp99;
  uint64_t tcp999;
  emit_latency_snapshot(&udp50, &udp95, &udp99, &udp999, &tcp50, &tcp95,
                        &tcp99, &tcp999);

  klog(
      "network: queue-backed udp/tcp self-test passed rx=%lu tx=%lu drops=%lu "
      "lifecycle=%lu udp_flows=%lu udp_hits=%lu udp_expired=%lu "
      "tcp_timeouts=%lu tcp_retransmits=%lu queue_rx=%lu queue_tx=%lu "
      "queue_done=%lu backpressure=%lu flow_mismatch=%lu udp_p50=%lu p95=%lu "
      "p99=%lu p999=%lu tcp_p50=%lu p95=%lu p99=%lu p999=%lu\n",
      network_stack_rx_packet_count(), network_stack_tx_packet_count(),
      network_stack_packet_drop_count(), network_stack_packet_lifecycle_count(),
      network_stack_udp_flow_count(), network_stack_udp_flow_hit_count(),
      network_stack_udp_expired_count(), network_stack_tcp_timeout_count(),
      network_stack_tcp_retransmit_count(),
      network_stack_queue_rx_enqueue_count(),
      network_stack_queue_tx_enqueue_count(),
      network_stack_queue_completion_count(),
      network_stack_queue_backpressure_drop_count(),
      network_stack_flow_core_mismatch_count(),
      udp50, udp95, udp99, udp999, tcp50, tcp95, tcp99, tcp999);
}

void network_init_persistent(void) {
  if (g_persistent_initialized != 0) {
    return;
  }
  if (network_device_get_mac(g_local_mac) == XAIOS_OK) {
    klog("network: local mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
         g_local_mac[0], g_local_mac[1], g_local_mac[2],
         g_local_mac[3], g_local_mac[4], g_local_mac[5]);
  }
  arp_init();
  ndp_init();
  ntp_init();
  ipv4_frag_init();
  ipv6_frag_init();
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_FREE;
    g_tcp_flows[i].flow_id = 0;
    g_tcp_flows[i].rx_buf = 0;
    g_tcp_flows[i].tx_buf = 0;
    g_tcp_flows[i].pending_synack = 0;
    g_tcp_flows[i].pending_ack = 0;
    g_tcp_flows[i].pending_fin = 0;
  }
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    g_udp_flows[i].active = 0;
    g_udp_flows[i].flow_id = 0;
    g_udp_flows[i].rx_buf = 0;
  }
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    g_listeners_ex[i].active = 0;
    g_listeners_ex[i].backlog_count = 0;
  }
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    g_socket_flow_map[i].active = 0;
  }
  g_half_open_count = 0;
  g_tcp_drain_cursor = 0U;
  sockbuf_pool_init();
  routing_init();
  if (network_stack_queue_bindings() == 0U) {
    kassert(network_stack_bind_queue(0, 1, 1U) == XAIOS_OK);
  }
  ipv6_link_local_from_mac(&g_link_local_v6, g_local_mac);
  xaios_ip_addr_zero(&g_public_v6);
  g_public_v6_valid_until_ns = 0U;
  xaios_ip_addr_zero(&g_slaac_v6);
  g_slaac_valid_until_ns = 0U;
  g_persistent_initialized = 1;
  g_poll_tick_count = 0;
  g_icmp_reply_count = 0;
  g_arp_reply_count = 0;
  g_icmpv6_reply_count = 0;
  g_ndp_reply_count = 0;
  g_ipv6_rx_count = 0;
  g_ping.state = XAIOS_NETWORK_PING_IDLE;
  g_ping.target_ip = 0U;
  g_ping.attempts = 0U;
  g_ping.round_trip_ns = 0U;
  g_ping.last_error = XAIOS_OK;
  g_ping_sent_ns = 0U;
  g_ping_sequence = 0U;
  /* RFC 4861 has a host solicit a router on startup rather than wait for the
     next unsolicited advertisement, which may be minutes away or never come.
     Without this the stack has a link-local address and no global one, and
     IPv6 works only on the local link. */
  if (ndp_send_router_solicitation(g_local_mac, &g_link_local_v6) !=
      XAIOS_OK) {
    klog("network: router solicitation could not be sent\n");
  }
  klog("network: persistent mode initialized (dual-stack)\n");
}

xaios_status_t network_stack_local_ipv6(xaios_ip_addr_t *address) {
  if (address == 0) return XAIOS_ERR_INVALID;
  if (g_persistent_initialized == 0U) {
    xaios_ip_addr_zero(address);
    return XAIOS_ERR_NOT_FOUND;
  }
  if (g_slaac_valid_until_ns != 0U &&
      timer_now_ns() < g_slaac_valid_until_ns &&
      g_slaac_v6.family == XAIOS_IP_FAMILY_V6) {
    *address = g_slaac_v6;
    return XAIOS_OK;
  }
  *address = g_link_local_v6;
  return XAIOS_OK;
}

xaios_status_t network_wait_for_ipv6_slaac(uint64_t timeout_ns) {
  if (g_persistent_initialized == 0U || timeout_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* A router advertisement answers the solicitation within milliseconds, but
     nothing polls the interface between bringing it up and starting services,
     so the reply would sit unread in the receive ring and the machine would
     come up with a link-local address only. Poll for it here, re-soliciting
     the way RFC 4861 does rather than waiting on one packet. */
  xaios_ip_addr_t address;
  uint64_t started = timer_now_ns();
  uint64_t next_solicit = started + UINT64_C(500000000);
  uint32_t solicits = 1U;
  for (;;) {
    network_poll_tick();
    if (g_slaac_valid_until_ns != 0U &&
        network_stack_local_ipv6(&address) == XAIOS_OK) {
      return XAIOS_OK;
    }
    uint64_t now = timer_now_ns();
    if (now - started >= timeout_ns) break;
    if (now >= next_solicit && solicits < 3U) {
      (void)ndp_send_router_solicitation(g_local_mac, &g_link_local_v6);
      ++solicits;
      next_solicit = now + UINT64_C(500000000);
    }
  }
  klog("network: no usable IPv6 prefix after %u solicitations; link-local "
       "only\n",
       solicits);
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t network_stack_local_ipv4(void) { return network_config_local_ipv4(); }

xaios_status_t network_stack_local_mac(uint8_t mac[6]) {
  if (mac == 0 || g_persistent_initialized == 0U) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t i = 0U; i < 6U; ++i) mac[i] = g_local_mac[i];
  return XAIOS_OK;
}

xaios_status_t network_stack_local_public_ipv6(xaios_ip_addr_t *address) {
  if (address == 0) return XAIOS_ERR_INVALID;
  if (g_persistent_initialized == 0U ||
      !network_ipv6_is_global_unicast(&g_public_v6) ||
      g_public_v6_valid_until_ns == 0U ||
      timer_now_ns() >= g_public_v6_valid_until_ns) {
    xaios_ip_addr_zero(address);
    return XAIOS_ERR_NOT_FOUND;
  }
  *address = g_public_v6;
  return XAIOS_OK;
}

xaios_status_t network_stack_ping_start(uint32_t target_ip) {
  uint8_t frame[50];
  uint8_t gateway_mac[6];
  if (g_persistent_initialized == 0U || target_ip == 0U)
    return XAIOS_ERR_INVALID;
  if (g_ping.state == XAIOS_NETWORK_PING_PENDING) return XAIOS_ERR_BUSY;
  network_config_gateway_mac(gateway_mac);
  for (uint32_t i = 0U; i < sizeof(frame); ++i) frame[i] = 0U;
  for (uint32_t i = 0U; i < 6U; ++i) {
    frame[i] = gateway_mac[i];
    frame[6U + i] = g_local_mac[i];
  }
  write_be16(frame + 12U, NETWORK_ETHERTYPE_IPV4);
  ipv4_build_header(frame + 14U, 36U, XAIOS_IPV4_PROTO_ICMP,
                    network_config_local_ipv4(), target_ip);
  uint8_t *icmp = frame + 34U;
  icmp[0] = XAIOS_ICMP_ECHO_REQUEST;
  icmp[1] = 0U;
  write_be16(icmp + 4U, NETWORK_PING_IDENTIFIER);
  ++g_ping_sequence;
  write_be16(icmp + 6U, g_ping_sequence);
  icmp[8] = 'X'; icmp[9] = 'A'; icmp[10] = 'I'; icmp[11] = 'O';
  icmp[12] = 'S'; icmp[13] = 'P'; icmp[14] = 'N'; icmp[15] = 'G';
  write_be16(icmp + 2U, ipv4_checksum(icmp, 16U));
  xaios_status_t status = network_device_tx(frame, sizeof(frame));
  g_ping.state = status == XAIOS_OK ? XAIOS_NETWORK_PING_PENDING
                                     : XAIOS_NETWORK_PING_FAILED;
  g_ping.target_ip = target_ip;
  g_ping.attempts = 1U;
  g_ping.round_trip_ns = 0U;
  g_ping.last_error = status;
  g_ping_sent_ns = timer_now_ns();
  return status == XAIOS_OK ? XAIOS_ERR_BUSY : status;
}

xaios_network_ping_status_t network_stack_ping_status(void) { return g_ping; }

static int network_reassemble_incoming(uint8_t *frame, uint32_t *frame_len,
                                       uint16_t ethertype) {
  uint64_t completed_len = *frame_len;
  xaios_status_t status;

  if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (!ipv4_validate_incoming(frame, completed_len)) {
      return 0;
    }
    if (!ipv4_is_fragment(frame, completed_len)) {
      return 1;
    }
    status = ipv4_reassemble(frame, &completed_len);
  } else if (ethertype == NETWORK_ETHERTYPE_IPV6) {
    if (!ipv6_is_fragment_v6(frame, completed_len)) {
      return 1;
    }
    status = ipv6_reassemble_v6(frame, &completed_len);
  } else {
    return 0;
  }

  if (status != XAIOS_OK || completed_len > NETWORK_BUFFER_SIZE) {
    return 0;
  }
  *frame_len = (uint32_t)completed_len;
  return 1;
}

static void network_poll_tick_locked(void) {
  operations_tick();
  if (g_persistent_initialized == 0) {
    return;
  }
  uint64_t now_ns = timer_now_ns();
  ntp_tick(now_ns);
  if (g_public_v6_valid_until_ns != 0U && now_ns >= g_public_v6_valid_until_ns) {
    xaios_ip_addr_zero(&g_public_v6);
    g_public_v6_valid_until_ns = 0U;
  }
  if (g_ping.state == XAIOS_NETWORK_PING_PENDING && now_ns >= g_ping_sent_ns &&
      now_ns - g_ping_sent_ns >= NETWORK_PING_TIMEOUT_NS) {
    g_ping.state = XAIOS_NETWORK_PING_TIMEOUT;
    g_ping.last_error = XAIOS_ERR_IO;
  }
  uint8_t rx_buf[NETWORK_BUFFER_SIZE];
  ++g_poll_tick_count;
  /* Take everything the device has queued rather than one frame per call. The
     receive ring holds a handful of buffers, so draining only the head leaves
     a link with steady inbound traffic permanently full: the device then drops
     what arrives, and the guest answers nothing it was not already holding.
     An interrupt hides this by draining promptly; a platform with none, and a
     poll that runs only inside network syscalls, does not. Bounded so a busy
     link cannot hold the poll lock indefinitely. */
  for (uint32_t drained = 0U; drained < NETWORK_POLL_RX_BUDGET; ++drained) {
    uint32_t frame_len = network_device_rx_poll(rx_buf, sizeof(rx_buf));
    if (frame_len == 0) {
      break;
    }
  if (frame_len < 14U) {
    return;
  }
  uint16_t ethertype = read_u16_be(rx_buf + 12U);
  if (ethertype == 0x0806U) {
    if (frame_len >= 42U && read_u16_be(rx_buf + 20U) == XAIOS_ARP_OP_REPLY) {
      arp_process_reply(rx_buf, frame_len);
    } else if (frame_len >= 42U &&
               read_u16_be(rx_buf + 20U) == XAIOS_ARP_OP_REQUEST) {
      uint32_t target_ip = read_u32_be(rx_buf + 38U);
      if (target_ip == network_config_local_ipv4()) {
        uint8_t reply_frame[64];
        uint64_t reply_len = 0;
        if (arp_build_reply(reply_frame, &reply_len, g_local_mac,
                            network_config_local_ipv4(), rx_buf + 6,
                            read_u32_be(rx_buf + 28U)) == XAIOS_OK) {
          network_device_tx(reply_frame, reply_len);
          ++g_arp_reply_count;
        }
      }
    }
  } else if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (frame_len < 34U ||
        !network_reassemble_incoming(rx_buf, &frame_len, ethertype)) {
      return;
    }
    uint8_t protocol = rx_buf[23U];
    if (protocol == NETWORK_IP_PROTO_UDP &&
        ntp_process_ipv4_frame(rx_buf, frame_len, now_ns) == XAIOS_OK) {
      return;
    }
    if (protocol == NETWORK_IP_PROTO_UDP &&
        dns_process_ipv4_frame(rx_buf, frame_len, now_ns) == XAIOS_OK) {
      dns_tick(now_ns);
      return;
    }
    if (protocol == XAIOS_IPV4_PROTO_ICMP) {
      const uint8_t *icmp = rx_buf + 34U;
      if (frame_len >= 42U && icmp[0] == XAIOS_ICMP_ECHO_REPLY &&
          read_u16_be(icmp + 4U) == NETWORK_PING_IDENTIFIER &&
          read_u16_be(icmp + 6U) == g_ping_sequence &&
          read_u32_be(rx_buf + 26U) == g_ping.target_ip &&
          ipv4_checksum(icmp, read_u16_be(rx_buf + 16U) - 20U) == 0U &&
          g_ping.state == XAIOS_NETWORK_PING_PENDING) {
        g_ping.state = XAIOS_NETWORK_PING_REPLIED;
        g_ping.round_trip_ns = now_ns >= g_ping_sent_ns
                                  ? now_ns - g_ping_sent_ns : 0U;
        g_ping.last_error = XAIOS_OK;
        return;
      }
      uint16_t identifier = 0;
      uint16_t sequence = 0;
      if (icmp_process_echo_request(rx_buf, frame_len, &identifier,
                                     &sequence) == XAIOS_OK) {
        uint8_t reply_buf[NETWORK_BUFFER_SIZE];
        uint64_t reply_len = 0;
        if (icmp_build_echo_reply(reply_buf, &reply_len, g_local_mac,
                                   rx_buf + 6, network_config_local_ipv4(),
                                   read_u32_be(rx_buf + 26U), rx_buf,
                                   frame_len) == XAIOS_OK) {
          network_device_tx(reply_buf, reply_len);
          ++g_icmp_reply_count;
        }
      }
    } else if (protocol == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame(rx_buf, frame_len);
    } else if (protocol == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame(rx_buf, frame_len);
    }
  } else if (ethertype == NETWORK_ETHERTYPE_IPV6) {
    ++g_ipv6_rx_count;
    if (frame_len < 54U ||
        !network_reassemble_incoming(rx_buf, &frame_len, ethertype)) {
      return;
    }
    uint8_t next_header = rx_buf[20U]; /* byte 6 of IPv6 at offset 14 */
    if (next_header == XAIOS_IPV6_NEXT_ICMPV6) {
      if (frame_len >= XAIOS_ICMPV6_MIN_FRAME) {
        uint8_t icmpv6_type = rx_buf[XAIOS_ICMPV6_OFFSET];
        if (icmpv6_type == XAIOS_ICMPV6_ECHO_REQUEST) {
          xaios_ip_addr_t echo_src;
          xaios_ip_addr_t echo_dst;
          uint16_t identifier = 0;
          uint16_t sequence = 0;
          if (icmpv6_process_echo_request(rx_buf, frame_len, &identifier,
                                           &sequence, &echo_src,
                                           &echo_dst) == XAIOS_OK) {
            uint8_t reply_buf[NETWORK_BUFFER_SIZE];
            uint64_t reply_len = 0;
            if (icmpv6_build_echo_reply(reply_buf, &reply_len, g_local_mac,
                                         rx_buf + 6, &g_link_local_v6,
                                         &echo_src, rx_buf,
                                         frame_len) == XAIOS_OK) {
              network_device_tx(reply_buf, reply_len);
              ++g_icmpv6_reply_count;
            }
          }
        } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_SOLICIT) {
          /* Extract target address from NS (bytes 8-23 of ICMPv6 payload) */
          xaios_ip_addr_t ns_target;
          xaios_ip_addr_from_raw_ipv6(&ns_target, rx_buf + XAIOS_ICMPV6_OFFSET + 8);
          /* Build NA: source = our link-local, dest = NS source */
          xaios_ip_addr_t na_src = g_link_local_v6;
          xaios_ip_addr_t na_dst;
          xaios_ip_addr_from_raw_ipv6(&na_dst, rx_buf + 22); /* IPv6 src */
          uint8_t na_frame[128];
          uint64_t na_len = 0;
          if (icmpv6_build_neighbor_advertisement(na_frame, &na_len,
                g_local_mac, rx_buf + 6, &na_src, &na_dst, &ns_target,
                rx_buf, frame_len) == XAIOS_OK) {
            network_device_tx(na_frame, na_len);
            ++g_ndp_reply_count;
          }
        } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_ADVERT) {
          ndp_process_neighbor_advertisement(rx_buf, frame_len);
        } else if (icmpv6_type == XAIOS_ICMPV6_ROUTER_ADVERT &&
                   ndp_process_router_advertisement(rx_buf, frame_len) == XAIOS_OK) {
          network_ipv6_apply_router_advertisement(rx_buf, frame_len, now_ns);
        }
      }
    } else if (next_header == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame_v6(rx_buf, frame_len);
    } else if (next_header == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame_v6(rx_buf, frame_len);
    }
  }
  }
  /* Drain pending TCP transmissions (SYN-ACK, data, ACK, FIN) */
  dns_tick(now_ns);
  network_stack_retransmit_tcp_flows(now_ns);
  network_stack_expire_tcp_flows(now_ns);
  tcp_drain_pending();
}

void network_poll_tick(void) {
  network_lock();
  network_poll_tick_locked();
  network_unlock();
  dns_transport_tick(timer_now_ns());
}

uint64_t network_poll_tick_count(void) {
  return g_poll_tick_count;
}

uint64_t network_icmp_reply_count(void) {
  return g_icmp_reply_count;
}

uint64_t network_arp_reply_sent_count(void) {
  return g_arp_reply_count;
}

uint64_t network_icmpv6_reply_count(void) {
  return g_icmpv6_reply_count;
}

uint64_t network_ndp_reply_count(void) {
  return g_ndp_reply_count;
}

uint64_t network_ipv6_rx_count(void) {
  return g_ipv6_rx_count;
}
