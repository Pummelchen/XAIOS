#include <xaios/arp.h>
#include <xaios/assert.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/network_stack.h>
#include <xaios/routing.h>
#include <xaios/socket_buffer.h>
#include <xaios/timer.h>
#include <xaios/virtio_net.h>

#define NETWORK_ETHERTYPE_IPV4 UINT16_C(0x0800)
#define NETWORK_ETHERTYPE_IPV6 UINT16_C(0x86DD)
#define NETWORK_IP_PROTO_UDP UINT8_C(17)
#define NETWORK_IP_PROTO_TCP UINT8_C(6)

#define NETWORK_BUFFER_SIZE 1520U
#define NETWORK_MAX_SAMPLES 64U

#define NETWORK_TCP_CONNECTIONS 16U
#define NETWORK_UDP_FLOWS 16U
#define NETWORK_PACKET_DESCRIPTORS 16U
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

#define NETWORK_TCP_MSS 1400U
#define NETWORK_TCP_WSCALE_OK 1U
#define TCP_OOO_BUF_ENTRIES 4U      /* A9: out-of-order buffer slots */   /* we accept window scaling */

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
  uint8_t  pending_fin;        /* FIN needs to be sent */
  uint8_t  pending_ack;        /* ACK needs to be sent */
  uint8_t  close_requested;    /* local side called close */
  uint8_t  remote_mac[6];      /* cached peer MAC */
  uint8_t  remote_mac_valid;
  /* A3: TCP retransmission */
  uint64_t last_tx_ns;         /* timestamp of last data send */
  uint64_t rto_ns;             /* current retransmission timeout */
  uint32_t rto_retries;        /* consecutive RTO timeouts */
  uint8_t  in_retransmit;      /* currently in retransmission */
  /* A9: out-of-order data buffering */
  struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  in_use;
    uint8_t  data[NETWORK_TCP_MSS];
  } ooo_buf[TCP_OOO_BUF_ENTRIES];
  /* A4: TCP MSS negotiation */
  uint16_t peer_mss;           /* received from peer */
  uint8_t  mss_parsed;         /* we parsed peer MSS */
  /* A5: TCP window scaling */
  uint8_t  ws_parsed;          /* peer sent window scale */
  uint8_t  peer_ws;            /* peer's window scale factor */
  uint8_t  our_ws;             /* our window scale factor */
  /* A6: TCP congestion control */
  uint32_t cwnd;               /* congestion window (bytes) */
  uint32_t ssthresh;           /* slow start threshold (bytes) */
  uint32_t dup_ack_count;      /* duplicate ACK counter */
  uint32_t highest_acked;      /* highest seq acked by peer */
  uint32_t in_flight;          /* bytes sent but not yet acked */
  uint32_t retransmit_seq;
  uint16_t retransmit_len;
  uint8_t retransmit_data[NETWORK_TCP_MSS];
  uint8_t retransmit_pending;
  /* A7: TCP keepalive */
  uint64_t keepalive_last_tx_ns;
  uint32_t keepalive_probes_sent;
} network_tcp_flow_t;

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

/* FIX-001: SYN flood protection */
#define NETWORK_TCP_MAX_HALF_OPEN 8U
#define NETWORK_TCP_SYN_RATE_LIMIT 10U  /* SYNs per second per source IP */
/* Note: NETWORK_TCP_SYN_TIMEOUT_NS defined above (3 seconds) */

typedef struct tcp_syn_tracker {
  uint32_t source_ip;
  xaios_ip_addr_t source_addr;
  uint64_t syn_count;
  uint64_t last_reset_ns;
} tcp_syn_tracker_t;

static uint32_t g_half_open_count = 0;

static uint8_t g_local_mac[6];
static uint32_t g_persistent_initialized;
static uint64_t g_poll_tick_count;
static uint64_t g_icmp_reply_count;
static uint64_t g_arp_reply_count;
static uint64_t g_icmpv6_reply_count;
static uint64_t g_ndp_reply_count;
static uint64_t g_ipv6_rx_count;
static xaios_ip_addr_t g_link_local_v6;

/*
 * Listener registry: migrated to per-listener backlog
 * (network_listener_ex_t, see A10)
 */


/* ---- Accept Queue ---- */
/* A10: Replaced by per-listener backlog in network_listener_ex_t */

/* ---- Socket-to-Flow Mapping ---- */
#define NETWORK_SOCK_FLOW_MAP_SIZE 16U
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

/* A9: Buffer out-of-order TCP segment. Returns bytes buffered. */
static uint32_t ooo_buffer_store(network_tcp_flow_t *flow, uint32_t seq,
                                   const uint8_t *data, uint32_t len,
                                   uint32_t expected_seq) {
  if (len == 0 || seq <= expected_seq) return 0;
  for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (!flow->ooo_buf[i].in_use) {
      uint32_t copy_len = (len < NETWORK_TCP_MSS) ? len : NETWORK_TCP_MSS;
      for (uint32_t j = 0; j < copy_len; ++j)
        flow->ooo_buf[i].data[j] = data[j];
      flow->ooo_buf[i].seq = seq;
      flow->ooo_buf[i].len = (uint16_t)copy_len;
      flow->ooo_buf[i].in_use = 1;
      return copy_len;
    }
  }
  return 0;
}

/* A9: Drain OOO buffer into rx_buf in order. Returns bytes delivered. */
static uint32_t ooo_buffer_drain(network_tcp_flow_t *flow) {
  uint32_t total = 0;
  int progress = 1;
  while (progress) {
    progress = 0;
    for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
      if (flow->ooo_buf[i].in_use && flow->ooo_buf[i].seq == flow->expected_seq) {
        uint32_t written = sockbuf_write(flow->rx_buf,
                            flow->ooo_buf[i].data, flow->ooo_buf[i].len);
        flow->expected_seq += written;
        flow->pending_ack = 1;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        flow->ooo_buf[i].in_use = 0;
        total += written;
        progress = 1;
      }
    }
  }
  return total;
}

/* A10: Per-listener accept backlog */
#define NETWORK_MAX_LISTENERS 8U
#define NETWORK_LISTENER_BACKLOG 8U
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
  flow->pending_fin = 0;
  flow->pending_ack = 0;
  flow->close_requested = 0;
  flow->in_flight = 0;
  flow->retransmit_len = 0;
  flow->retransmit_pending = 0;
  flow->in_retransmit = 0;
  flow->state = XAIOS_NETWORK_FLOW_FREE;
}

static int acknowledge_tcp_flow(network_tcp_flow_t *flow, uint32_t ack,
                                uint64_t now_ns) {
  if (flow == 0) return 0;
  if (flow->state == XAIOS_NETWORK_FLOW_LAST_ACK &&
      ack >= flow->next_send_seq) {
    ++g_tcp_closed_count;
    release_tcp_flow(flow);
    return 1;
  }
  if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT &&
      ack >= flow->next_send_seq) {
    flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT_2;
    flow->last_seen_ns = now_ns;
  }
  if (ack > flow->local_seq) {
    uint32_t newly_acked = ack - flow->local_seq;
    flow->local_seq = ack;
    flow->highest_acked = ack;
    if (flow->in_flight >= newly_acked) {
      flow->in_flight -= newly_acked;
    } else {
      flow->in_flight = 0;
    }
    if (flow->retransmit_len != 0U &&
        ack >= flow->retransmit_seq + flow->retransmit_len) {
      flow->in_flight = 0;
      flow->retransmit_len = 0;
      flow->retransmit_pending = 0;
      flow->in_retransmit = 0;
      flow->rto_retries = 0;
      flow->rto_ns = NETWORK_TCP_RETRANSMIT_NS;
    }
    flow->dup_ack_count = 0;
    uint32_t mss = flow->peer_mss > 0U ? flow->peer_mss : NETWORK_TCP_MSS;
    if (flow->cwnd < flow->ssthresh) {
      flow->cwnd += mss;
    } else {
      flow->cwnd += (mss * mss) / (flow->cwnd > 0U ? flow->cwnd : 1U);
    }
  } else if (ack == flow->local_seq && flow->in_flight > 0U) {
    ++flow->dup_ack_count;
    if (flow->dup_ack_count >= TCP_MAX_DUP_ACK &&
        flow->in_retransmit == 0U) {
      flow->ssthresh = flow->cwnd > 1U ? flow->cwnd >> 1U : 1U;
      flow->cwnd = flow->ssthresh + TCP_MAX_DUP_ACK * NETWORK_TCP_MSS;
      flow->in_retransmit = 1;
      if (flow->retransmit_len != 0U) {
        flow->retransmit_pending = 1;
        flow->last_tx_ns = now_ns;
        ++flow->retransmits;
        ++g_tcp_retransmit_count;
      }
    }
  }
  return 0;
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

static void udp_listener_enqueue(uint16_t port, uint32_t flow_id,
                                 uint16_t peer_port,
                                 const xaios_ip_addr_t *peer_addr,
                                 uint16_t payload_len) {
  network_listener_ex_t *listener =
      find_listener_ex(port, NETWORK_IP_PROTO_UDP);
  if (listener == 0) {
    return;
  }
  if (listener->backlog_count >= NETWORK_LISTENER_BACKLOG) {
    ++g_udp_dropped_count;
    return;
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

/* Parse TCP options, extract MSS and window scale if present */
static void parse_tcp_options(const uint8_t *tcp_hdr, uint32_t hdr_bytes,
                               uint16_t *out_mss, uint8_t *out_ws) {
  *out_mss = 0;
  *out_ws = 0;
  uint32_t offset = 20; /* skip fixed header */
  while (offset + 1U <= hdr_bytes) {
    uint8_t kind = tcp_hdr[offset];
    if (kind == TCP_OPT_END) break;
    if (kind == TCP_OPT_NOP) { offset += 1; continue; }
    if (offset + 2U > hdr_bytes) break;
    uint8_t len = tcp_hdr[offset + 1U];
    if (len < 2U || offset + (uint32_t)len > hdr_bytes) break;
    if (kind == TCP_OPT_MSS && len == 4U && offset + 4U <= hdr_bytes) {
      *out_mss = read_u16_be(tcp_hdr + offset + 2U);
    } else if (kind == TCP_OPT_WSCALE && len == 3U) {
      *out_ws = tcp_hdr[offset + 2U];
    }
    offset += (uint32_t)len;
  }
}

static uint16_t checksum_u16(const uint8_t *data, uint32_t length) {
  uint64_t sum = 0;
  for (uint32_t i = 0; i + 1U < length; i += 2U) {
    sum += ((uint64_t)data[i] << 8U) | (uint64_t)data[i + 1U];
  }
  if ((length & 1U) != 0U) {
    sum += ((uint64_t)data[length - 1U] << 8U);
  }
  while ((sum >> 16U) != 0U) {
    sum = (sum & 0xFFFFU) + (sum >> 16U);
  }
  return (uint16_t)(~sum & 0xFFFFU);
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

  if ((ip->checksum != 0U) &&
      (checksum_u16((const uint8_t *)ip, ip_header_bytes) != 0U)) {
    return 0;
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
  
  /* FIX-002: TCP options bounds checking */
  if (data_offset_words < 5U) {
    return 0;  /* TCP header too small */
  }
  if (data_offset_words > 15U) {
    return 0;  /* TCP header too large (max 60 bytes) */
  }
  
  const uint64_t tcp_header_bytes = (uint64_t)data_offset_words * 4U;
  
  /* FIX-002: Validate options don't exceed IP payload */
  if (tcp_header_bytes > ip_len - ip_header_bytes) {
    return 0;  /* TCP header extends beyond IP payload */
  }
  
  /* FIX-002: Limit TCP options to maximum 40 bytes */
  if (tcp_header_bytes > 60) {
    return 0;  /* TCP options exceed 40 byte limit */
  }
  
  const uint64_t tcp_payload_len =
      ip_len - ip_header_bytes - (uint64_t)tcp_header_bytes;
  const uint16_t tcp_len = (uint16_t)(tcp_header_bytes + tcp_payload_len);

  if (tcp_header_bytes > ip_len) {
    return 0;
  }

  if ((ip->checksum != 0U) &&
      (checksum_u16((const uint8_t *)ip, (uint16_t)ip_header_bytes) != 0U)) {
    return 0;
  }

  /* A1: Validate TCP checksum */
  uint32_t src_ip_be = read_u32_be((const uint8_t *)&ip->source);
  uint32_t dst_ip_be = read_u32_be((const uint8_t *)&ip->destination);
  uint16_t wire_cksum = read_u16_be((const uint8_t *)&tcp->checksum);
  if (wire_cksum != 0) {
    uint16_t computed = ipv4_pseudo_checksum(src_ip_be, dst_ip_be,
                         NETWORK_IP_PROTO_TCP, tcp_len,
                         (const uint8_t *)tcp, tcp_len);
    if (computed != 0) {
      return 0; /* checksum mismatch */
    }
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

  /* A8: Validate IPv6 UDP checksum (mandatory per RFC 2460 Section 8.1) */
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

  /* A1: Validate TCP checksum for IPv6 */
  uint32_t tcp_total = tcp_hdr_bytes + ((uint32_t)plen - tcp_hdr_bytes);
  uint16_t wire_cksum = read_u16_be(tcp + 16U);
  if (wire_cksum != 0) {
    xaios_ip_addr_t src, dst;
    xaios_ip_addr_from_raw_ipv6(&src, ip6 + 8U);
    xaios_ip_addr_from_raw_ipv6(&dst, ip6 + 24U);
    uint16_t computed = ipv6_pseudo_checksum(&src, &dst,
                         NETWORK_IP_PROTO_TCP, tcp_total,
                         tcp, tcp_total);
    if (computed != 0) {
      return 0; /* checksum mismatch */
    }
  }

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

static network_tcp_flow_t *alloc_tcp_flow(void) {
  /* FIX-001: Limit half-open connections to prevent SYN flood */
  if (g_half_open_count >= NETWORK_TCP_MAX_HALF_OPEN) {
    klog("network: SYN flood protection: rejecting connection (half-open: %u)\n", g_half_open_count);
    return 0;
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
      g_tcp_flows[i].pending_fin = 0;
      g_tcp_flows[i].pending_ack = 0;
      g_tcp_flows[i].close_requested = 0;
      g_tcp_flows[i].remote_mac_valid = 0;
      /* A3: retransmission */
      g_tcp_flows[i].last_tx_ns = 0;
      g_tcp_flows[i].rto_ns = NETWORK_TCP_RETRANSMIT_NS;
      g_tcp_flows[i].rto_retries = 0;
      g_tcp_flows[i].in_retransmit = 0;
      /* A9: OOO buffer */
      for (uint32_t j = 0; j < TCP_OOO_BUF_ENTRIES; ++j) {
        g_tcp_flows[i].ooo_buf[j].in_use = 0;
        g_tcp_flows[i].ooo_buf[j].seq = 0;
        g_tcp_flows[i].ooo_buf[j].len = 0;
      }
      /* A4: MSS */
      g_tcp_flows[i].peer_mss = 0;
      g_tcp_flows[i].mss_parsed = 0;
      /* A5: window scaling */
      g_tcp_flows[i].ws_parsed = 0;
      g_tcp_flows[i].peer_ws = 0;
      g_tcp_flows[i].our_ws = 0;
      /* A6: congestion control */
      g_tcp_flows[i].cwnd = TCP_INIT_CWND * NETWORK_TCP_MSS;
      g_tcp_flows[i].ssthresh = TCP_INIT_SSTHRESH * NETWORK_TCP_MSS;
      g_tcp_flows[i].dup_ack_count = 0;
      g_tcp_flows[i].highest_acked = 0;
      g_tcp_flows[i].in_flight = 0;
      g_tcp_flows[i].retransmit_seq = 0;
      g_tcp_flows[i].retransmit_len = 0;
      g_tcp_flows[i].retransmit_pending = 0;
      /* A7: keepalive */
      g_tcp_flows[i].keepalive_last_tx_ns = 0;
      g_tcp_flows[i].keepalive_probes_sent = 0;
      g_half_open_count++;
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

void network_stack_init(void) {
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
    sockbuf_write(flow->rx_buf, udp_payload, data_len);
    xaios_ip_addr_t peer_addr;
    peer_addr.family = XAIOS_IP_FAMILY_V4;
    for (uint32_t i = 0; i < 4U; ++i) {
      peer_addr.addr[i] = frame[26U + i];
    }
    for (uint32_t i = 4U; i < 16U; ++i) {
      peer_addr.addr[i] = 0;
    }
    udp_listener_enqueue(dst_port, flow->flow_id, src_port, &peer_addr,
                         (uint16_t)data_len);
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
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack_val,
    uint8_t flags, uint16_t window,
    const uint8_t *payload, uint32_t payload_len) {
  /* Include TCP options only in SYN segments (MSS + window scale) */
  uint32_t tcp_opt_len = 0;
  uint8_t tcp_opts[12];
  bytes_zero(tcp_opts, sizeof(tcp_opts));
  if ((flags & NETWORK_TCP_FLAG_SYN) != 0 && (flags & NETWORK_TCP_FLAG_ACK) == 0) {
    tcp_opts[0] = TCP_OPT_MSS; tcp_opts[1] = 4;
    write_be16(tcp_opts + 2, NETWORK_TCP_MSS);
    tcp_opts[4] = TCP_OPT_NOP;
    tcp_opts[5] = TCP_OPT_WSCALE; tcp_opts[6] = 3; tcp_opts[7] = 0; /* ws=0 */
    tcp_opts[8] = TCP_OPT_NOP;
    tcp_opts[9] = TCP_OPT_NOP;
    tcp_opts[10] = TCP_OPT_END;
    tcp_opt_len = 12;
  } else if ((flags & NETWORK_TCP_FLAG_SYN) != 0) {
    /* SYN-ACK: include MSS and echo window scale */
    tcp_opts[0] = TCP_OPT_MSS; tcp_opts[1] = 4;
    write_be16(tcp_opts + 2, NETWORK_TCP_MSS);
    tcp_opts[4] = TCP_OPT_NOP;
    tcp_opts[5] = TCP_OPT_WSCALE; tcp_opts[6] = 3; tcp_opts[7] = 0;
    tcp_opts[8] = TCP_OPT_END;
    tcp_opt_len = 12;
  }
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
  return virtio_net_tx(frame, frame_len);
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
                         XAIOS_IPV4_GUEST_IP, next_hop) == XAIOS_OK) {
    virtio_net_tx(arp_frame, arp_len);
  }
  return 0;
}

/* Build and send a TCP segment over IPv6 */
static xaios_status_t tcp_build_and_send_segment_v6(
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack_val,
    uint8_t flags, uint16_t window,
    const uint8_t *payload, uint32_t payload_len) {
  /* Include TCP options only in SYN segments (MSS + window scale) */
  uint32_t tcp_opt_len = 0;
  uint8_t tcp_opts[12];
  bytes_zero(tcp_opts, sizeof(tcp_opts));
  if ((flags & NETWORK_TCP_FLAG_SYN) != 0) {
    tcp_opts[0] = TCP_OPT_MSS; tcp_opts[1] = 4;
    write_be16(tcp_opts + 2, NETWORK_TCP_MSS);
    tcp_opts[4] = TCP_OPT_NOP;
    tcp_opts[5] = TCP_OPT_WSCALE; tcp_opts[6] = 3; tcp_opts[7] = 0;
    tcp_opts[8] = TCP_OPT_END;
    tcp_opt_len = 12;
  }
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
  return virtio_net_tx(frame, frame_len);
}

static void tcp_drain_pending(void) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &g_tcp_flows[i];
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
    
    if (flow->local_addr.family == XAIOS_IP_FAMILY_V6) {
      /* IPv6 flow: use v6 segment builder */
      if (flow->pending_synack != 0) {
        tcp_build_and_send_segment_v6(g_local_mac, flow->remote_mac,
            &flow->local_addr, &flow->remote_addr,
            flow->local_port, flow->remote_port,
            flow->local_seq, flow->expected_seq,
            NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK,
            flow->window_size, 0, 0);
        flow->pending_synack = 0;
      }
      if (flow->retransmit_pending != 0 && flow->retransmit_len != 0) {
        xaios_status_t status = tcp_build_and_send_segment_v6(
            g_local_mac, flow->remote_mac, &flow->local_addr,
            &flow->remote_addr, flow->local_port, flow->remote_port,
            flow->retransmit_seq, flow->expected_seq,
            NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_PSH, flow->window_size,
            flow->retransmit_data, flow->retransmit_len);
        if (status == XAIOS_OK) {
          if (flow->in_flight == 0U) {
            flow->next_send_seq += flow->retransmit_len;
            flow->in_flight = flow->retransmit_len;
          }
          flow->last_tx_ns = timer_now_ns();
          flow->retransmit_pending = 0;
          ++flow->packets_tx;
        }
      }
      if (flow->tx_buf != 0 && sockbuf_used(flow->tx_buf) > 0 &&
          flow->in_flight == 0U && flow->retransmit_len == 0U &&
          (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
           flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT)) {
        uint32_t bytes_to_send = sockbuf_read(
            flow->tx_buf, flow->retransmit_data, NETWORK_TCP_MSS);
        if (bytes_to_send > 0) {
          flow->retransmit_seq = flow->next_send_seq;
          flow->retransmit_len = (uint16_t)bytes_to_send;
          flow->retransmit_pending = 1;
        }
      }
      if (flow->pending_ack != 0 &&
          (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0)) {
        tcp_build_and_send_segment_v6(g_local_mac, flow->remote_mac,
            &flow->local_addr, &flow->remote_addr,
            flow->local_port, flow->remote_port,
            flow->next_send_seq, flow->expected_seq,
            NETWORK_TCP_FLAG_ACK, flow->window_size, 0, 0);
        flow->pending_ack = 0;
      }
      if (flow->pending_fin != 0 &&
          (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0) &&
          flow->in_flight == 0U && flow->retransmit_len == 0U) {
        tcp_build_and_send_segment_v6(g_local_mac, flow->remote_mac,
            &flow->local_addr, &flow->remote_addr,
            flow->local_port, flow->remote_port,
            flow->next_send_seq, flow->expected_seq,
            NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_ACK,
            flow->window_size, 0, 0);
        flow->pending_fin = 0;
        flow->next_send_seq++;
        if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
          flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT;
        } else if (flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) {
          flow->state = XAIOS_NETWORK_FLOW_LAST_ACK;
        }
      }
    } else {
      /* IPv4 flow: use v4 segment builder */
      uint32_t src_ip_be = XAIOS_IPV4_GUEST_IP;
      uint32_t dst_ip_be = ((flow->remote_address & 0xFFU) << 24U) |
                            (((flow->remote_address >> 8U) & 0xFFU) << 16U) |
                            (((flow->remote_address >> 16U) & 0xFFU) << 8U) |
                            ((flow->remote_address >> 24U) & 0xFFU);
      if (flow->pending_synack != 0) {
        tcp_build_and_send_segment(g_local_mac, flow->remote_mac,
                                    src_ip_be, dst_ip_be,
                                    flow->local_port, flow->remote_port,
                                    flow->local_seq, flow->expected_seq,
                                    NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK,
                                    flow->window_size, 0, 0);
        flow->pending_synack = 0;
      }
      if (flow->retransmit_pending != 0 && flow->retransmit_len != 0) {
        xaios_status_t status = tcp_build_and_send_segment(
            g_local_mac, flow->remote_mac, src_ip_be, dst_ip_be,
            flow->local_port, flow->remote_port, flow->retransmit_seq,
            flow->expected_seq, NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_PSH,
            flow->window_size, flow->retransmit_data,
            flow->retransmit_len);
        if (status == XAIOS_OK) {
          if (flow->in_flight == 0U) {
            flow->next_send_seq += flow->retransmit_len;
            flow->in_flight = flow->retransmit_len;
          }
          flow->last_tx_ns = timer_now_ns();
          flow->retransmit_pending = 0;
          ++flow->packets_tx;
        }
      }
      if (flow->tx_buf != 0 && sockbuf_used(flow->tx_buf) > 0 &&
          flow->in_flight == 0U && flow->retransmit_len == 0U &&
          (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
           flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT)) {
        uint32_t bytes_to_send = sockbuf_read(
            flow->tx_buf, flow->retransmit_data, NETWORK_TCP_MSS);
        if (bytes_to_send > 0) {
          flow->retransmit_seq = flow->next_send_seq;
          flow->retransmit_len = (uint16_t)bytes_to_send;
          flow->retransmit_pending = 1;
        }
      }
      if (flow->pending_ack != 0 &&
          (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0)) {
        tcp_build_and_send_segment(g_local_mac, flow->remote_mac,
                                    src_ip_be, dst_ip_be,
                                    flow->local_port, flow->remote_port,
                                    flow->next_send_seq, flow->expected_seq,
                                    NETWORK_TCP_FLAG_ACK,
                                    flow->window_size, 0, 0);
        flow->pending_ack = 0;
      }
      if (flow->pending_fin != 0 &&
          (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0) &&
          flow->in_flight == 0U && flow->retransmit_len == 0U) {
        tcp_build_and_send_segment(g_local_mac, flow->remote_mac,
                                    src_ip_be, dst_ip_be,
                                    flow->local_port, flow->remote_port,
                                    flow->next_send_seq, flow->expected_seq,
                                    NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_ACK,
                                    flow->window_size, 0, 0);
        flow->pending_fin = 0;
        flow->next_send_seq++;
        if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
          flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT;
        } else if (flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) {
          flow->state = XAIOS_NETWORK_FLOW_LAST_ACK;
        }
      }
    }
  }
}

/* ---- Listener Registry Functions ---- */

void network_stack_register_listener(uint16_t port, uint64_t sockfd) {
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

void network_stack_register_udp_listener(uint16_t port, uint64_t sockfd) {
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

void network_stack_unregister_listener(uint16_t port) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active && g_listeners_ex[i].port == port &&
        g_listeners_ex[i].protocol == NETWORK_IP_PROTO_TCP) {
      g_listeners_ex[i].active = 0;
      g_listeners_ex[i].backlog_count = 0;
      return;
    }
  }
}

void network_stack_unregister_udp_listener(uint16_t port) {
  for (uint32_t i = 0; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active && g_listeners_ex[i].port == port &&
        g_listeners_ex[i].protocol == NETWORK_IP_PROTO_UDP) {
      g_listeners_ex[i].active = 0;
      g_listeners_ex[i].backlog_count = 0;
      return;
    }
  }
}

int network_stack_has_listener(uint16_t port) {
  return find_listener_ex(port, NETWORK_IP_PROTO_TCP) != 0;
}

/* ---- Accept Queue Functions ---- */

static void accept_queue_enqueue(uint32_t flow_id, uint32_t peer_ip,
                                  uint16_t peer_port, uint16_t local_port,
                                  const xaios_ip_addr_t *peer_addr) {
  listener_enqueue_backlog(local_port, flow_id, peer_ip, peer_port, peer_addr);
}

xaios_status_t network_stack_accept_connection(uint16_t listen_port,
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

/* ---- Socket-to-Flow Mapping Functions ---- */

void network_stack_map_socket(uint64_t sockfd, uint32_t flow_id,
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

socket_flow_mapping_t *network_stack_get_socket_mapping(uint64_t sockfd) {
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0 &&
        g_socket_flow_map[i].sockfd == sockfd) {
      return &g_socket_flow_map[i];
    }
  }
  return 0;
}

void network_stack_unmap_socket(uint64_t sockfd) {
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0 &&
        g_socket_flow_map[i].sockfd == sockfd) {
      g_socket_flow_map[i].active = 0;
      return;
    }
  }
}

/* ---- TCP Send / Close API ---- */

xaios_status_t network_stack_tcp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
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

xaios_status_t network_stack_tcp_close_flow(uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id) {
      g_tcp_flows[i].close_requested = 1;
      g_tcp_flows[i].pending_fin = 1;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_udp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].flow_id == flow_id && g_udp_flows[i].active != 0) {
      /* Build Ethernet + IPv4 + UDP frame */
      uint8_t frame[NETWORK_BUFFER_SIZE];
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
                         XAIOS_IPV4_GUEST_IP, dst_ip_be);
      /* UDP header */
      uint8_t *udp = frame + 34U;
      write_be16(udp, g_udp_flows[i].local_port);
      write_be16(udp + 2, g_udp_flows[i].remote_port);
      write_be16(udp + 4, udp_len);
      write_be16(udp + 6, 0); /* UDP checksum optional */
      /* Payload */
      for (uint32_t j = 0; j < len; ++j) {
        frame[42U + j] = data[j];
      }
      *bytes_written = len;
      return virtio_net_tx(frame, frame_len);
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t network_stack_tcp_recv(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size) {
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

int network_stack_tcp_peer_closed(uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id) {
      return g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
             g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSED ||
             g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_TIME_WAIT;
    }
  }
  return 1;
}

uint32_t network_stack_udp_recv(uint64_t sockfd, uint8_t *buffer,
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

  const network_ip4_header_t *ip =
      (const network_ip4_header_t *)(frame + 14U);
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

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
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

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow();
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
    flow->local_seq = (uint32_t)(timer_now_ns() ^ (uint64_t)flow->flow_id);
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
    flow->last_seen_ns = start;
    flow->state = XAIOS_NETWORK_FLOW_SYN_RECV;
    flow->retransmits = 0;
    flow->packets_rx = 1;
    flow->packets_tx = 0;

    /* A4/A5: Parse MSS and window scale from peer SYN */
    {
      const network_ip4_header_t *iph4 =
          (const network_ip4_header_t *)(frame + 14U);
      uint32_t ip_hdr_b = (uint32_t)(iph4->version_ihl & 0x0fU) * 4U;
      const uint8_t *thdr = frame + 14U + ip_hdr_b;
      uint32_t thdr_b = (uint32_t)(thdr[12] >> 4U) * 4U;
      uint16_t p_mss = 0; uint8_t p_ws = 0;
      parse_tcp_options(thdr, thdr_b, &p_mss, &p_ws);
      flow->peer_mss = (p_mss > 0 && p_mss < NETWORK_TCP_MSS) ? p_mss : NETWORK_TCP_MSS;
      flow->mss_parsed = 1;
      flow->peer_ws = p_ws;
      flow->ws_parsed = (p_ws > 0) ? 1 : 0;
      flow->our_ws = 0;
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
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->pending_synack = 0;
    flow->local_seq = ack;
    flow->next_send_seq = ack; /* peer confirmed our ISN+1 */
    flow->last_seen_ns = start;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    /* FIX-001: Decrement half-open counter when connection established */
    if (g_half_open_count > 0) {
      g_half_open_count--;
    }
    /* Enqueue in accept queue for syscall layer */
    uint32_t peer_ip_be = ((remote_address & 0xFFU) << 24U) |
                           (((remote_address >> 8U) & 0xFFU) << 16U) |
                           (((remote_address >> 16U) & 0xFFU) << 8U) |
                           ((remote_address >> 24U) & 0xFFU);
    accept_queue_enqueue(flow->flow_id, peer_ip_be, src_port, dst_port, 0);
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
    flow->last_seen_ns = start;
    ++flow->packets_rx;

        /* Handle incoming FIN */
    if ((flags & NETWORK_TCP_FLAG_FIN) != 0U) {
      flow->expected_seq = seq + 1U; /* FIN consumes one seq */
      flow->pending_ack = 1;
      if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
        flow->state = XAIOS_NETWORK_FLOW_CLOSE_WAIT;
      } else if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2) {
        /* A2: FIN in FIN_WAIT_2 → TIME_WAIT */
        flow->state = XAIOS_NETWORK_FLOW_TIME_WAIT;
        flow->last_seen_ns = start;
      }
    }

    /* Extract TCP payload */
    const network_ip4_header_t *iph =
        (const network_ip4_header_t *)(frame + 14U);
    uint64_t ip_hdr_bytes = (uint64_t)(iph->version_ihl & 0x0FU) * 4U;
    uint16_t ip_total = read_u16_be((const uint8_t *)&iph->total_length);
    const uint8_t *tcp_hdr = frame + 14U + ip_hdr_bytes;
    uint64_t tcp_hdr_bytes = (uint64_t)(tcp_hdr[12] >> 4U) * 4U;
    uint32_t payload_len = (uint32_t)(ip_total) - (uint32_t)ip_hdr_bytes -
                            (uint32_t)tcp_hdr_bytes;

    if (payload_len > 0 && flow->rx_buf != 0) {
      const uint8_t *payload = tcp_hdr + tcp_hdr_bytes;
      if (seq == flow->expected_seq) {
        uint32_t written = sockbuf_write(flow->rx_buf, payload, payload_len);
        flow->expected_seq += written;
        flow->pending_ack = 1;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        /* A9: Drain any buffered OOO data */
        ooo_buffer_drain(flow);
      } else if (seq > flow->expected_seq) {
        /* A9: Buffer out-of-order segment */
        ooo_buffer_store(flow, seq, payload, payload_len, flow->expected_seq);
      }
    }

    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U &&
        acknowledge_tcp_flow(flow, ack, start) != 0) {
      packet_mark_tx(packet);
      packet_mark_complete(packet);
      record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                     timer_now_ns() - start);
      return XAIOS_OK;
    }

    /* Reset keepalive on any data from peer */
    flow->keepalive_last_tx_ns = 0;
    flow->keepalive_probes_sent = 0;

    /* If close was requested and all data sent, mark FIN pending */
    if (flow->close_requested &&
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
    sockbuf_write(flow->rx_buf, udp_payload, data_len);
    udp_listener_enqueue(dst_port, flow->flow_id, src_port, &src_addr,
                         (uint16_t)data_len);
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

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
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

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow();
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
    flow->local_seq = (uint32_t)(timer_now_ns() ^ (uint64_t)flow->flow_id);
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
    flow->last_seen_ns = start;
    flow->state = XAIOS_NETWORK_FLOW_SYN_RECV;
    flow->retransmits = 0;
    flow->packets_rx = 1;
    flow->packets_tx = 0;
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
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->pending_synack = 0;
    flow->local_seq = ack_v;
    flow->next_send_seq = ack_v;
    flow->last_seen_ns = start;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    if (g_half_open_count > 0) {
      g_half_open_count--;
    }
    /* Enqueue in accept queue for syscall layer */
    accept_queue_enqueue(flow->flow_id, 0, src_port, dst_port, &src_addr);
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
    flow->last_seen_ns = start;
    ++flow->packets_rx;

    /* Handle incoming FIN */
    if ((flags & NETWORK_TCP_FLAG_FIN) != 0U) {
      flow->expected_seq = seq + 1U;
      flow->pending_ack = 1;
      if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
        flow->state = XAIOS_NETWORK_FLOW_CLOSE_WAIT;
      } else if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2) {
        flow->state = XAIOS_NETWORK_FLOW_TIME_WAIT;
        flow->last_seen_ns = start;
      }
    }

    /* Extract TCP payload from IPv6 frame */
    /* IPv6 header is 40 bytes at offset 14, TCP header starts after that */
    const uint8_t *ip6 = frame + 14U;
    const uint8_t *tcp_hdr = ip6 + 40U;
    uint64_t tcp_hdr_bytes = (uint64_t)(tcp_hdr[12] >> 4U) * 4U;
    uint16_t ip6_payload_len = read_u16_be(ip6 + 4U);
    uint32_t payload_len_v6 = (uint32_t)ip6_payload_len - (uint32_t)tcp_hdr_bytes;

    if (payload_len_v6 > 0 && flow->rx_buf != 0) {
      const uint8_t *payload = tcp_hdr + tcp_hdr_bytes;
      if (seq == flow->expected_seq) {
        uint32_t written = sockbuf_write(flow->rx_buf, payload, payload_len_v6);
        flow->expected_seq += written;
        flow->pending_ack = 1;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        ooo_buffer_drain(flow);
      } else if (seq > flow->expected_seq) {
        ooo_buffer_store(flow, seq, payload, payload_len_v6, flow->expected_seq);
      }
    }

    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U &&
        acknowledge_tcp_flow(flow, ack_v, start) != 0) {
      packet_mark_tx(packet);
      packet_mark_complete(packet);
      record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                     timer_now_ns() - start);
      return XAIOS_OK;
    }

    if (flow->close_requested &&
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
      g_udp_flows[i].active = 0;
      ++g_udp_expired_count;
      ++expired;
      klog("network: udp flow id=%u expired queue=%u cell=%u rx=%lu tx=%lu\n",
           g_udp_flows[i].flow_id, g_udp_flows[i].queue_id,
           g_udp_flows[i].cell_id, g_udp_flows[i].packets_rx,
           g_udp_flows[i].packets_tx);
    }
  }
  return expired;
}

uint64_t network_stack_retransmit_tcp_flows(uint64_t now_ns) {
  uint64_t retransmitted = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV &&
        now_ns > g_tcp_flows[i].last_seen_ns &&
        now_ns - g_tcp_flows[i].last_seen_ns >= NETWORK_TCP_RETRANSMIT_NS &&
        g_tcp_flows[i].retransmits < NETWORK_TCP_MAX_RETRANSMITS) {
      ++g_tcp_flows[i].retransmits;
      ++g_tcp_flows[i].packets_tx;
      g_tcp_flows[i].last_seen_ns = now_ns;
      g_tcp_flows[i].pending_synack = 1;
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

    /* SYN_RECV timeout */
    if (flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
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

    /* A3: Data retransmission for ESTABLISHED/CLOSE_WAIT flows */
    if ((flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        flow->last_tx_ns > 0 &&
        flow->in_flight > 0 &&
        now_ns > flow->last_tx_ns &&
        now_ns - flow->last_tx_ns >= flow->rto_ns) {
      if (flow->rto_retries >= NETWORK_TCP_MAX_RETRANSMITS) {
        ++g_tcp_timeout_count;
        ++g_tcp_closed_count;
        ++expired;
        klog("network: tcp flow id=%u data retransmit limit\n",
             flow->flow_id);
        release_tcp_flow(flow);
        continue;
      }
      flow->retransmits++;
      flow->rto_retries++;
      /* Exponential backoff: double RTO, cap at 60s */
      flow->rto_ns = (flow->rto_ns * 2);
      if (flow->rto_ns > UINT64_C(60000000000)) {
        flow->rto_ns = UINT64_C(60000000000);
      }
      /* Retain and resend the authoritative outstanding segment. */
      flow->in_retransmit = 1;
      flow->retransmit_pending = 1;
      /* Reduce ssthresh on timeout (Reno) */
      flow->ssthresh = (flow->cwnd > 1) ? (flow->cwnd >> 1) : 1;
      flow->cwnd = NETWORK_TCP_MSS; /* reset to 1 MSS */
      ++g_tcp_retransmit_count;
      ++expired;
      klog("network: tcp flow id=%u retransmit=%u rto=%lu\n",
           flow->flow_id, flow->retransmits, flow->rto_ns);
    }

    /* A7: TCP keepalive for established connections */
    if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED &&
        flow->keepalive_last_tx_ns > 0 &&
        now_ns > flow->keepalive_last_tx_ns &&
        now_ns - flow->keepalive_last_tx_ns >= TCP_KEEPALIVE_INTERVAL_NS) {
      if (flow->keepalive_probes_sent < TCP_KEEPALIVE_PROBES) {
        flow->keepalive_probes_sent++;
        flow->keepalive_last_tx_ns = now_ns;
        flow->pending_ack = 1; /* trigger duplicate ACK as keepalive probe */
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

xaios_status_t network_stack_app_udp_echo(const uint8_t *payload,
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

xaios_status_t network_stack_app_tcp_connect(uint64_t *round_trips) {
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

  xaios_status_t status = network_stack_process_tcp_frame(syn, 58U);
  if (status == XAIOS_OK) {
    status = network_stack_process_tcp_frame(ack, 58U);
  }
  if (status == XAIOS_OK) {
    status = network_stack_process_tcp_frame(rst, 58U);
  }
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (temporary_listener != 0) {
    network_stack_unregister_listener(local_port);
  }
  if (status != XAIOS_OK && status != XAIOS_ERR_INVALID) {
    return status;
  }
  *round_trips = 2U;
  klog("network: app tcp connect-close queue=%u cell=%u round_trips=%lu\n",
       queue_id, cell_id, *round_trips);
  return XAIOS_OK;
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

xaios_status_t network_stack_external_session(uint64_t protocol, uint64_t port,
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

  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_OK);
  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_ERR_BUSY);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);
  kassert(network_stack_bind_queue(2, 2, 0x8U) == XAIOS_ERR_BUSY);

  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);

  kassert(network_stack_queue_bindings() == 2U);
  network_stack_register_listener(80U, 1U);

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

  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
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
  frame_tcp_syn[20] = 0x00;
  frame_tcp_syn[21] = 0x40;
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
  frame_tcp_syn_ack[42] = 0;
  frame_tcp_syn_ack[43] = 0;
  frame_tcp_syn_ack[44] = 0;
  frame_tcp_syn_ack[45] = 0;
  frame_tcp_syn_ack[46] = 0x60; /* offset 6 words */
  frame_tcp_syn_ack[47] = NETWORK_TCP_FLAG_ACK;
  frame_tcp_syn_ack[50] = 0;
  frame_tcp_syn_ack[51] = 0;

  kassert(network_stack_process_tcp_frame(frame_tcp_syn_ack, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_connections() == 1U);
  kassert(network_stack_tcp_established_count() == 1U);

  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_timeout[i] = frame_tcp_syn[i];
  }
  frame_tcp_timeout[35] = 0x91;
  frame_tcp_timeout[50] = 0;
  frame_tcp_timeout[51] = 0;
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
  kassert(network_stack_queue_bindings() == 0U);

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
  if (virtio_net_get_mac(g_local_mac) == XAIOS_OK) {
    klog("network: local mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
         g_local_mac[0], g_local_mac[1], g_local_mac[2],
         g_local_mac[3], g_local_mac[4], g_local_mac[5]);
  }
  arp_init();
  ndp_init();
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
  sockbuf_pool_init();
  routing_init();
  if (network_stack_queue_bindings() == 0U) {
    kassert(network_stack_bind_queue(0, 1, 1U) == XAIOS_OK);
  }
  ipv6_link_local_from_mac(&g_link_local_v6, g_local_mac);
  g_persistent_initialized = 1;
  g_poll_tick_count = 0;
  g_icmp_reply_count = 0;
  g_arp_reply_count = 0;
  g_icmpv6_reply_count = 0;
  g_ndp_reply_count = 0;
  g_ipv6_rx_count = 0;
  klog("network: persistent mode initialized (dual-stack)\n");
}

void network_poll_tick(void) {
  if (g_persistent_initialized == 0) {
    return;
  }
  uint8_t rx_buf[NETWORK_BUFFER_SIZE];
  uint32_t frame_len = virtio_net_rx_poll(rx_buf, sizeof(rx_buf));
  if (frame_len == 0) {
    uint64_t now_ns = timer_now_ns();
    ++g_poll_tick_count;
    network_stack_retransmit_tcp_flows(now_ns);
    network_stack_expire_tcp_flows(now_ns);
    tcp_drain_pending();
    return;
  }
  ++g_poll_tick_count;
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
      if (target_ip == XAIOS_IPV4_GUEST_IP) {
        uint8_t reply_frame[64];
        uint64_t reply_len = 0;
        if (arp_build_reply(reply_frame, &reply_len, g_local_mac,
                            XAIOS_IPV4_GUEST_IP, rx_buf + 6,
                            read_u32_be(rx_buf + 28U)) == XAIOS_OK) {
          virtio_net_tx(reply_frame, reply_len);
          ++g_arp_reply_count;
        }
      }
    }
  } else if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (frame_len < 34U) {
      return;
    }
    uint8_t protocol = rx_buf[23U];
    if (protocol == XAIOS_IPV4_PROTO_ICMP) {
      uint16_t identifier = 0;
      uint16_t sequence = 0;
      if (icmp_process_echo_request(rx_buf, frame_len, &identifier,
                                     &sequence) == XAIOS_OK) {
        uint8_t reply_buf[NETWORK_BUFFER_SIZE];
        uint64_t reply_len = 0;
        if (icmp_build_echo_reply(reply_buf, &reply_len, g_local_mac,
                                   rx_buf + 6, XAIOS_IPV4_GUEST_IP,
                                   read_u32_be(rx_buf + 26U), rx_buf,
                                   frame_len) == XAIOS_OK) {
          virtio_net_tx(reply_buf, reply_len);
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
    if (frame_len < 54U) {
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
              virtio_net_tx(reply_buf, reply_len);
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
            virtio_net_tx(na_frame, na_len);
            ++g_ndp_reply_count;
          }
        } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_ADVERT) {
          ndp_process_neighbor_advertisement(rx_buf, frame_len);
        }
      }
    } else if (next_header == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame_v6(rx_buf, frame_len);
    } else if (next_header == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame_v6(rx_buf, frame_len);
    }
  }
  /* Drain pending TCP transmissions (SYN-ACK, data, ACK, FIN) */
  uint64_t now_ns = timer_now_ns();
  network_stack_retransmit_tcp_flows(now_ns);
  network_stack_expire_tcp_flows(now_ns);
  tcp_drain_pending();
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
