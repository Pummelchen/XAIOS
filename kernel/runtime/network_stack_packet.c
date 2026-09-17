/*
 * The queue-binding registry and the receive packet-descriptor pool, moved
 * verbatim out of network_stack.c. See network_stack_packet.h for the
 * interface and the locking contract.
 */

#include "network_stack_packet.h"

#include "network_stack_tcp.h"

#include <xaios/klog.h>

/* The descriptor pool depth and the per-queue ring depth, moved from
   network_stack.c's constants block. */
#define NETWORK_PACKET_DESCRIPTORS 32U
#define NETWORK_QUEUE_RING_SIZE 8U

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

static network_queue_binding_t g_queue_bindings[XAIOS_NETWORK_MAX_QUEUE_BINDINGS];
static network_queue_ring_t g_queue_rings[XAIOS_NETWORK_MAX_QUEUE_BINDINGS];
static network_packet_desc_t g_packet_descs[NETWORK_PACKET_DESCRIPTORS];

static uint64_t g_queue_binding_count;
static uint64_t g_rx_packet_count;
static uint64_t g_tx_packet_count;
static uint64_t g_packet_drop_count;
static uint64_t g_packet_lifecycle_count;
static uint64_t g_queue_rx_enqueue_count;
static uint64_t g_queue_tx_enqueue_count;
static uint64_t g_queue_completion_count;
static uint64_t g_queue_backpressure_drop_count;

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

int net_queue_binding_find(uint32_t queue_id, network_queue_binding_t *out) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id) {
      if (out != 0) {
        *out = g_queue_bindings[i];
      }
      return 1;
    }
  }
  return 0;
}

int net_queue_binding_select(uint16_t local_port, uint16_t remote_port,
                             uint32_t local_address, uint32_t remote_address,
                             network_queue_binding_t *out) {
  uint32_t active = active_binding_count();
  if (active == 0U) {
    return 0;
  }
  uint32_t hash = (uint32_t)local_port ^ ((uint32_t)remote_port << 3U) ^
                  local_address ^ (remote_address >> 8U);
  network_queue_binding_t *row = binding_by_active_index(hash % active);
  if (row == 0) {
    return 0;
  }
  if (out != 0) {
    *out = *row;
  }
  return 1;
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

void net_note_packet_drop(void) { ++g_packet_drop_count; }

uint32_t net_packet_alloc(uint32_t queue_id, uint64_t length, uint64_t now_ns,
                          uint16_t src_port, uint16_t dst_port,
                          uint32_t src_address, uint32_t dst_address,
                          const xaios_ip_addr_t *src_addr,
                          const xaios_ip_addr_t *dst_addr) {
  network_queue_binding_t binding;
  if (!net_queue_binding_find(queue_id, &binding) || length == 0 ||
      length > NETWORK_BUFFER_SIZE) {
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
      g_packet_descs[i].cell_id = binding.cell_id;
      g_packet_descs[i].src_port = src_port;
      g_packet_descs[i].dst_port = dst_port;
      g_packet_descs[i].src_address = src_address;
      g_packet_descs[i].dst_address = dst_address;
      if (src_addr != 0) {
        g_packet_descs[i].src_addr = *src_addr;
      } else {
        xaios_ip_addr_zero(&g_packet_descs[i].src_addr);
      }
      if (dst_addr != 0) {
        g_packet_descs[i].dst_addr = *dst_addr;
      } else {
        xaios_ip_addr_zero(&g_packet_descs[i].dst_addr);
      }
      g_packet_descs[i].length = length;
      g_packet_descs[i].created_ns = now_ns;
      ++g_rx_packet_count;
      ++g_packet_lifecycle_count;
      return i + 1U;
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

static network_packet_desc_t *packet_from_lease(uint32_t packet) {
  if (packet == 0U || packet > NETWORK_PACKET_DESCRIPTORS) {
    return 0;
  }
  return &g_packet_descs[packet - 1U];
}

void net_packet_mark_tx(uint32_t packet) {
  packet_mark_tx(packet_from_lease(packet));
}

void net_packet_mark_complete(uint32_t packet) {
  packet_mark_complete(packet_from_lease(packet));
}

void net_packet_mark_dropped(uint32_t packet) {
  packet_mark_dropped(packet_from_lease(packet));
}

void net_packet_reset(void) {
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

  g_queue_binding_count = 0;
  g_rx_packet_count = 0;
  g_tx_packet_count = 0;
  g_packet_drop_count = 0;
  g_packet_lifecycle_count = 0;
  g_queue_rx_enqueue_count = 0;
  g_queue_tx_enqueue_count = 0;
  g_queue_completion_count = 0;
  g_queue_backpressure_drop_count = 0;
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
