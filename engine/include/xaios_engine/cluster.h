#ifndef XAIOS_ENGINE_CLUSTER_H
#define XAIOS_ENGINE_CLUSTER_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/model_v2.h>

#define XAIOS_CLUSTER_KEY_SIZE 32U
#define XAIOS_CLUSTER_TAG_SIZE 32U
#define XAIOS_CLUSTER_HEADER_SIZE 48U
#define XAIOS_CLUSTER_MAX_PAYLOAD 128U
#define XAIOS_CLUSTER_MAX_MESSAGE \
  (XAIOS_CLUSTER_HEADER_SIZE + XAIOS_CLUSTER_MAX_PAYLOAD + \
   XAIOS_CLUSTER_TAG_SIZE)

typedef enum xaios_cluster_opcode {
  XAIOS_CLUSTER_JOIN = 1,
  XAIOS_CLUSTER_JOIN_ACK = 2,
  XAIOS_CLUSTER_HEARTBEAT = 3,
  XAIOS_CLUSTER_LEAVE = 4
} xaios_cluster_opcode_t;

typedef enum xaios_cluster_node_state {
  XAIOS_CLUSTER_NODE_OFFLINE = 0,
  XAIOS_CLUSTER_NODE_ONLINE = 1
} xaios_cluster_node_state_t;

typedef struct xaios_cluster_peer {
  uint64_t node_id;
  uint64_t last_received_nonce;
  uint64_t next_transmit_nonce;
  uint8_t transmit_key[XAIOS_CLUSTER_KEY_SIZE];
  uint8_t receive_key[XAIOS_CLUSTER_KEY_SIZE];
  uint32_t state;
} xaios_cluster_peer_t;

typedef struct xaios_cluster {
  uint64_t local_node_id;
  uint64_t epoch;
  xaios_cluster_peer_t *peers;
  uint64_t peer_capacity;
} xaios_cluster_t;

typedef struct xaios_cluster_message {
  uint64_t sender_node_id;
  uint64_t receiver_node_id;
  uint64_t epoch;
  uint64_t nonce;
  uint16_t opcode;
  uint16_t payload_length;
  uint8_t payload[XAIOS_CLUSTER_MAX_PAYLOAD];
} xaios_cluster_message_t;

typedef struct xaios_expert_identity {
  uint8_t model_uuid[16];
  uint64_t layer_id;
  uint64_t expert_id;
  uint32_t layout_id;
} xaios_expert_identity_t;

typedef struct xaios_expert_assignment {
  uint64_t node_id;
  uint64_t expert_id;
} xaios_expert_assignment_t;

typedef struct xaios_expert_partial {
  uint64_t node_id;
  uint64_t expert_id;
  const float *values;
} xaios_expert_partial_t;

xaios_engine_status_t xaios_cluster_init(xaios_cluster_t *cluster,
                                          uint64_t local_node_id,
                                          uint64_t epoch,
                                          xaios_cluster_peer_t *peers,
                                          uint64_t peer_capacity);
xaios_engine_status_t xaios_cluster_seal(
    xaios_cluster_t *cluster, uint64_t receiver_node_id, uint16_t opcode,
    const void *payload, uint16_t payload_length, uint8_t *wire,
    size_t wire_capacity, size_t *wire_length);
xaios_engine_status_t xaios_cluster_open(xaios_cluster_t *cluster,
                                          const uint8_t *wire,
                                          size_t wire_length,
                                          xaios_cluster_message_t *message);
xaios_engine_status_t xaios_cluster_set_peer_state(
    xaios_cluster_t *cluster, uint64_t node_id, uint32_t state);
xaios_engine_status_t xaios_cluster_select_owner(
    const xaios_cluster_t *cluster, const xaios_expert_identity_t *identity,
    uint64_t *node_id);
xaios_engine_status_t xaios_cluster_route_experts(
    const xaios_cluster_t *cluster, const uint8_t model_uuid[16],
    uint64_t layer_id, uint32_t layout_id, const uint64_t *expert_ids,
    uint64_t expert_count, xaios_expert_assignment_t *assignments,
    uint64_t assignment_capacity);
xaios_engine_status_t xaios_cluster_reduce_stable(
    const xaios_expert_partial_t *partials, uint64_t partial_count,
    uint64_t value_count, uint64_t *order_scratch, uint64_t order_capacity,
    float *output);

#endif
