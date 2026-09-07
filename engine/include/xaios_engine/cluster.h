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
  /* When a frame from this peer was last opened, on the local clock, or zero
     for a peer that has never been heard from.

     The distinction matters more than it looks: a peer that has said nothing
     yet has not gone silent, it has not arrived. Treating the two the same
     turns a slow boot into a death, and a cluster that kills its members for
     booting slowly is worse than one with no failure detection at all --
     failure detection that fires on healthy nodes removes them. Nothing in
     this file reads a clock; the caller stamps this through
     xaios_cluster_note_heard, because the engine has no business deciding
     which clock a deployment keeps time by. */
  uint64_t last_heard_nanos;
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
/* Record that this node was heard from at `now_nanos`. `now_nanos` must be
   non-zero, because zero is the value that means "never heard". */
xaios_engine_status_t xaios_cluster_note_heard(xaios_cluster_t *cluster,
                                               uint64_t node_id,
                                               uint64_t now_nanos);
/* Take offline every peer that was online and has not been heard from for
   longer than `deadline_nanos`, and report how many that was.

   This is the failure case a LEAVE cannot cover. A node that announces its
   departure is being polite; a node whose power fails, whose kernel panics or
   whose network is cut says nothing at all, and that is the ordinary way
   machines leave a cluster. Only a deadline distinguishes a peer that is gone
   from one that is merely slow, and picking it is a judgement rather than a
   calculation: too short and a healthy node is evicted for being busy, too
   long and work is stalled behind a machine that is never coming back. */
xaios_engine_status_t xaios_cluster_expire_silent(xaios_cluster_t *cluster,
                                                  uint64_t now_nanos,
                                                  uint64_t deadline_nanos,
                                                  uint64_t *expired_count);
/* How many nodes this one currently believes are up, out of how many the
   cluster has, and whether that is a majority.

   Quorum is the question that does not exist at two nodes -- at two, a
   surviving node cannot tell a dead peer from a cut wire, and either answer
   it gives is defensible. At three it becomes answerable: a majority can
   still be certain no other majority exists, and a minority must therefore
   decline to decide anything the majority might decide differently. `live`
   counts this node, which is why a lone survivor of three reports 1 of 3 and
   no quorum. */
xaios_engine_status_t xaios_cluster_quorum(const xaios_cluster_t *cluster,
                                           uint64_t *live_nodes,
                                           uint64_t *total_nodes,
                                           int *has_quorum);
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
