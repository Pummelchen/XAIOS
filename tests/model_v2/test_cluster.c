#include <xaios_engine/cluster.h>

#include <stdio.h>
#include <string.h>

static void set_key(uint8_t key[32], uint8_t seed) {
  for (uint32_t i = 0U; i < 32U; ++i) key[i] = (uint8_t)(seed + i * 13U);
}

static void connect_peers(xaios_cluster_peer_t *left, uint64_t left_id,
                          xaios_cluster_peer_t *right, uint64_t right_id,
                          uint8_t forward_seed, uint8_t reverse_seed) {
  memset(left, 0, sizeof(*left));
  memset(right, 0, sizeof(*right));
  left->node_id = right_id;
  right->node_id = left_id;
  set_key(left->transmit_key, forward_seed);
  set_key(right->receive_key, forward_seed);
  set_key(right->transmit_key, reverse_seed);
  set_key(left->receive_key, reverse_seed);
}

int main(void) {
  xaios_cluster_peer_t a_peers[2];
  xaios_cluster_peer_t b_peers[2];
  xaios_cluster_peer_t c_peers[2];
  connect_peers(&a_peers[0], 1U, &b_peers[0], 2U, 11U, 23U);
  connect_peers(&a_peers[1], 1U, &c_peers[0], 3U, 37U, 41U);
  connect_peers(&b_peers[1], 2U, &c_peers[1], 3U, 53U, 67U);
  xaios_cluster_t a;
  xaios_cluster_t b;
  xaios_cluster_t c;
  if (xaios_cluster_init(&a, 1U, 9U, a_peers, 2U) != XAIOS_ENGINE_OK ||
      xaios_cluster_init(&b, 2U, 9U, b_peers, 2U) != XAIOS_ENGINE_OK ||
      xaios_cluster_init(&c, 3U, 9U, c_peers, 2U) != XAIOS_ENGINE_OK) {
    return 1;
  }

  uint8_t wire[XAIOS_CLUSTER_MAX_MESSAGE];
  uint8_t replay[XAIOS_CLUSTER_MAX_MESSAGE];
  size_t wire_length = 0U;
  xaios_cluster_message_t message;
  static const char join_payload[] = "node-a";
  if (xaios_cluster_seal(&a, 2U, XAIOS_CLUSTER_JOIN, join_payload,
                         (uint16_t)sizeof(join_payload), wire, sizeof(wire),
                         &wire_length) != XAIOS_ENGINE_OK) {
    return 1;
  }
  memcpy(replay, wire, wire_length);
  if (xaios_cluster_open(&b, wire, wire_length, &message) != XAIOS_ENGINE_OK ||
      message.sender_node_id != 1U || message.opcode != XAIOS_CLUSTER_JOIN ||
      memcmp(message.payload, join_payload, sizeof(join_payload)) != 0 ||
      xaios_cluster_open(&b, replay, wire_length, &message) !=
          XAIOS_ENGINE_ERR_BUSY) {
    return 1;
  }
  if (xaios_cluster_seal(&b, 1U, XAIOS_CLUSTER_JOIN_ACK, NULL, 0U, wire,
                         sizeof(wire), &wire_length) != XAIOS_ENGINE_OK ||
      xaios_cluster_open(&a, wire, wire_length, &message) != XAIOS_ENGINE_OK) {
    return 1;
  }
  wire[wire_length - 1U] ^= UINT8_C(0x80);
  if (xaios_cluster_open(&a, wire, wire_length, &message) !=
      XAIOS_ENGINE_ERR_CHECKSUM) {
    return 1;
  }

  for (uint64_t i = 0U; i < 2U; ++i) {
    a.peers[i].state = XAIOS_CLUSTER_NODE_ONLINE;
    b.peers[i].state = XAIOS_CLUSTER_NODE_ONLINE;
    c.peers[i].state = XAIOS_CLUSTER_NODE_ONLINE;
  }
  uint8_t model_uuid[16];
  for (uint32_t i = 0U; i < sizeof(model_uuid); ++i) model_uuid[i] = (uint8_t)i;
  const uint64_t experts[6] = {9U, 2U, 7U, 1U, 5U, 3U};
  xaios_expert_assignment_t first[6];
  xaios_expert_assignment_t second[6];
  xaios_expert_assignment_t third[6];
  if (xaios_cluster_route_experts(&a, model_uuid, 17U, 4U, experts, 6U,
                                  first, 6U) != XAIOS_ENGINE_OK ||
      xaios_cluster_route_experts(&b, model_uuid, 17U, 4U, experts, 6U,
                                  second, 6U) != XAIOS_ENGINE_OK ||
      xaios_cluster_route_experts(&c, model_uuid, 17U, 4U, experts, 6U,
                                  third, 6U) != XAIOS_ENGINE_OK ||
      memcmp(first, second, sizeof(first)) != 0 ||
      memcmp(first, third, sizeof(first)) != 0) {
    return 1;
  }
  const uint64_t failed_node = 2U;
  if (xaios_cluster_set_peer_state(&a, failed_node,
                                   XAIOS_CLUSTER_NODE_OFFLINE) !=
          XAIOS_ENGINE_OK ||
      xaios_cluster_route_experts(&a, model_uuid, 17U, 4U, experts, 6U,
                                  second, 6U) != XAIOS_ENGINE_OK) {
    return 1;
  }
  for (uint64_t i = 0U; i < 6U; ++i) {
    if (second[i].node_id == failed_node) return 1;
  }

  const float partial_a[3] = {1.0e20f, 2.0f, -3.0f};
  const float partial_b[3] = {-1.0e20f, 5.0f, 7.0f};
  const float partial_c[3] = {1.0f, -4.0f, 2.0f};
  const xaios_expert_partial_t shuffled[3] = {
      {3U, 8U, partial_c}, {1U, 7U, partial_a}, {2U, 4U, partial_b}};
  uint64_t order[3];
  float output[3];
  if (xaios_cluster_reduce_stable(shuffled, 3U, 3U, order, 3U, output) !=
          XAIOS_ENGINE_OK ||
      output[0] != 1.0f || output[1] != 3.0f || output[2] != 6.0f ||
      order[0] != 1U || order[1] != 2U || order[2] != 0U) {
    return 1;
  }

  puts("cluster: mutual authentication, replay rejection, deterministic routing, failure reroute, and stable reduction passed");
  return 0;
}
