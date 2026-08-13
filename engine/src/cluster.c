#include <xaios_engine/cluster.h>

#include <string.h>

#include "sha256.h"

#define CLUSTER_MAGIC UINT32_C(0x5841434c)
#define CLUSTER_VERSION UINT16_C(1)

static void store_le16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

static void store_le32(uint8_t *output, uint32_t value) {
  for (uint32_t i = 0U; i < 4U; ++i) output[i] = (uint8_t)(value >> (i * 8U));
}

static void store_le64(uint8_t *output, uint64_t value) {
  for (uint32_t i = 0U; i < 8U; ++i) output[i] = (uint8_t)(value >> (i * 8U));
}

static uint16_t load_le16(const uint8_t *input) {
  return (uint16_t)input[0] | ((uint16_t)input[1] << 8U);
}

static uint32_t load_le32(const uint8_t *input) {
  uint32_t value = 0U;
  for (uint32_t i = 0U; i < 4U; ++i) value |= (uint32_t)input[i] << (i * 8U);
  return value;
}

static uint64_t load_le64(const uint8_t *input) {
  uint64_t value = 0U;
  for (uint32_t i = 0U; i < 8U; ++i) value |= (uint64_t)input[i] << (i * 8U);
  return value;
}

static xaios_cluster_peer_t *find_peer(xaios_cluster_t *cluster,
                                       uint64_t node_id) {
  if (cluster == NULL || node_id == 0U) return NULL;
  for (uint64_t i = 0U; i < cluster->peer_capacity; ++i) {
    if (cluster->peers[i].node_id == node_id) return &cluster->peers[i];
  }
  return NULL;
}

static void hmac_sha256(const uint8_t key[XAIOS_CLUSTER_KEY_SIZE],
                        const uint8_t *data, size_t length,
                        uint8_t output[XAIOS_CLUSTER_TAG_SIZE]) {
  uint8_t inner_key[64];
  uint8_t outer_key[64];
  uint8_t inner_digest[32];
  for (size_t i = 0U; i < sizeof(inner_key); ++i) {
    uint8_t value = i < XAIOS_CLUSTER_KEY_SIZE ? key[i] : 0U;
    inner_key[i] = value ^ UINT8_C(0x36);
    outer_key[i] = value ^ UINT8_C(0x5c);
  }
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, inner_key, sizeof(inner_key));
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, inner_digest);
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, outer_key, sizeof(outer_key));
  xaios_engine_sha256_update(&context, inner_digest, sizeof(inner_digest));
  xaios_engine_sha256_final(&context, output);
  memset(inner_key, 0, sizeof(inner_key));
  memset(outer_key, 0, sizeof(outer_key));
  memset(inner_digest, 0, sizeof(inner_digest));
}

static int constant_time_equal(const uint8_t *left, const uint8_t *right,
                               size_t length) {
  uint8_t difference = 0U;
  for (size_t i = 0U; i < length; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
}

xaios_engine_status_t xaios_cluster_init(xaios_cluster_t *cluster,
                                          uint64_t local_node_id,
                                          uint64_t epoch,
                                          xaios_cluster_peer_t *peers,
                                          uint64_t peer_capacity) {
  if (cluster == NULL || local_node_id == 0U || epoch == 0U || peers == NULL ||
      peer_capacity == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t i = 0U; i < peer_capacity; ++i) {
    if (peers[i].node_id == 0U || peers[i].node_id == local_node_id) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    for (uint64_t j = 0U; j < i; ++j) {
      if (peers[i].node_id == peers[j].node_id) {
        return XAIOS_ENGINE_ERR_INVALID;
      }
    }
  }
  *cluster = (xaios_cluster_t){local_node_id, epoch, peers, peer_capacity};
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_cluster_seal(
    xaios_cluster_t *cluster, uint64_t receiver_node_id, uint16_t opcode,
    const void *payload, uint16_t payload_length, uint8_t *wire,
    size_t wire_capacity, size_t *wire_length) {
  if (cluster == NULL || wire == NULL || wire_length == NULL ||
      opcode < XAIOS_CLUSTER_JOIN || opcode > XAIOS_CLUSTER_LEAVE ||
      payload_length > XAIOS_CLUSTER_MAX_PAYLOAD ||
      (payload_length != 0U && payload == NULL)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *wire_length = 0U;
  size_t length = XAIOS_CLUSTER_HEADER_SIZE + (size_t)payload_length +
                  XAIOS_CLUSTER_TAG_SIZE;
  if (wire_capacity < length) return XAIOS_ENGINE_ERR_CAPABILITY;
  xaios_cluster_peer_t *peer = find_peer(cluster, receiver_node_id);
  if (peer == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (peer->next_transmit_nonce == UINT64_MAX) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  uint64_t nonce = ++peer->next_transmit_nonce;
  memset(wire, 0, XAIOS_CLUSTER_HEADER_SIZE);
  store_le32(wire, CLUSTER_MAGIC);
  store_le16(wire + 4U, CLUSTER_VERSION);
  store_le16(wire + 6U, opcode);
  store_le64(wire + 8U, cluster->local_node_id);
  store_le64(wire + 16U, receiver_node_id);
  store_le64(wire + 24U, cluster->epoch);
  store_le64(wire + 32U, nonce);
  store_le16(wire + 40U, payload_length);
  if (payload_length != 0U) {
    memcpy(wire + XAIOS_CLUSTER_HEADER_SIZE, payload, payload_length);
  }
  hmac_sha256(peer->transmit_key, wire,
              XAIOS_CLUSTER_HEADER_SIZE + payload_length,
              wire + XAIOS_CLUSTER_HEADER_SIZE + payload_length);
  *wire_length = length;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_cluster_open(xaios_cluster_t *cluster,
                                          const uint8_t *wire,
                                          size_t wire_length,
                                          xaios_cluster_message_t *message) {
  if (cluster == NULL || wire == NULL || message == NULL ||
      wire_length < XAIOS_CLUSTER_HEADER_SIZE + XAIOS_CLUSTER_TAG_SIZE ||
      load_le32(wire) != CLUSTER_MAGIC ||
      load_le16(wire + 4U) != CLUSTER_VERSION) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint16_t opcode = load_le16(wire + 6U);
  uint64_t sender = load_le64(wire + 8U);
  uint64_t receiver = load_le64(wire + 16U);
  uint64_t epoch = load_le64(wire + 24U);
  uint64_t nonce = load_le64(wire + 32U);
  uint16_t payload_length = load_le16(wire + 40U);
  size_t expected = XAIOS_CLUSTER_HEADER_SIZE + (size_t)payload_length +
                    XAIOS_CLUSTER_TAG_SIZE;
  if (opcode < XAIOS_CLUSTER_JOIN || opcode > XAIOS_CLUSTER_LEAVE ||
      payload_length > XAIOS_CLUSTER_MAX_PAYLOAD || wire_length != expected ||
      receiver != cluster->local_node_id || epoch != cluster->epoch ||
      nonce == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_cluster_peer_t *peer = find_peer(cluster, sender);
  if (peer == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  uint8_t expected_tag[XAIOS_CLUSTER_TAG_SIZE];
  hmac_sha256(peer->receive_key, wire,
              XAIOS_CLUSTER_HEADER_SIZE + payload_length, expected_tag);
  if (!constant_time_equal(expected_tag,
                           wire + XAIOS_CLUSTER_HEADER_SIZE + payload_length,
                           sizeof(expected_tag))) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  if (nonce <= peer->last_received_nonce) return XAIOS_ENGINE_ERR_BUSY;
  peer->last_received_nonce = nonce;
  peer->state = opcode == XAIOS_CLUSTER_LEAVE ? XAIOS_CLUSTER_NODE_OFFLINE
                                               : XAIOS_CLUSTER_NODE_ONLINE;
  memset(message, 0, sizeof(*message));
  message->sender_node_id = sender;
  message->receiver_node_id = receiver;
  message->epoch = epoch;
  message->nonce = nonce;
  message->opcode = opcode;
  message->payload_length = payload_length;
  if (payload_length != 0U) {
    memcpy(message->payload, wire + XAIOS_CLUSTER_HEADER_SIZE, payload_length);
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_cluster_set_peer_state(
    xaios_cluster_t *cluster, uint64_t node_id, uint32_t state) {
  if (state != XAIOS_CLUSTER_NODE_OFFLINE &&
      state != XAIOS_CLUSTER_NODE_ONLINE) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_cluster_peer_t *peer = find_peer(cluster, node_id);
  if (peer == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  peer->state = state;
  return XAIOS_ENGINE_OK;
}

static uint64_t identity_score(const xaios_expert_identity_t *identity,
                               uint64_t node_id) {
  uint64_t value = UINT64_C(0xcbf29ce484222325);
  for (size_t i = 0U; i < sizeof(identity->model_uuid); ++i) {
    value = (value ^ identity->model_uuid[i]) * UINT64_C(0x100000001b3);
  }
  const uint64_t words[4] = {identity->layer_id, identity->expert_id,
                             identity->layout_id, node_id};
  for (size_t word = 0U; word < 4U; ++word) {
    uint64_t input = words[word];
    for (uint32_t byte = 0U; byte < 8U; ++byte) {
      value = (value ^ (input & UINT64_C(0xff))) * UINT64_C(0x100000001b3);
      input >>= 8U;
    }
  }
  value ^= value >> 33U;
  value *= UINT64_C(0xff51afd7ed558ccd);
  value ^= value >> 33U;
  return value;
}

xaios_engine_status_t xaios_cluster_select_owner(
    const xaios_cluster_t *cluster, const xaios_expert_identity_t *identity,
    uint64_t *node_id) {
  if (cluster == NULL || identity == NULL || node_id == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *node_id = 0U;
  uint64_t best_score = identity_score(identity, cluster->local_node_id);
  *node_id = cluster->local_node_id;
  for (uint64_t i = 0U; i < cluster->peer_capacity; ++i) {
    const xaios_cluster_peer_t *peer = &cluster->peers[i];
    if (peer->state != XAIOS_CLUSTER_NODE_ONLINE) continue;
    uint64_t score = identity_score(identity, peer->node_id);
    if (*node_id == 0U || score > best_score ||
        (score == best_score && peer->node_id < *node_id)) {
      *node_id = peer->node_id;
      best_score = score;
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_cluster_route_experts(
    const xaios_cluster_t *cluster, const uint8_t model_uuid[16],
    uint64_t layer_id, uint32_t layout_id, const uint64_t *expert_ids,
    uint64_t expert_count, xaios_expert_assignment_t *assignments,
    uint64_t assignment_capacity) {
  if (cluster == NULL || model_uuid == NULL || expert_ids == NULL ||
      assignments == NULL || expert_count == 0U ||
      assignment_capacity < expert_count) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t i = 0U; i < expert_count; ++i) {
    xaios_expert_identity_t identity;
    memcpy(identity.model_uuid, model_uuid, sizeof(identity.model_uuid));
    identity.layer_id = layer_id;
    identity.expert_id = expert_ids[i];
    identity.layout_id = layout_id;
    assignments[i].expert_id = expert_ids[i];
    xaios_engine_status_t status = xaios_cluster_select_owner(
        cluster, &identity, &assignments[i].node_id);
    if (status != XAIOS_ENGINE_OK) return status;
  }
  for (uint64_t i = 1U; i < expert_count; ++i) {
    xaios_expert_assignment_t value = assignments[i];
    uint64_t position = i;
    while (position > 0U &&
           (assignments[position - 1U].node_id > value.node_id ||
            (assignments[position - 1U].node_id == value.node_id &&
             assignments[position - 1U].expert_id > value.expert_id))) {
      assignments[position] = assignments[position - 1U];
      --position;
    }
    assignments[position] = value;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_cluster_reduce_stable(
    const xaios_expert_partial_t *partials, uint64_t partial_count,
    uint64_t value_count, uint64_t *order_scratch, uint64_t order_capacity,
    float *output) {
  if (partials == NULL || partial_count == 0U || value_count == 0U ||
      order_scratch == NULL || order_capacity < partial_count || output == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (value_count > SIZE_MAX / sizeof(*output)) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  for (uint64_t i = 0U; i < partial_count; ++i) {
    if (partials[i].node_id == 0U || partials[i].values == NULL) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    order_scratch[i] = i;
  }
  for (uint64_t i = 1U; i < partial_count; ++i) {
    uint64_t value = order_scratch[i];
    uint64_t position = i;
    while (position > 0U) {
      const xaios_expert_partial_t *left = &partials[order_scratch[position - 1U]];
      const xaios_expert_partial_t *right = &partials[value];
      if (left->node_id < right->node_id ||
          (left->node_id == right->node_id &&
           left->expert_id <= right->expert_id)) {
        break;
      }
      order_scratch[position] = order_scratch[position - 1U];
      --position;
    }
    order_scratch[position] = value;
  }
  memset(output, 0, (size_t)value_count * sizeof(*output));
  for (uint64_t ordered = 0U; ordered < partial_count; ++ordered) {
    const float *values = partials[order_scratch[ordered]].values;
    for (uint64_t value = 0U; value < value_count; ++value) {
      output[value] += values[value];
    }
  }
  return XAIOS_ENGINE_OK;
}
