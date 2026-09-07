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

  /* Failure detection by silence, and the quorum question that only exists
     above two nodes.

     Everything above this point tests a cluster whose members announce their
     departures. Real members mostly do not: they lose power, panic, or have
     their network cut, and the only evidence the survivors get is that
     nothing arrives any more. What follows is that case -- a deadline, and
     the three-node majority that makes a survivor's decision safe to act on.
     Each check below is paired with the case that must NOT fire, because a
     detector that expires everything passes every positive test. */
  xaios_cluster_peer_t d_peers[2];
  xaios_cluster_peer_t e_peers[2];
  connect_peers(&d_peers[0], 1U, &e_peers[0], 2U, 71U, 73U);
  connect_peers(&d_peers[1], 1U, &e_peers[1], 3U, 79U, 83U);
  xaios_cluster_t d;
  if (xaios_cluster_init(&d, 1U, 9U, d_peers, 2U) != XAIOS_ENGINE_OK) return 1;

  uint64_t live = 0U;
  uint64_t total = 0U;
  int quorum = -1;
  /* Alone, before anyone has been heard from: one of three, no quorum. A
     node that thought otherwise would act on its own authority during a boot
     while the rest of the cluster was still coming up. */
  if (xaios_cluster_quorum(&d, &live, &total, &quorum) != XAIOS_ENGINE_OK ||
      live != 1U || total != 3U || quorum != 0) {
    return 1;
  }

  const uint64_t deadline = 20000000000ULL; /* twenty seconds, in nanoseconds */
  const uint64_t heard_at = 1000000000ULL;
  d_peers[0].state = XAIOS_CLUSTER_NODE_ONLINE;
  d_peers[1].state = XAIOS_CLUSTER_NODE_ONLINE;
  if (xaios_cluster_note_heard(&d, 2U, heard_at) != XAIOS_ENGINE_OK ||
      xaios_cluster_note_heard(&d, 3U, heard_at) != XAIOS_ENGINE_OK) {
    return 1;
  }
  if (xaios_cluster_quorum(&d, &live, &total, &quorum) != XAIOS_ENGINE_OK ||
      live != 3U || total != 3U || quorum != 1) {
    return 1;
  }

  /* A clock reading zero cannot be recorded, and an unknown node cannot be
     noted at all -- both would otherwise write into a peer table by
     accident. */
  if (xaios_cluster_note_heard(&d, 2U, 0U) != XAIOS_ENGINE_ERR_INVALID ||
      xaios_cluster_note_heard(&d, 99U, heard_at) !=
          XAIOS_ENGINE_ERR_NOT_FOUND) {
    return 1;
  }

  /* Exactly at the deadline is not past it. This is the check that fails if
     the comparison is ever loosened to >=, and it is the difference between
     a detector that is strict about its own definition and one that is a
     little eager -- which, on a busy machine, is the difference between a
     stable cluster and one that evicts a member every few minutes. */
  uint64_t expired = UINT64_MAX;
  if (xaios_cluster_expire_silent(&d, heard_at + deadline, deadline,
                                  &expired) != XAIOS_ENGINE_OK ||
      expired != 0U || d_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE) {
    return 1;
  }
  /* A frame from node 2 arrives; node 3 stays silent. One of them must be
     expired and the other must not, which is the check a detector that
     expires the whole table cannot pass. */
  if (xaios_cluster_note_heard(&d, 2U, heard_at + deadline) !=
      XAIOS_ENGINE_OK) {
    return 1;
  }
  if (xaios_cluster_expire_silent(&d, heard_at + deadline + 1U, deadline,
                                  &expired) != XAIOS_ENGINE_OK ||
      expired != 1U || d_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE ||
      d_peers[1].state != XAIOS_CLUSTER_NODE_OFFLINE) {
    return 1;
  }
  /* Two of three still decides. */
  if (xaios_cluster_quorum(&d, &live, &total, &quorum) != XAIOS_ENGINE_OK ||
      live != 2U || total != 3U || quorum != 1) {
    return 1;
  }

  /* A peer that has never spoken is not expired, however long the clock has
     run. This is the boot case: a node brought up first would otherwise
     declare every node that had not finished booting dead, and then have to
     un-declare them, which is a membership flap caused by nothing but start
     order. */
  d_peers[0].state = XAIOS_CLUSTER_NODE_OFFLINE; /* asking about node 3 only */
  d_peers[1].state = XAIOS_CLUSTER_NODE_ONLINE;
  d_peers[1].last_heard_nanos = 0U;
  if (xaios_cluster_expire_silent(&d, heard_at + deadline * 100U, deadline,
                                  &expired) != XAIOS_ENGINE_OK ||
      expired != 0U || d_peers[1].state != XAIOS_CLUSTER_NODE_ONLINE) {
    return 1;
  }
  /* Put it back where the rest of this expects it. */
  d_peers[1].state = XAIOS_CLUSTER_NODE_OFFLINE;
  d_peers[1].last_heard_nanos = heard_at;

  /* A clock that has gone backwards must not expire anyone. Time going
     backwards is a real event -- a corrected clock, a migrated guest -- and
     the answer to it is to wait, not to evict half the cluster. */
  d_peers[0].state = XAIOS_CLUSTER_NODE_ONLINE;
  d_peers[0].last_heard_nanos = heard_at + deadline * 10U;
  if (xaios_cluster_expire_silent(&d, heard_at, deadline, &expired) !=
          XAIOS_ENGINE_OK ||
      expired != 0U || d_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE) {
    return 1;
  }
  d_peers[0].last_heard_nanos = heard_at + deadline;

  /* Four nodes split two and two: neither half has a majority, and neither
     may act. This is the case a rule written as "at least half" gets wrong,
     and getting it wrong means both halves proceed -- the split brain the
     whole idea of quorum exists to prevent. The three-node cluster above
     cannot catch that mistake, because at three the two rules agree. */
  xaios_cluster_peer_t four_peers[3];
  memset(four_peers, 0, sizeof(four_peers));
  for (uint64_t i = 0U; i < 3U; ++i) {
    four_peers[i].node_id = i + 2U;
    set_key(four_peers[i].transmit_key, (uint8_t)(107U + i));
    set_key(four_peers[i].receive_key, (uint8_t)(113U + i));
  }
  xaios_cluster_t four;
  if (xaios_cluster_init(&four, 1U, 9U, four_peers, 3U) != XAIOS_ENGINE_OK) {
    return 1;
  }
  four_peers[0].state = XAIOS_CLUSTER_NODE_ONLINE;
  if (xaios_cluster_quorum(&four, &live, &total, &quorum) !=
          XAIOS_ENGINE_OK ||
      live != 2U || total != 4U || quorum != 0) {
    return 1;
  }
  four_peers[1].state = XAIOS_CLUSTER_NODE_ONLINE;
  if (xaios_cluster_quorum(&four, &live, &total, &quorum) !=
          XAIOS_ENGINE_OK ||
      live != 3U || total != 4U || quorum != 1) {
    return 1;
  }

  /* An expired peer is not expired twice: the count is transitions, not
     offline members, or a caller that logs on every non-zero count would
     report the same death for as long as the node stayed down. */
  if (xaios_cluster_expire_silent(&d, heard_at + deadline * 4U, deadline,
                                  &expired) != XAIOS_ENGINE_OK ||
      expired != 1U) {
    return 1;
  }

  /* Ownership across the failure: whoever the dead node owned moves, and
     nobody else does. This is the property that makes a survivor's answer
     usable -- if losing one node reshuffled every expert, a failure would
     cost the cluster every cached weight it held rather than a third of
     them, and two survivors racing to reload everything is its own outage. */
  xaios_cluster_peer_t f_peers[2];
  xaios_cluster_peer_t g_peers[2];
  connect_peers(&f_peers[0], 1U, &g_peers[0], 2U, 89U, 97U);
  connect_peers(&f_peers[1], 1U, &g_peers[1], 3U, 101U, 103U);
  xaios_cluster_t whole;
  if (xaios_cluster_init(&whole, 1U, 9U, f_peers, 2U) != XAIOS_ENGINE_OK) {
    return 1;
  }
  f_peers[0].state = XAIOS_CLUSTER_NODE_ONLINE;
  f_peers[1].state = XAIOS_CLUSTER_NODE_ONLINE;
  const uint64_t owned_experts[8] = {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U};
  xaios_expert_assignment_t before[8];
  xaios_expert_assignment_t after[8];
  if (xaios_cluster_route_experts(&whole, model_uuid, 7U, 1U, owned_experts,
                                  8U, before, 8U) != XAIOS_ENGINE_OK) {
    return 1;
  }
  if (xaios_cluster_note_heard(&whole, 2U, heard_at) != XAIOS_ENGINE_OK ||
      xaios_cluster_note_heard(&whole, 3U, heard_at) != XAIOS_ENGINE_OK ||
      xaios_cluster_expire_silent(&whole, heard_at + deadline * 2U, deadline,
                                  &expired) != XAIOS_ENGINE_OK ||
      expired != 2U) {
    return 1;
  }
  /* Bring node 2 back -- one node dead, not two, or there is no reassignment
     to observe and the survivor owns everything trivially. */
  if (xaios_cluster_set_peer_state(&whole, 2U, XAIOS_CLUSTER_NODE_ONLINE) !=
          XAIOS_ENGINE_OK ||
      xaios_cluster_route_experts(&whole, model_uuid, 7U, 1U, owned_experts,
                                  8U, after, 8U) != XAIOS_ENGINE_OK) {
    return 1;
  }
  uint64_t moved = 0U;
  for (uint64_t i = 0U; i < 8U; ++i) {
    uint64_t expert = owned_experts[i];
    uint64_t owner_before = 0U;
    uint64_t owner_after = 0U;
    for (uint64_t j = 0U; j < 8U; ++j) {
      if (before[j].expert_id == expert) owner_before = before[j].node_id;
      if (after[j].expert_id == expert) owner_after = after[j].node_id;
    }
    if (owner_after == 3U) return 1; /* a dead node owns nothing */
    if (owner_before == 3U) {
      moved += 1U;
      continue;
    }
    if (owner_before != owner_after) return 1; /* nobody else moved */
  }
  /* If the dead node happened to own none of these eight experts the loop
     above proves nothing at all, so say so rather than pass. */
  if (moved == 0U) return 1;

  puts("cluster: mutual authentication, replay rejection, deterministic routing, failure reroute, and stable reduction passed");
  puts("cluster: silence expiry, three-node quorum, and ownership stability across a failure passed");
  return 0;
}
