/*
 * Carry a sealed cluster frame over a real network connection.
 *
 * engine/src/cluster.c has had framing, sealing, peer state and owner
 * selection since it was written, and no transport: nothing in it ever opened
 * a socket, so every test of it handed a buffer from one function to another
 * inside one process. That proves the framing and nothing about a cluster,
 * which is two machines or it is not a cluster.
 *
 * This connects to a peer, sends a sealed JOIN, reads the reply, and opens it.
 * The sealing is the same code the hosted tests exercise; what is new is that
 * the bytes go through a socket, a network stack and a host in between, and
 * come back having been somewhere.
 *
 * The peer is told to us rather than discovered. Discovery is a separate
 * problem and inventing one here would test the invention.
 *
 * Either end. Built with XAIOS_CLUSTER_ROLE_SERVER this listens instead of
 * dialling, which is what lets the peer be a second XAIOS machine rather than
 * a program on a host reading the format out of a header file. Two XAIOS
 * machines agreeing is a different claim from XAIOS and a Python script
 * agreeing, and it is the one a cluster rests on.
 *
 * The address to dial is a build-time figure so that one image can be pointed
 * at a peer across a real network -- XAIOS_CLUSTER_PEER_IPV4_{A,B,C,D} -- and
 * defaults to the host side of the QEMU user network, which is where the
 * host-process peer has always been.
 *
 * There is a second program in this file, built with
 * XAIOS_CLUSTER_MESH_NODES=3, and it exists because everything described
 * above tests a cluster whose members are polite. Membership here moves on
 * frames that say what they mean -- a LEAVE takes a node offline, a JOIN
 * brings it back -- and machines do not usually fail that way. They lose
 * power, panic, or have a cable pulled, and say nothing at all. The mesh at
 * the bottom of this file has no LEAVE in it: three nodes heartbeat to each
 * other and a node is judged dead when a deadline passes with nothing heard
 * from it. Three, because until there is a third node there is no majority to
 * be in, and a survivor's decision cannot be distinguished from a guess.
 */

#include "clustertest_shared.h"

#ifndef CLUSTER_PEER_PORT
#define CLUSTER_PEER_PORT 7799U
#endif

#if !XAIOS_CLUSTER_MESH_NODES
static xaios_cluster_peer_t g_peers[1];
static xaios_cluster_t g_cluster;
static u64 g_ownership_version;
#endif

int main(void) {
#if XAIOS_CLUSTER_MESH_NODES
  return clustertest_mesh_main();
#else
  xaios_log("/bin/clustertest: cluster data plane over TCP\n");

  /* Every peer slot has to name a real node before init: it rejects a table
     with an empty or duplicated entry rather than accepting one and failing
     later, so the table is filled first and sized to the peers there are. */
  xaios_memzero(g_peers, sizeof(g_peers));
  g_peers[0].node_id = CLUSTER_PEER_NODE_ID;
  g_peers[0].state = XAIOS_CLUSTER_NODE_ONLINE;
  g_peers[0].next_transmit_nonce = 1ULL;
  g_peers[0].last_received_nonce = 0ULL;
  for (u64 i = 0; i < XAIOS_CLUSTER_KEY_SIZE; ++i) {
    /* One key for both directions here. A deployment would derive one per
       direction; this test shares the key with the peer so that each end can
       verify the other, which is the property being tested. */
    g_peers[0].transmit_key[i] = clustertest_shared_key[i];
    g_peers[0].receive_key[i] = clustertest_shared_key[i];
  }
  if (xaios_cluster_init(&g_cluster, CLUSTER_LOCAL_NODE_ID, 1ULL, g_peers,
                         1ULL) != XAIOS_ENGINE_OK) {
    return clustertest_fail("cluster init failed");
  }

#if XAIOS_CLUSTER_ROLE_SERVER
  /* Listen, open what arrives, and seal the same payload back addressed to
     the sender. The client's checks are the mirror of these, so a run that
     passes on both ends has had every frame verified twice by two independent
     machines rather than once by a program that also wrote it. */
  u64 listener = 0;
  if (xaios_net_listen(CLUSTER_PEER_PORT, &listener) != 0) {
    return clustertest_fail("could not listen for a cluster peer");
  }
  xaios_log_u64("/bin/clustertest: listening port=", (u64)CLUSTER_PEER_PORT,
                "\n");

  u64 socket = 0;
  /* Long enough for the other machine to finish booting and dial. Both ends
     are emulated and one of them may be on another continent. */
  u64 accept_deadline = xaios_clock_nanos() + 600000000000ULL;
  int accepted = -1;
  /* Any non-zero means "nothing yet", not "never": the accept syscall reports
     an empty backlog as an error rather than blocking, which is why sshd
     treats a failed accept as a reason to come round again rather than a
     reason to stop. Distinguishing BUSY from the rest, as the first version
     did, gave up on the first turn of the loop and reported no peer -- with
     the peer still booting. The deadline is what ends this, not the first
     unsuccessful call. */
  while (xaios_clock_nanos() < accept_deadline) {
    accepted = xaios_net_accept(listener, &socket);
    if (accepted == 0) break;
  }
  if (accepted != 0) {
    (void)xaios_net_close(listener);
    xaios_log("/bin/clustertest: no cluster peer connected; data plane not "
              "exercised\n");
    return 0;
  }

  u8 inbound[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 got = 0;
  if (clustertest_read_exactly(socket, inbound, (u64)XAIOS_CLUSTER_HEADER_SIZE,
                   30000000000ULL, &got) != 0) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("the peer sent no frame header");
  }
  u64 inbound_length = clustertest_frame_length_from_header(inbound);
  if (inbound_length > sizeof(inbound) ||
      inbound_length < (u64)XAIOS_CLUSTER_HEADER_SIZE) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("the peer announced an impossible frame length");
  }
  u64 rest = inbound_length - (u64)XAIOS_CLUSTER_HEADER_SIZE;
  if (rest != 0U &&
      clustertest_read_exactly(socket, inbound + XAIOS_CLUSTER_HEADER_SIZE, rest,
                   30000000000ULL, &got) != 0) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("the peer's frame was shorter than its header claimed");
  }

  xaios_cluster_message_t inbound_message;
  xaios_memzero(&inbound_message, sizeof(inbound_message));
  if (xaios_cluster_open(&g_cluster, inbound, (size_t)inbound_length,
                         &inbound_message) != XAIOS_ENGINE_OK) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("the peer's frame did not open");
  }
  if (inbound_message.sender_node_id != CLUSTER_PEER_NODE_ID ||
      inbound_message.receiver_node_id != CLUSTER_LOCAL_NODE_ID) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("the frame was not addressed to this node");
  }
  xaios_log_u64("/bin/clustertest: opened peer frame bytes=", inbound_length,
                "");
  xaios_log_u64(" opcode=", (u64)inbound_message.opcode, "");
  xaios_log_u64(" nonce=", inbound_message.nonce, "\n");

  /* The same frame a second time must be refused here too. The client checks
     its own replay; this checks that a node refuses one arriving from the
     network, which is the direction an attacker would use. */
  xaios_cluster_message_t inbound_replay;
  xaios_memzero(&inbound_replay, sizeof(inbound_replay));
  if (xaios_cluster_open(&g_cluster, inbound, (size_t)inbound_length,
                         &inbound_replay) == XAIOS_ENGINE_OK) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("a replayed frame from the network was accepted");
  }

  u8 outbound[XAIOS_CLUSTER_MAX_MESSAGE];
  size_t resealed = 0;
  if (xaios_cluster_seal(&g_cluster, CLUSTER_PEER_NODE_ID,
                         inbound_message.opcode, inbound_message.payload,
                         inbound_message.payload_length, outbound,
                         sizeof(outbound), &resealed) != XAIOS_ENGINE_OK) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("sealing the reply failed");
  }
  u64 replied = 0;
  if (xaios_net_send(socket, outbound, (u64)resealed, &replied) != 0 ||
      replied != (u64)resealed) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return clustertest_fail("could not send the sealed reply");
  }
  xaios_log_u64("/bin/clustertest: sealed reply bytes=", (u64)resealed, "\n");

  /* The peer is online because a frame from it arrived and opened. */
  clustertest_log_ownership(&g_cluster, g_peers, &g_ownership_version, "joined");
  (void)xaios_net_close(socket);

  /* Partition and recovery each arrive on their own connection, so this
     accepts until it has seen both rather than assuming what the next one
     carries. The first version assumed, took the client's LEAVE for its
     rejoin, and failed a machine that was behaving correctly -- which is the
     shape of most distributed-systems test bugs: an ordering the code did not
     expect but the network is entitled to produce. */
  int partitioned = 0;
  int recovered = 0;
  u64 membership_deadline = xaios_clock_nanos() + 180000000000ULL;
  while (recovered == 0 && xaios_clock_nanos() < membership_deadline) {
    u64 next_socket = 0;
    if (xaios_net_accept(listener, &next_socket) != 0) continue;
    xaios_cluster_message_t frame;
    if (clustertest_recv_sealed(&g_cluster, next_socket, &frame, 30000000000ULL) != 0) {
      (void)xaios_net_close(next_socket);
      continue;
    }
    if (frame.opcode == (u16)XAIOS_CLUSTER_LEAVE) {
      (void)xaios_net_close(next_socket);
      if (g_peers[0].state != XAIOS_CLUSTER_NODE_OFFLINE) {
        (void)xaios_net_close(listener);
        return clustertest_fail("a leave did not take the peer offline");
      }
      if (partitioned == 0) {
        clustertest_log_ownership(&g_cluster, g_peers, &g_ownership_version, "partitioned");
        partitioned = 1;
      }
      continue;
    }
    if (frame.opcode == (u16)XAIOS_CLUSTER_JOIN) {
      if (partitioned == 0) {
        (void)xaios_net_close(next_socket);
        (void)xaios_net_close(listener);
        return clustertest_fail("the peer rejoined without ever having left");
      }
      if (clustertest_send_sealed(&g_cluster, next_socket, (u16)XAIOS_CLUSTER_JOIN_ACK, 0, 0) != 0) {
        (void)xaios_net_close(next_socket);
        (void)xaios_net_close(listener);
        return clustertest_fail("could not acknowledge the rejoin");
      }
      (void)xaios_net_close(next_socket);
      if (g_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE) {
        (void)xaios_net_close(listener);
        return clustertest_fail("a rejoin did not bring the peer back online");
      }
      clustertest_log_ownership(&g_cluster, g_peers, &g_ownership_version, "recovered");
      recovered = 1;
      continue;
    }
    (void)xaios_net_close(next_socket);
  }
  (void)xaios_net_close(listener);
  if (partitioned == 0) return clustertest_fail("the peer never left");
  if (recovered == 0) return clustertest_fail("the peer never came back");

  xaios_log("/bin/clustertest: cluster data plane over TCP passed\n");
  xaios_log("/bin/clustertest: membership join/partition/recovery passed\n");
  return 0;
#else
  u8 wire[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 wire_length = 0;
  static const char payload[] = "xaios-cluster-join";
  size_t sealed = 0;
  if (xaios_cluster_seal(&g_cluster, CLUSTER_PEER_NODE_ID,
                         (u16)XAIOS_CLUSTER_JOIN, payload,
                         (u16)(sizeof(payload) - 1U), wire, sizeof(wire),
                         &sealed) != XAIOS_ENGINE_OK) {
    return clustertest_fail("sealing the join frame failed");
  }
  wire_length = (u64)sealed;
  xaios_log_u64("/bin/clustertest: sealed frame bytes=", wire_length, "\n");

  /* The host side of the user network, which is where the gate's peer runs.
     A guest reaches it at 10.0.2.2 by convention, the same address the DHCP
     server and the resolver live at. */
  xaios_ip_addr_user_t address;
  xaios_memzero(&address, sizeof(address));
  address.family = 4U;
  address.addr[0] = (u8)XAIOS_CLUSTER_PEER_IPV4_A;
  address.addr[1] = (u8)XAIOS_CLUSTER_PEER_IPV4_B;
  address.addr[2] = (u8)XAIOS_CLUSTER_PEER_IPV4_C;
  address.addr[3] = (u8)XAIOS_CLUSTER_PEER_IPV4_D;

  u64 socket = 0;
  if (xaios_net_connect(&address, CLUSTER_PEER_PORT, &socket) != 0) {
    /* No peer is the ordinary case: most boots of this machine are not part
       of a cluster, and a node that refused to start because the other end
       was absent would be a worse thing than one that says so. The gate that
       cares starts a peer first and requires the line below it. */
    xaios_log("/bin/clustertest: no cluster peer reachable; data plane not "
              "exercised\n");
    return 0;
  }

  u64 sent = 0;
  if (xaios_net_send(socket, wire, wire_length, &sent) != 0 ||
      sent != wire_length) {
    (void)xaios_net_close(socket);
    return clustertest_fail("could not send the sealed frame");
  }

  u8 reply[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 total = 0;
  /* Ten seconds, which is a network's timescale rather than a loop's. The
     first version of this counted iterations instead, finished four thousand
     of them in microseconds, and reported a short read of zero bytes -- which
     read as the peer failing and was this loop being faster than a wire. */
  int last_status = clustertest_read_exactly(socket, reply, wire_length, 10000000000ULL,
                                 &total);
  (void)xaios_net_close(socket);
  if (total != wire_length) {
    xaios_log_u64("/bin/clustertest: short read bytes=", total, "");
    xaios_log_u64(" expected=", wire_length, "");
    xaios_log_u64(" last_status=", (u64)(s64)last_status, "\n");
    return clustertest_fail("the peer returned a frame of the wrong length");
  }

  xaios_cluster_message_t message;
  xaios_memzero(&message, sizeof(message));
  if (xaios_cluster_open(&g_cluster, reply, (size_t)total, &message) !=
      XAIOS_ENGINE_OK) {
    return clustertest_fail("the returned frame did not open");
  }
  if (message.opcode != (u16)XAIOS_CLUSTER_JOIN ||
      message.sender_node_id != CLUSTER_PEER_NODE_ID ||
      message.receiver_node_id != CLUSTER_LOCAL_NODE_ID ||
      message.payload_length != (u16)(sizeof(payload) - 1U)) {
    return clustertest_fail("the reply was not addressed back from the peer");
  }
  for (u64 i = 0; i < message.payload_length; ++i) {
    if (message.payload[i] != (u8)payload[i]) {
      return clustertest_fail("the payload changed in flight");
    }
  }

  /* The reply's nonce has now been seen. Replaying it must be refused -- that
     is what the nonce is for, and a data plane that accepts a replayed frame
     is worse than one with no transport at all. */
  xaios_cluster_message_t replay;
  xaios_memzero(&replay, sizeof(replay));
  if (xaios_cluster_open(&g_cluster, reply, (size_t)total, &replay) ==
      XAIOS_ENGINE_OK) {
    return clustertest_fail("a replayed frame was accepted");
  }

  xaios_log_u64("/bin/clustertest: round trip verified bytes=", wire_length,
                "");
  xaios_log_u64(" opcode=", (u64)message.opcode, "");
  xaios_log_u64(" nonce=", message.nonce, "\n");
  clustertest_log_ownership(&g_cluster, g_peers, &g_ownership_version, "joined");

  /* Leave, on the connection that is still open from the exchange above.
     Saying so is better than vanishing: both are partitions to the other end,
     and only one of them tells it why. The socket from the round trip was
     closed already, so this opens another -- which is also what makes the
     next phase a reconnection rather than a continuation. */
  u64 leave_socket = 0;
  if (xaios_net_connect(&address, CLUSTER_PEER_PORT, &leave_socket) != 0) {
    return clustertest_fail("could not reconnect to announce leaving");
  }
  if (clustertest_send_sealed(&g_cluster, leave_socket, (u16)XAIOS_CLUSTER_LEAVE, 0, 0) != 0) {
    (void)xaios_net_close(leave_socket);
    return clustertest_fail("could not send the leave frame");
  }
  (void)xaios_net_close(leave_socket);
  (void)xaios_cluster_set_peer_state(&g_cluster, CLUSTER_PEER_NODE_ID,
                                     XAIOS_CLUSTER_NODE_OFFLINE);
  clustertest_log_ownership(&g_cluster, g_peers, &g_ownership_version, "partitioned");

  /* Rejoin. The peer has been offline on both sides; ownership has to come
     back to what it was, because the membership has. If it does not, the two
     ends will disagree about who owns an expert the moment one of them
     forgets a node it once knew. */
  u64 rejoin_socket = 0;
  if (xaios_net_connect(&address, CLUSTER_PEER_PORT, &rejoin_socket) != 0) {
    return clustertest_fail("could not reconnect to rejoin");
  }
  static const char rejoin_payload[] = "xaios-cluster-rejoin";
  if (clustertest_send_sealed(&g_cluster, rejoin_socket, (u16)XAIOS_CLUSTER_JOIN, rejoin_payload,
                  (u16)(sizeof(rejoin_payload) - 1U)) != 0) {
    (void)xaios_net_close(rejoin_socket);
    return clustertest_fail("could not send the rejoin frame");
  }
  xaios_cluster_message_t acknowledgement;
  if (clustertest_recv_sealed(&g_cluster, rejoin_socket, &acknowledgement, 30000000000ULL) != 0) {
    (void)xaios_net_close(rejoin_socket);
    return clustertest_fail("the peer did not acknowledge the rejoin");
  }
  (void)xaios_net_close(rejoin_socket);
  if (acknowledgement.opcode != (u16)XAIOS_CLUSTER_JOIN_ACK) {
    return clustertest_fail("the rejoin was answered with the wrong opcode");
  }
  if (g_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE) {
    return clustertest_fail("an acknowledged rejoin did not bring the peer back online");
  }
  clustertest_log_ownership(&g_cluster, g_peers, &g_ownership_version, "recovered");

  xaios_log("/bin/clustertest: cluster data plane over TCP passed\n");
  xaios_log("/bin/clustertest: membership join/partition/recovery passed\n");
  return 0;
#endif /* XAIOS_CLUSTER_ROLE_SERVER */
#endif /* XAIOS_CLUSTER_MESH_NODES */
}
