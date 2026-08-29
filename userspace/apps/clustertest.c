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
 */

#include <xaios_user.h>

#include <xaios_engine/cluster.h>

#define CLUSTER_PEER_PORT 7799U
#define CLUSTER_PEER_NODE_ID 2ULL
#define CLUSTER_LOCAL_NODE_ID 1ULL

static xaios_cluster_peer_t g_peers[1];
static xaios_cluster_t g_cluster;

/* The key both ends share. A real deployment derives one; this is a test
   whose point is the transport, and a key that is generated here would have to
   be got to the other end somehow, which is the problem this is not solving. */
static const u8 k_shared_key[XAIOS_CLUSTER_KEY_SIZE] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};

static int fail(const char *why) {
  xaios_log("/bin/clustertest: ");
  xaios_log(why);
  xaios_log("\n");
  return 1;
}

int main(void) {
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
    g_peers[0].transmit_key[i] = k_shared_key[i];
    g_peers[0].receive_key[i] = k_shared_key[i];
  }
  if (xaios_cluster_init(&g_cluster, CLUSTER_LOCAL_NODE_ID, 1ULL, g_peers,
                         1ULL) != XAIOS_ENGINE_OK) {
    return fail("cluster init failed");
  }

  u8 wire[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 wire_length = 0;
  static const char payload[] = "xaios-cluster-join";
  size_t sealed = 0;
  if (xaios_cluster_seal(&g_cluster, CLUSTER_PEER_NODE_ID,
                         (u16)XAIOS_CLUSTER_JOIN, payload,
                         (u16)(sizeof(payload) - 1U), wire, sizeof(wire),
                         &sealed) != XAIOS_ENGINE_OK) {
    return fail("sealing the join frame failed");
  }
  wire_length = (u64)sealed;
  xaios_log_u64("/bin/clustertest: sealed frame bytes=", wire_length, "\n");

  /* The host side of the user network, which is where the gate's peer runs.
     A guest reaches it at 10.0.2.2 by convention, the same address the DHCP
     server and the resolver live at. */
  xaios_ip_addr_user_t address;
  xaios_memzero(&address, sizeof(address));
  address.family = 4U;
  address.addr[0] = 10U;
  address.addr[1] = 0U;
  address.addr[2] = 2U;
  address.addr[3] = 2U;

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
    return fail("could not send the sealed frame");
  }

  u8 reply[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 received = 0;
  u64 total = 0;
  /* Read until the whole frame is in hand. A stream gives back what it has,
     not what was asked for, and treating a short read as the message is how a
     protocol works in testing and fails on a busy network.
     
     Busy and zero both mean "nothing yet" rather than "no more": the first is
     the stack saying it has not finished, the second that no bytes have
     arrived in this instant. Treating either as the end gave up on a frame the
     peer had already sent, and the attempt bound is what keeps that from
     becoming a machine that never stops waiting. */
  int last_status = 0;
  /* A deadline rather than a number of attempts. Four thousand tight
     iterations complete in microseconds, long before a frame has crossed to
     the host and back, so the first version of this gave up before the peer
     had answered and reported a short read of zero bytes -- which reads as the
     peer failing and was this loop being faster than a network. */
  u64 deadline = xaios_clock_nanos() + 10000000000ULL;
  while (total < wire_length && xaios_clock_nanos() < deadline) {
    int status = xaios_net_recv(socket, reply + total,
                                sizeof(reply) - total, &received);
    last_status = status;
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0) break;
    if (received == 0U) continue;
    total += received;
  }
  (void)xaios_net_close(socket);
  if (total != wire_length) {
    xaios_log_u64("/bin/clustertest: short read bytes=", total, "");
    xaios_log_u64(" expected=", wire_length, "");
    xaios_log_u64(" last_status=", (u64)(s64)last_status, "\n");
    return fail("the peer returned a frame of the wrong length");
  }

  xaios_cluster_message_t message;
  xaios_memzero(&message, sizeof(message));
  if (xaios_cluster_open(&g_cluster, reply, (size_t)total, &message) !=
      XAIOS_ENGINE_OK) {
    return fail("the returned frame did not open");
  }
  if (message.opcode != (u16)XAIOS_CLUSTER_JOIN ||
      message.sender_node_id != CLUSTER_PEER_NODE_ID ||
      message.receiver_node_id != CLUSTER_LOCAL_NODE_ID ||
      message.payload_length != (u16)(sizeof(payload) - 1U)) {
    return fail("the reply was not addressed back from the peer");
  }
  for (u64 i = 0; i < message.payload_length; ++i) {
    if (message.payload[i] != (u8)payload[i]) {
      return fail("the payload changed in flight");
    }
  }

  /* The reply's nonce has now been seen. Replaying it must be refused -- that
     is what the nonce is for, and a data plane that accepts a replayed frame
     is worse than one with no transport at all. */
  xaios_cluster_message_t replay;
  xaios_memzero(&replay, sizeof(replay));
  if (xaios_cluster_open(&g_cluster, reply, (size_t)total, &replay) ==
      XAIOS_ENGINE_OK) {
    return fail("a replayed frame was accepted");
  }

  xaios_log_u64("/bin/clustertest: round trip verified bytes=", wire_length,
                "");
  xaios_log_u64(" opcode=", (u64)message.opcode, "");
  xaios_log_u64(" nonce=", message.nonce, "\n");
  xaios_log("/bin/clustertest: cluster data plane over TCP passed\n");
  return 0;
}
