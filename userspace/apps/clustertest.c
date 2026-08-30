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
 */

#include <xaios_user.h>

#include <xaios_engine/cluster.h>

#ifndef CLUSTER_PEER_PORT
#define CLUSTER_PEER_PORT 7799U
#endif

/* The two ends are mirror images: each is the other's peer, so the node ids
   swap with the role and the sealing keys stay shared. */
#if XAIOS_CLUSTER_ROLE_SERVER
#define CLUSTER_LOCAL_NODE_ID 2ULL
#define CLUSTER_PEER_NODE_ID 1ULL
#else
#define CLUSTER_LOCAL_NODE_ID 1ULL
#define CLUSTER_PEER_NODE_ID 2ULL
#endif

/* Where a client dials. The default is the host side of the QEMU user
   network, the same address the DHCP server and the resolver live at. */
#ifndef XAIOS_CLUSTER_PEER_IPV4_A
#define XAIOS_CLUSTER_PEER_IPV4_A 10U
#define XAIOS_CLUSTER_PEER_IPV4_B 0U
#define XAIOS_CLUSTER_PEER_IPV4_C 2U
#define XAIOS_CLUSTER_PEER_IPV4_D 2U
#endif

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


/* Read exactly `want` bytes, or give up when the deadline passes.
 *
 * A stream returns what it has rather than what was asked for. Busy and zero
 * both mean "nothing yet" rather than "no more": the first is the stack saying
 * it has not finished, the second that nothing arrived in this instant.
 * Treating either as the end is how a protocol works in testing and fails on a
 * real network -- and a deadline rather than an iteration count is the same
 * lesson, since a tight loop finishes millions of turns before a frame has
 * crossed the Atlantic. */
static int read_exactly(u64 socket, u8 *buffer, u64 want, u64 timeout_nanos,
                        u64 *out_total) {
  u64 total = 0;
  u64 deadline = xaios_clock_nanos() + timeout_nanos;
  int last_status = 0;
  while (total < want && xaios_clock_nanos() < deadline) {
    u64 received = 0;
    int status = xaios_net_recv(socket, buffer + total, want - total,
                                &received);
    last_status = status;
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0) break;
    if (received == 0U) continue;
    total += received;
  }
  *out_total = total;
  return total == want ? 0 : (last_status != 0 ? last_status : -1);
}

#if XAIOS_CLUSTER_ROLE_SERVER
/* The frame's own length, read out of the header it starts with.
 *
 * A client knows how many bytes to expect because it sealed them. A server
 * does not, so it reads the fixed header, takes the payload length from it,
 * and reads exactly the rest. Guessing instead -- reading "whatever arrives"
 * and treating it as a frame -- is how two machines agree on a busy day and
 * disagree on a slow one. */
static u64 frame_length_from_header(const u8 *header) {
  u64 payload_length = (u64)header[40] | ((u64)header[41] << 8);
  return (u64)XAIOS_CLUSTER_HEADER_SIZE + payload_length +
         (u64)XAIOS_CLUSTER_TAG_SIZE;
}
#endif

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

#if XAIOS_CLUSTER_ROLE_SERVER
  /* Listen, open what arrives, and seal the same payload back addressed to
     the sender. The client's checks are the mirror of these, so a run that
     passes on both ends has had every frame verified twice by two independent
     machines rather than once by a program that also wrote it. */
  u64 listener = 0;
  if (xaios_net_listen(CLUSTER_PEER_PORT, &listener) != 0) {
    return fail("could not listen for a cluster peer");
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
  if (read_exactly(socket, inbound, (u64)XAIOS_CLUSTER_HEADER_SIZE,
                   30000000000ULL, &got) != 0) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("the peer sent no frame header");
  }
  u64 inbound_length = frame_length_from_header(inbound);
  if (inbound_length > sizeof(inbound) ||
      inbound_length < (u64)XAIOS_CLUSTER_HEADER_SIZE) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("the peer announced an impossible frame length");
  }
  u64 rest = inbound_length - (u64)XAIOS_CLUSTER_HEADER_SIZE;
  if (rest != 0U &&
      read_exactly(socket, inbound + XAIOS_CLUSTER_HEADER_SIZE, rest,
                   30000000000ULL, &got) != 0) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("the peer's frame was shorter than its header claimed");
  }

  xaios_cluster_message_t inbound_message;
  xaios_memzero(&inbound_message, sizeof(inbound_message));
  if (xaios_cluster_open(&g_cluster, inbound, (size_t)inbound_length,
                         &inbound_message) != XAIOS_ENGINE_OK) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("the peer's frame did not open");
  }
  if (inbound_message.sender_node_id != CLUSTER_PEER_NODE_ID ||
      inbound_message.receiver_node_id != CLUSTER_LOCAL_NODE_ID) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("the frame was not addressed to this node");
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
    return fail("a replayed frame from the network was accepted");
  }

  u8 outbound[XAIOS_CLUSTER_MAX_MESSAGE];
  size_t resealed = 0;
  if (xaios_cluster_seal(&g_cluster, CLUSTER_PEER_NODE_ID,
                         inbound_message.opcode, inbound_message.payload,
                         inbound_message.payload_length, outbound,
                         sizeof(outbound), &resealed) != XAIOS_ENGINE_OK) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("sealing the reply failed");
  }
  u64 replied = 0;
  if (xaios_net_send(socket, outbound, (u64)resealed, &replied) != 0 ||
      replied != (u64)resealed) {
    (void)xaios_net_close(socket);
    (void)xaios_net_close(listener);
    return fail("could not send the sealed reply");
  }
  (void)xaios_net_close(socket);
  (void)xaios_net_close(listener);
  xaios_log_u64("/bin/clustertest: sealed reply bytes=", (u64)resealed, "\n");
  xaios_log("/bin/clustertest: cluster data plane over TCP passed\n");
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
    return fail("could not send the sealed frame");
  }

  u8 reply[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 total = 0;
  /* Ten seconds, which is a network's timescale rather than a loop's. The
     first version of this counted iterations instead, finished four thousand
     of them in microseconds, and reported a short read of zero bytes -- which
     read as the peer failing and was this loop being faster than a wire. */
  int last_status = read_exactly(socket, reply, wire_length, 10000000000ULL,
                                 &total);
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
#endif
}
