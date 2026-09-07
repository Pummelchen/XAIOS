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

/* Which program this file is. Zero -- the default -- is the two-node data
   plane below: one machine dials, one listens, and membership moves because
   each end says what it is doing. Three is the mesh at the bottom of this
   file, where nobody announces anything and a node is judged by whether it
   is still speaking. They are separate programs sharing one source file
   because they share the framing, the key and the peer table, and because a
   machine only ever runs one of them. */
#ifndef XAIOS_CLUSTER_MESH_NODES
#define XAIOS_CLUSTER_MESH_NODES 0
#endif
#if XAIOS_CLUSTER_MESH_NODES != 0 && XAIOS_CLUSTER_MESH_NODES != 3
#error "XAIOS_CLUSTER_MESH_NODES is 0 (two-node data plane) or 3 (mesh)"
#endif

#if !XAIOS_CLUSTER_MESH_NODES
static xaios_cluster_peer_t g_peers[1];
static xaios_cluster_t g_cluster;
#endif

/* The key both ends share. A real deployment derives one; this is a test
   whose point is the transport, and a key that is generated here would have to
   be got to the other end somehow, which is the problem this is not solving. */
static const u8 k_shared_key[XAIOS_CLUSTER_KEY_SIZE] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};


#if !XAIOS_CLUSTER_MESH_NODES
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

#endif /* !XAIOS_CLUSTER_MESH_NODES */

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

#if !XAIOS_CLUSTER_MESH_NODES
/* Membership, and the ownership it decides.
 *
 * The framing tests above prove two machines can exchange a sealed frame. A
 * cluster needs more than that: the two ends have to agree on who owns what,
 * and go on agreeing across a peer leaving and coming back. That agreement is
 * the thing worth testing, because it is the thing a wrong answer silently
 * breaks -- two nodes each believing they own an expert is not an error
 * anywhere, it is just work done twice and a result nobody reconciles.
 *
 * `xaios_cluster_open` already moves membership: it marks the sender ONLINE
 * for any opcode but LEAVE, and OFFLINE for that one. So the transitions come
 * from frames that actually arrived rather than from a test asserting its own
 * bookkeeping.
 *
 * The version is local and deliberately not the wire epoch. `open` refuses a
 * frame whose epoch is not its own, so bumping the epoch to mark a membership
 * change would stop the two ends being able to speak -- the very thing being
 * measured. This counts observed changes instead, which is what an ownership
 * version is for. */
static u64 g_ownership_version;

/* One fixed expert, so both ends are asking the same question. Its owner is a
   hash of the identity against each candidate node, so which node wins is not
   predictable from here -- only that both ends must name the same one. */
static void log_ownership(const char *phase) {
  xaios_expert_identity_t identity;
  xaios_memzero(&identity, sizeof(identity));
  for (u64 i = 0; i < 16U; ++i) identity.model_uuid[i] = (u8)(i + 1U);
  identity.layer_id = 7ULL;
  identity.expert_id = 3ULL;
  identity.layout_id = 1U;
  /* The engine's own width, not the userspace alias: `u64` is unsigned long
     long here and `uint64_t` is unsigned long, which are the same size and
     not the same type. */
  uint64_t owner = 0;
  if (xaios_cluster_select_owner(&g_cluster, &identity, &owner) !=
      XAIOS_ENGINE_OK) {
    xaios_log("/bin/clustertest: owner selection failed\n");
    return;
  }
  ++g_ownership_version;
  xaios_log("/bin/clustertest: ownership phase=");
  xaios_log(phase);
  xaios_log_u64(" version=", g_ownership_version, "");
  xaios_log_u64(" owner=", (u64)owner, "");
  xaios_log_u64(" peer_online=",
                (u64)(g_peers[0].state == XAIOS_CLUSTER_NODE_ONLINE ? 1U : 0U),
                "\n");
}

static u8 g_outbound[XAIOS_CLUSTER_MAX_MESSAGE];

static int send_sealed(u64 socket, u16 opcode, const void *payload,
                       u16 length) {
  size_t sealed = 0;
  if (xaios_cluster_seal(&g_cluster, CLUSTER_PEER_NODE_ID, opcode, payload,
                         length, g_outbound, sizeof(g_outbound),
                         &sealed) != XAIOS_ENGINE_OK) {
    return -1;
  }
  u64 sent = 0;
  if (xaios_net_send(socket, g_outbound, (u64)sealed, &sent) != 0 ||
      sent != (u64)sealed) {
    return -1;
  }
  return 0;
}

/* Read one whole frame and open it. The length comes out of the header rather
   than from whatever arrived, for the reason frame_length_from_header gives. */
static int recv_sealed(u64 socket, xaios_cluster_message_t *message,
                       u64 timeout_nanos) {
  u8 buffer[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 got = 0;
  if (read_exactly(socket, buffer, (u64)XAIOS_CLUSTER_HEADER_SIZE,
                   timeout_nanos, &got) != 0) {
    return -1;
  }
  u64 length = frame_length_from_header(buffer);
  if (length > sizeof(buffer) || length < (u64)XAIOS_CLUSTER_HEADER_SIZE) {
    return -1;
  }
  u64 rest = length - (u64)XAIOS_CLUSTER_HEADER_SIZE;
  if (rest != 0U &&
      read_exactly(socket, buffer + XAIOS_CLUSTER_HEADER_SIZE, rest,
                   timeout_nanos, &got) != 0) {
    return -1;
  }
  xaios_memzero(message, sizeof(*message));
  if (xaios_cluster_open(&g_cluster, buffer, (size_t)length, message) !=
      XAIOS_ENGINE_OK) {
    return -1;
  }
  return 0;
}

#endif /* !XAIOS_CLUSTER_MESH_NODES */

static int fail(const char *why) {
  xaios_log("/bin/clustertest: ");
  xaios_log(why);
  xaios_log("\n");
  return 1;
}

#if XAIOS_CLUSTER_MESH_NODES
/* ---------------------------------------------------------------------------
 * Three nodes, heartbeats, and a peer that stops answering.
 *
 * The two-node program below this one moves membership on frames that say
 * what they mean: a LEAVE takes a node offline, a JOIN brings it back. That
 * is the polite case, and it is not the case that happens. Machines fail by
 * losing power, by panicking, by having a cable pulled or a switch reboot,
 * and every one of those looks the same from the outside: nothing arrives any
 * more. Detecting that needs a heartbeat -- traffic that exists so its
 * absence means something -- and a deadline, which is a judgement about how
 * long a healthy node may be quiet before it is presumed gone.
 *
 * It also needs a third node. At two, a survivor cannot distinguish a dead
 * peer from a cut wire, and both nodes deciding they are in charge is a
 * defensible answer for each of them. At three, a majority can be certain no
 * other majority exists, so a survivor pair may act and a lone survivor must
 * not. That is why this is three machines and not two, and it is the whole
 * reason the row this closes could not be closed by the two-node gate.
 *
 * Topology: every node listens on a port of its own and dials both others,
 * so each ordered pair gets a connection carrying heartbeats one way. Two
 * connections per pair rather than one shared in both directions, because
 * then a node's liveness rests entirely on frames it chose to send: nothing
 * it receives, and no connection somebody else opened towards it, can make it
 * look alive to a peer. Which peer spoke is read out of the frame's sender
 * field after it opens, never inferred from the socket it arrived on.
 *
 * The link state is deliberately NOT membership. Under QEMU's user network a
 * dial to a peer's forwarded port is accepted by the emulator on the host
 * before the guest behind it has been asked anything at all, so "connected"
 * can mean nothing more than "an emulator is running". A frame that opens --
 * right epoch, right receiver, fresh nonce, valid tag -- is the only evidence
 * this program will treat as a live peer, which is also the only evidence
 * worth anything on a network with an attacker on it.
 * ------------------------------------------------------------------------ */

#ifndef XAIOS_CLUSTER_NODE_ID
#define XAIOS_CLUSTER_NODE_ID 1U
#endif
#ifndef XAIOS_CLUSTER_MESH_PORT_1
#define XAIOS_CLUSTER_MESH_PORT_1 7801U
#endif
#ifndef XAIOS_CLUSTER_MESH_PORT_2
#define XAIOS_CLUSTER_MESH_PORT_2 7802U
#endif
#ifndef XAIOS_CLUSTER_MESH_PORT_3
#define XAIOS_CLUSTER_MESH_PORT_3 7803U
#endif

#define MESH_TOTAL ((u64)XAIOS_CLUSTER_MESH_NODES)
#define MESH_PEER_COUNT (XAIOS_CLUSTER_MESH_NODES - 1)
#define MESH_LOCAL_ID ((uint64_t)XAIOS_CLUSTER_NODE_ID)

/* How often a node speaks, and how long a silence has to last before it is
   read as a death.
 *
 * Forty heartbeats fit inside the deadline. That ratio is not caution for its
 * own sake: a dial to a peer that has vanished can sit in the kernel's
 * connect path for up to ten seconds before it gives up, and during that
 * stall this node sends nothing to anybody. A deadline shorter than that
 * stall would have each survivor declare the OTHER survivor dead while it was
 * busy dialling the corpse -- one failure turning into three. The gate
 * measures the worst dial this run actually took and refuses to pass if it
 * came anywhere near the deadline, so the margin is checked rather than
 * assumed. */
#define MESH_TICK_NS 200000000ULL
#define MESH_HEARTBEAT_NS 500000000ULL
#define MESH_SILENCE_NS 20000000000ULL
/* A peer that has never been heard from is still booting; retry often. One
   that has been declared dead is probably not coming back in this run, but a
   real node would keep trying, because that is how a repaired machine
   rejoins -- so retry, rarely. */
#define MESH_DIAL_RETRY_NS 2000000000ULL
#define MESH_DEAD_DIAL_RETRY_NS 30000000000ULL
/* Long enough for three emulated machines to boot and find each other. */
#define MESH_FORM_LIMIT_NS 300000000000ULL
/* An outer bound on the whole run, so a node that is never killed exits with
   a complaint rather than holding the gate open until its timeout. */
#define MESH_RUN_LIMIT_NS 900000000000ULL

/* The experts whose ownership is reported. Eight, because the point is to
   watch which ones move when a node dies and which do not, and one expert
   can only demonstrate the first. */
#define MESH_EXPERTS 8U

static const u64 k_mesh_port[3] = {
    (u64)XAIOS_CLUSTER_MESH_PORT_1,
    (u64)XAIOS_CLUSTER_MESH_PORT_2,
    (u64)XAIOS_CLUSTER_MESH_PORT_3,
};

static xaios_cluster_peer_t g_mesh_peers[MESH_PEER_COUNT];
static xaios_cluster_t g_mesh;
static uint64_t g_mesh_peer_id[MESH_PEER_COUNT];
static u64 g_mesh_out[MESH_PEER_COUNT];
static u64 g_mesh_last_sent[MESH_PEER_COUNT];
static u64 g_mesh_last_dial[MESH_PEER_COUNT];
static int g_mesh_seen_online[MESH_PEER_COUNT];
static u64 g_mesh_report_version;
static u64 g_mesh_worst_dial_ns;
static u8 g_mesh_frame[XAIOS_CLUSTER_MAX_MESSAGE];

/* Inbound connections. Two peers, but a peer that reconnects can briefly hold
   two, and a slot that is never freed would silently stop this node hearing
   from anyone -- so there is room to spare and a slot is released the moment
   its socket reports the far end gone. */
#define MESH_INBOUND 6
#define MESH_INBOUND_BUFFER (2U * XAIOS_CLUSTER_MAX_MESSAGE)
static u64 g_mesh_in[MESH_INBOUND];
static u8 g_mesh_in_buffer[MESH_INBOUND][MESH_INBOUND_BUFFER];
static u64 g_mesh_in_filled[MESH_INBOUND];

/* Every line this program prints is assembled here and written once.
 *
 * xaios_log_u64 is three console writes -- prefix, number, suffix -- and a
 * report built from a dozen of them is a dozen chances for sshd or the kernel
 * to put a line of its own through the middle of this one. The gate reads
 * these lines with a regular expression, so a torn line is a failed match,
 * and a failed match reads exactly like a check that never ran. One write per
 * line is the difference between a gate that is flaky on a busy machine and
 * one that is not. */
static char g_mesh_line[512];
static u64 g_mesh_line_len;

static void mesh_line_reset(void) {
  g_mesh_line_len = 0;
  g_mesh_line[0] = 0;
}

static void mesh_line_text(const char *text) {
  while (*text != 0 && g_mesh_line_len + 1U < sizeof(g_mesh_line)) {
    g_mesh_line[g_mesh_line_len++] = *text++;
  }
  g_mesh_line[g_mesh_line_len] = 0;
}

static void mesh_line_u64(u64 value) {
  char digits[21];
  u64 count = 0;
  if (value == 0U) {
    mesh_line_text("0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (char)(value % 10U));
    value /= 10U;
  }
  while (count != 0U) {
    --count;
    if (g_mesh_line_len + 1U < sizeof(g_mesh_line)) {
      g_mesh_line[g_mesh_line_len++] = digits[count];
    }
  }
  g_mesh_line[g_mesh_line_len] = 0;
}

static void mesh_line_emit(void) {
  mesh_line_text("\n");
  xaios_log(g_mesh_line);
}

static int mesh_peer_online(uint64_t node_id) {
  for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
    if (g_mesh_peer_id[i] == node_id) {
      return g_mesh_peers[i].state == XAIOS_CLUSTER_NODE_ONLINE ? 1 : 0;
    }
  }
  return 0;
}

static void mesh_expert_identity(u64 expert, xaios_expert_identity_t *out) {
  xaios_memzero(out, sizeof(*out));
  for (u64 i = 0; i < 16U; ++i) out->model_uuid[i] = (u8)(i + 1U);
  out->layer_id = 7ULL;
  out->expert_id = expert;
  out->layout_id = 1U;
}

/* One line carrying everything this node believes: who is up, whether that is
   a majority, and who owns each expert.
 *
 * It is one line on purpose. The gate compares these across machines, and a
 * membership printed separately from the ownership computed from it invites
 * comparing a view against an answer taken from a different instant. */
static void mesh_report(const char *reason) {
  uint64_t live = 0;
  uint64_t total = 0;
  int quorum = 0;
  if (xaios_cluster_quorum(&g_mesh, &live, &total, &quorum) !=
      XAIOS_ENGINE_OK) {
    xaios_log("/bin/clustertest: mesh quorum query failed\n");
    return;
  }
  ++g_mesh_report_version;
  mesh_line_reset();
  mesh_line_text("/bin/clustertest: mesh report node=");
  mesh_line_u64((u64)MESH_LOCAL_ID);
  mesh_line_text(" version=");
  mesh_line_u64(g_mesh_report_version);
  mesh_line_text(" live=");
  mesh_line_u64((u64)live);
  mesh_line_text(" total=");
  mesh_line_u64((u64)total);
  mesh_line_text(" quorum=");
  mesh_line_u64((u64)(quorum ? 1 : 0));
  mesh_line_text(" reason=");
  mesh_line_text(reason);
  mesh_line_text(" members=");
  int printed = 0;
  for (u64 id = 1; id <= MESH_TOTAL; ++id) {
    int up = id == (u64)MESH_LOCAL_ID ? 1 : mesh_peer_online((uint64_t)id);
    if (!up) continue;
    if (printed) mesh_line_text(",");
    mesh_line_u64(id);
    printed = 1;
  }
  if (!quorum) {
    /* A minority does not get to answer. Somewhere on the other side of this
       silence there may be two nodes that can still see each other, and they
       are entitled to decide; if this node decided as well, one expert would
       have two owners, which is not an error anybody detects -- it is just
       work done twice and a result nobody reconciles. Withholding is the
       whole practical content of quorum. */
    mesh_line_text(" owners=withheld");
    mesh_line_emit();
    return;
  }
  mesh_line_text(" owners=");
  for (u64 expert = 0; expert < MESH_EXPERTS; ++expert) {
    xaios_expert_identity_t identity;
    uint64_t owner = 0;
    mesh_expert_identity(expert, &identity);
    if (xaios_cluster_select_owner(&g_mesh, &identity, &owner) !=
        XAIOS_ENGINE_OK) {
      mesh_line_text("error");
      mesh_line_emit();
      return;
    }
    if (expert != 0U) mesh_line_text(",");
    mesh_line_u64((u64)owner);
  }
  mesh_line_emit();
}

static void mesh_dial(u64 index) {
  xaios_ip_addr_user_t address;
  xaios_memzero(&address, sizeof(address));
  address.family = 4U;
  address.addr[0] = (u8)XAIOS_CLUSTER_PEER_IPV4_A;
  address.addr[1] = (u8)XAIOS_CLUSTER_PEER_IPV4_B;
  address.addr[2] = (u8)XAIOS_CLUSTER_PEER_IPV4_C;
  address.addr[3] = (u8)XAIOS_CLUSTER_PEER_IPV4_D;
  u64 port = k_mesh_port[g_mesh_peer_id[index] - 1U];
  u64 socket = 0;
  u64 started = xaios_clock_nanos();
  int status = xaios_net_connect(&address, port, &socket);
  u64 took = xaios_clock_nanos() - started;
  /* Both outcomes are timed, and the worst is reported at the end. A dial
     blocks this node's whole loop, so its cost is the real risk to the
     deadline, and a number nobody prints is a number nobody checks. */
  if (took > g_mesh_worst_dial_ns) g_mesh_worst_dial_ns = took;
  mesh_line_reset();
  mesh_line_text("/bin/clustertest: mesh dial node=");
  mesh_line_u64((u64)g_mesh_peer_id[index]);
  mesh_line_text(" port=");
  mesh_line_u64(port);
  mesh_line_text(status != 0 ? " result=failed took_ms=" : " result=ok took_ms=");
  mesh_line_u64(took / 1000000ULL);
  mesh_line_emit();
  if (status != 0) return;
  g_mesh_out[index] = socket;
}

static void mesh_heartbeat(u64 index, u64 now) {
  size_t sealed = 0;
  if (xaios_cluster_seal(&g_mesh, g_mesh_peer_id[index],
                         (u16)XAIOS_CLUSTER_HEARTBEAT, 0, 0, g_mesh_frame,
                         sizeof(g_mesh_frame), &sealed) != XAIOS_ENGINE_OK) {
    return;
  }
  u64 sent = 0;
  if (xaios_net_send(g_mesh_out[index], g_mesh_frame, (u64)sealed, &sent) !=
          0 ||
      sent != (u64)sealed) {
    /* The link is gone; the peer may or may not be. Closing the socket is all
       that happens here -- membership is decided by silence and by nothing
       else, because a broken connection is a fact about a connection. */
    (void)xaios_net_close(g_mesh_out[index]);
    g_mesh_out[index] = 0;
    return;
  }
  g_mesh_last_sent[index] = now;
}

static void mesh_accept(u64 listener) {
  for (u64 guard = 0; guard < (u64)MESH_INBOUND; ++guard) {
    u64 socket = 0;
    if (xaios_net_accept(listener, &socket) != 0) return;
    u64 slot = (u64)MESH_INBOUND;
    for (u64 i = 0; i < (u64)MESH_INBOUND; ++i) {
      if (g_mesh_in[i] == 0) {
        slot = i;
        break;
      }
    }
    if (slot == (u64)MESH_INBOUND) {
      /* Nowhere to put it. Refusing loudly is better than holding a socket
         this node will never read, which would look like a peer that had
         gone quiet. */
      xaios_log("/bin/clustertest: mesh inbound table full; connection "
                "refused\n");
      (void)xaios_net_close(socket);
      return;
    }
    g_mesh_in[slot] = socket;
    g_mesh_in_filled[slot] = 0;
  }
}

/* Read whatever has arrived and open every complete frame in it.
 *
 * A stream has no frames in it; it has bytes, and the frames are a thing the
 * reader believes. Two heartbeats sent half a second apart can arrive in one
 * segment, and one heartbeat can arrive in two -- so this keeps a buffer per
 * connection, takes the length out of each header, and consumes only what is
 * whole. A version that treated one read as one frame would work on every
 * quiet machine and fail on a busy one. */
static void mesh_receive(u64 now) {
  for (u64 slot = 0; slot < (u64)MESH_INBOUND; ++slot) {
    if (g_mesh_in[slot] == 0) continue;
    u64 room = (u64)MESH_INBOUND_BUFFER - g_mesh_in_filled[slot];
    /* A read of zero bytes is a rejected syscall, not an empty read, so a
       full buffer is skipped rather than asked -- the frames already in it
       are consumed below and the room comes back on the next turn. */
    if (room != 0U) {
      u64 got = 0;
      int status = xaios_net_recv(g_mesh_in[slot],
                                  g_mesh_in_buffer[slot] +
                                      g_mesh_in_filled[slot],
                                  room, &got);
      if (status != 0 && status != XAIOS_ERR_BUSY) {
        (void)xaios_net_close(g_mesh_in[slot]);
        g_mesh_in[slot] = 0;
        g_mesh_in_filled[slot] = 0;
        continue;
      }
      if (status == 0) g_mesh_in_filled[slot] += got;
    }
    for (;;) {
      if (g_mesh_in_filled[slot] < (u64)XAIOS_CLUSTER_HEADER_SIZE) break;
      u64 length = frame_length_from_header(g_mesh_in_buffer[slot]);
      if (length > (u64)MESH_INBOUND_BUFFER ||
          length < (u64)XAIOS_CLUSTER_HEADER_SIZE) {
        /* A length this node cannot honour means the stream is not what it
           claims to be. There is no resynchronising from that without a
           framing marker, so drop the connection rather than guess. */
        xaios_log("/bin/clustertest: mesh impossible frame length; dropping "
                  "connection\n");
        (void)xaios_net_close(g_mesh_in[slot]);
        g_mesh_in[slot] = 0;
        g_mesh_in_filled[slot] = 0;
        break;
      }
      if (g_mesh_in_filled[slot] < length) break;
      xaios_cluster_message_t message;
      xaios_memzero(&message, sizeof(message));
      if (xaios_cluster_open(&g_mesh, g_mesh_in_buffer[slot], (size_t)length,
                             &message) == XAIOS_ENGINE_OK) {
        /* `open` has already marked the sender online. What it cannot do is
           say when, because nothing in the engine reads a clock -- so the
           timestamp is stamped here, from the one clock this node trusts. */
        (void)xaios_cluster_note_heard(&g_mesh, message.sender_node_id,
                                       now == 0U ? 1U : now);
      }
      /* Whether it opened or not, those bytes are spent. A frame that failed
         to open -- a stale nonce from a connection that was replaced, say --
         is not a reason to stop reading the ones behind it. */
      u64 remaining = g_mesh_in_filled[slot] - length;
      for (u64 i = 0; i < remaining; ++i) {
        g_mesh_in_buffer[slot][i] = g_mesh_in_buffer[slot][length + i];
      }
      g_mesh_in_filled[slot] = remaining;
    }
  }
}

static int mesh_main(void) {
  mesh_line_reset();
  mesh_line_text("/bin/clustertest: mesh node=");
  mesh_line_u64((u64)MESH_LOCAL_ID);
  mesh_line_text(" of=");
  mesh_line_u64((u64)MESH_TOTAL);
  mesh_line_text(" heartbeat_ms=");
  mesh_line_u64(MESH_HEARTBEAT_NS / 1000000ULL);
  mesh_line_text(" silence_deadline_ms=");
  mesh_line_u64(MESH_SILENCE_NS / 1000000ULL);
  mesh_line_emit();

  xaios_memzero(g_mesh_peers, sizeof(g_mesh_peers));
  u64 next = 0;
  for (u64 id = 1; id <= MESH_TOTAL; ++id) {
    if (id == (u64)MESH_LOCAL_ID) continue;
    g_mesh_peer_id[next] = (uint64_t)id;
    g_mesh_peers[next].node_id = (uint64_t)id;
    /* Every peer starts OFFLINE and unheard. Starting them online would mean
       this node's first report described a cluster it had not yet met, and
       the first thing the deadline did would be to correct an optimism this
       program had no reason to have. */
    g_mesh_peers[next].state = XAIOS_CLUSTER_NODE_OFFLINE;
    g_mesh_peers[next].last_heard_nanos = 0U;
    g_mesh_peers[next].next_transmit_nonce = 1ULL;
    g_mesh_peers[next].last_received_nonce = 0ULL;
    /* One key for every link in the mesh, which is weaker than it looks and
       is said out loud rather than left to be discovered: with a single
       shared key, node 3 can seal a frame that node 2 will accept as coming
       from node 1. Nothing in this test does that, and nothing in this test
       would notice. A deployment needs a key per ordered pair -- the peer
       table already has separate transmit and receive keys precisely so that
       it can -- and until it does, mutual authentication here means "a
       member of this cluster" rather than "this member of this cluster". */
    for (u64 i = 0; i < XAIOS_CLUSTER_KEY_SIZE; ++i) {
      g_mesh_peers[next].transmit_key[i] = k_shared_key[i];
      g_mesh_peers[next].receive_key[i] = k_shared_key[i];
    }
    ++next;
  }
  if (xaios_cluster_init(&g_mesh, MESH_LOCAL_ID, 1ULL, g_mesh_peers,
                         (uint64_t)MESH_PEER_COUNT) != XAIOS_ENGINE_OK) {
    return fail("mesh cluster init failed");
  }

  u64 listener = 0;
  u64 local_port = k_mesh_port[MESH_LOCAL_ID - 1U];
  if (xaios_net_listen(local_port, &listener) != 0) {
    return fail("mesh could not listen");
  }
  mesh_line_reset();
  mesh_line_text("/bin/clustertest: mesh listening port=");
  mesh_line_u64(local_port);
  mesh_line_emit();

  u64 start = xaios_clock_nanos();
  int formed = 0;
  for (;;) {
    u64 now = xaios_clock_nanos();
    if (!formed && now - start > MESH_FORM_LIMIT_NS) {
      (void)xaios_net_close(listener);
      return fail("mesh never formed: some peer was never heard from");
    }
    if (now - start > MESH_RUN_LIMIT_NS) {
      (void)xaios_net_close(listener);
      return fail("mesh run limit reached with quorum still held");
    }

    for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
      if (g_mesh_out[i] == 0) {
        u64 backoff = g_mesh_seen_online[i] == 0 &&
                              g_mesh_peers[i].last_heard_nanos != 0U
                          ? MESH_DEAD_DIAL_RETRY_NS
                          : MESH_DIAL_RETRY_NS;
        if (g_mesh_last_dial[i] == 0U || now - g_mesh_last_dial[i] >= backoff) {
          g_mesh_last_dial[i] = now;
          mesh_dial(i);
          now = xaios_clock_nanos();
        }
      }
      if (g_mesh_out[i] != 0 &&
          (g_mesh_last_sent[i] == 0U ||
           now - g_mesh_last_sent[i] >= MESH_HEARTBEAT_NS)) {
        mesh_heartbeat(i, now);
      }
    }

    mesh_accept(listener);
    mesh_receive(now);

    uint64_t expired = 0;
    if (xaios_cluster_expire_silent(&g_mesh, now, MESH_SILENCE_NS, &expired) !=
        XAIOS_ENGINE_OK) {
      (void)xaios_net_close(listener);
      return fail("mesh silence expiry failed");
    }

    int lost = 0;
    int found = 0;
    for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
      int up = g_mesh_peers[i].state == XAIOS_CLUSTER_NODE_ONLINE ? 1 : 0;
      if (up == g_mesh_seen_online[i]) continue;
      g_mesh_seen_online[i] = up;
      if (up) {
        found = 1;
        mesh_line_reset();
        mesh_line_text("/bin/clustertest: mesh peer-found node=");
        mesh_line_u64((u64)g_mesh_peer_id[i]);
        mesh_line_emit();
      } else {
        lost = 1;
        u64 silent_for = now - (u64)g_mesh_peers[i].last_heard_nanos;
        mesh_line_reset();
        mesh_line_text("/bin/clustertest: mesh peer-lost node=");
        mesh_line_u64((u64)g_mesh_peer_id[i]);
        /* The reason is the point of this whole program: nothing was said,
           and the deadline ran out. No LEAVE was sent, and none could have
           been -- the machine that stopped was killed outright, which is what
           a power failure looks like from here. */
        mesh_line_text(" reason=silence silent_for_ms=");
        mesh_line_u64(silent_for / 1000000ULL);
        mesh_line_text(" deadline_ms=");
        mesh_line_u64(MESH_SILENCE_NS / 1000000ULL);
        mesh_line_emit();
      }
    }

    if (!formed) {
      int all = 1;
      for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
        if (g_mesh_peers[i].state != XAIOS_CLUSTER_NODE_ONLINE) all = 0;
      }
      if (all) {
        formed = 1;
        mesh_report("formed");
      }
    } else if (lost || found) {
      mesh_report(lost ? "peer-lost" : "peer-found");
      uint64_t live = 0;
      uint64_t total = 0;
      int quorum = 0;
      if (xaios_cluster_quorum(&g_mesh, &live, &total, &quorum) ==
              XAIOS_ENGINE_OK &&
          !quorum) {
        /* Nothing left to decide and no right to decide it. Saying so and
           stopping is the honest end of a minority node's run; a node that
           carried on serving from here is the failure this gate exists to
           make visible. */
        mesh_line_reset();
        mesh_line_text("/bin/clustertest: mesh minority node=");
        mesh_line_u64((u64)MESH_LOCAL_ID);
        mesh_line_text(" live=");
        mesh_line_u64((u64)live);
        mesh_line_text(" total=");
        mesh_line_u64((u64)total);
        mesh_line_emit();
        mesh_line_reset();
        mesh_line_text("/bin/clustertest: mesh worst_dial_ms=");
        mesh_line_u64(g_mesh_worst_dial_ns / 1000000ULL);
        mesh_line_text(" deadline_ms=");
        mesh_line_u64(MESH_SILENCE_NS / 1000000ULL);
        mesh_line_emit();
        xaios_log("/bin/clustertest: mesh three-node membership passed\n");
        for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
          if (g_mesh_out[i] != 0) (void)xaios_net_close(g_mesh_out[i]);
        }
        for (u64 i = 0; i < (u64)MESH_INBOUND; ++i) {
          if (g_mesh_in[i] != 0) (void)xaios_net_close(g_mesh_in[i]);
        }
        (void)xaios_net_close(listener);
        return 0;
      }
    }

    /* Sleeping rather than spinning. A loop that polled these sockets as
       fast as it could would burn a core doing nothing, and on a machine
       running three of these at once that is three cores of noise underneath
       the thing being measured. */
    (void)xaios_sleep_ns(MESH_TICK_NS);
  }
}
#endif /* XAIOS_CLUSTER_MESH_NODES */

int main(void) {
#if XAIOS_CLUSTER_MESH_NODES
  return mesh_main();
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
  xaios_log_u64("/bin/clustertest: sealed reply bytes=", (u64)resealed, "\n");

  /* The peer is online because a frame from it arrived and opened. */
  log_ownership("joined");
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
    if (recv_sealed(next_socket, &frame, 30000000000ULL) != 0) {
      (void)xaios_net_close(next_socket);
      continue;
    }
    if (frame.opcode == (u16)XAIOS_CLUSTER_LEAVE) {
      (void)xaios_net_close(next_socket);
      if (g_peers[0].state != XAIOS_CLUSTER_NODE_OFFLINE) {
        (void)xaios_net_close(listener);
        return fail("a leave did not take the peer offline");
      }
      if (partitioned == 0) {
        log_ownership("partitioned");
        partitioned = 1;
      }
      continue;
    }
    if (frame.opcode == (u16)XAIOS_CLUSTER_JOIN) {
      if (partitioned == 0) {
        (void)xaios_net_close(next_socket);
        (void)xaios_net_close(listener);
        return fail("the peer rejoined without ever having left");
      }
      if (send_sealed(next_socket, (u16)XAIOS_CLUSTER_JOIN_ACK, 0, 0) != 0) {
        (void)xaios_net_close(next_socket);
        (void)xaios_net_close(listener);
        return fail("could not acknowledge the rejoin");
      }
      (void)xaios_net_close(next_socket);
      if (g_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE) {
        (void)xaios_net_close(listener);
        return fail("a rejoin did not bring the peer back online");
      }
      log_ownership("recovered");
      recovered = 1;
      continue;
    }
    (void)xaios_net_close(next_socket);
  }
  (void)xaios_net_close(listener);
  if (partitioned == 0) return fail("the peer never left");
  if (recovered == 0) return fail("the peer never came back");

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
  log_ownership("joined");

  /* Leave, on the connection that is still open from the exchange above.
     Saying so is better than vanishing: both are partitions to the other end,
     and only one of them tells it why. The socket from the round trip was
     closed already, so this opens another -- which is also what makes the
     next phase a reconnection rather than a continuation. */
  u64 leave_socket = 0;
  if (xaios_net_connect(&address, CLUSTER_PEER_PORT, &leave_socket) != 0) {
    return fail("could not reconnect to announce leaving");
  }
  if (send_sealed(leave_socket, (u16)XAIOS_CLUSTER_LEAVE, 0, 0) != 0) {
    (void)xaios_net_close(leave_socket);
    return fail("could not send the leave frame");
  }
  (void)xaios_net_close(leave_socket);
  (void)xaios_cluster_set_peer_state(&g_cluster, CLUSTER_PEER_NODE_ID,
                                     XAIOS_CLUSTER_NODE_OFFLINE);
  log_ownership("partitioned");

  /* Rejoin. The peer has been offline on both sides; ownership has to come
     back to what it was, because the membership has. If it does not, the two
     ends will disagree about who owns an expert the moment one of them
     forgets a node it once knew. */
  u64 rejoin_socket = 0;
  if (xaios_net_connect(&address, CLUSTER_PEER_PORT, &rejoin_socket) != 0) {
    return fail("could not reconnect to rejoin");
  }
  static const char rejoin_payload[] = "xaios-cluster-rejoin";
  if (send_sealed(rejoin_socket, (u16)XAIOS_CLUSTER_JOIN, rejoin_payload,
                  (u16)(sizeof(rejoin_payload) - 1U)) != 0) {
    (void)xaios_net_close(rejoin_socket);
    return fail("could not send the rejoin frame");
  }
  xaios_cluster_message_t acknowledgement;
  if (recv_sealed(rejoin_socket, &acknowledgement, 30000000000ULL) != 0) {
    (void)xaios_net_close(rejoin_socket);
    return fail("the peer did not acknowledge the rejoin");
  }
  (void)xaios_net_close(rejoin_socket);
  if (acknowledgement.opcode != (u16)XAIOS_CLUSTER_JOIN_ACK) {
    return fail("the rejoin was answered with the wrong opcode");
  }
  if (g_peers[0].state != XAIOS_CLUSTER_NODE_ONLINE) {
    return fail("an acknowledged rejoin did not bring the peer back online");
  }
  log_ownership("recovered");

  xaios_log("/bin/clustertest: cluster data plane over TCP passed\n");
  xaios_log("/bin/clustertest: membership join/partition/recovery passed\n");
  return 0;
#endif /* XAIOS_CLUSTER_ROLE_SERVER */
#endif /* XAIOS_CLUSTER_MESH_NODES */
}
