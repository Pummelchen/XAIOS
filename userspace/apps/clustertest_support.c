/*
 * Shared support for clustertest's two programs.
 *
 * The sealed-frame helpers here are what the two-node data plane carries its
 * frames with; the peer table, the line assembly and the reports here are
 * what the three-node mesh says what it believes through. The mesh's dial,
 * heartbeat, accept and receive loop, and its entry point, are in
 * clustertest_mesh.c, which is built on this file.
 */

#include "clustertest_shared.h"

/* The key both ends share. A real deployment derives one; this is a test
   whose point is the transport, and a key that is generated here would have to
   be got to the other end somehow, which is the problem this is not solving. */
const u8 clustertest_shared_key[XAIOS_CLUSTER_KEY_SIZE] = {
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
int clustertest_read_exactly(u64 socket, u8 *buffer, u64 want,
                             u64 timeout_nanos, u64 *out_total) {
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
u64 clustertest_frame_length_from_header(const u8 *header) {
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

/* One fixed expert, so both ends are asking the same question. Its owner is a
   hash of the identity against each candidate node, so which node wins is not
   predictable from here -- only that both ends must name the same one. */
void clustertest_log_ownership(xaios_cluster_t *cluster,
                               const xaios_cluster_peer_t *peers,
                               u64 *version, const char *phase) {
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
  if (xaios_cluster_select_owner(cluster, &identity, &owner) !=
      XAIOS_ENGINE_OK) {
    xaios_log("/bin/clustertest: owner selection failed\n");
    return;
  }
  ++*version;
  xaios_log("/bin/clustertest: ownership phase=");
  xaios_log(phase);
  xaios_log_u64(" version=", *version, "");
  xaios_log_u64(" owner=", (u64)owner, "");
  xaios_log_u64(" peer_online=",
                (u64)(peers[0].state == XAIOS_CLUSTER_NODE_ONLINE ? 1U : 0U),
                "\n");
}

static u8 g_outbound[XAIOS_CLUSTER_MAX_MESSAGE];

int clustertest_send_sealed(xaios_cluster_t *cluster, u64 socket, u16 opcode,
                            const void *payload, u16 length) {
  size_t sealed = 0;
  if (xaios_cluster_seal(cluster, CLUSTER_PEER_NODE_ID, opcode, payload,
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
int clustertest_recv_sealed(xaios_cluster_t *cluster, u64 socket,
                            xaios_cluster_message_t *message,
                            u64 timeout_nanos) {
  u8 buffer[XAIOS_CLUSTER_MAX_MESSAGE];
  u64 got = 0;
  if (clustertest_read_exactly(socket, buffer,
                               (u64)XAIOS_CLUSTER_HEADER_SIZE, timeout_nanos,
                               &got) != 0) {
    return -1;
  }
  u64 length = clustertest_frame_length_from_header(buffer);
  if (length > sizeof(buffer) || length < (u64)XAIOS_CLUSTER_HEADER_SIZE) {
    return -1;
  }
  u64 rest = length - (u64)XAIOS_CLUSTER_HEADER_SIZE;
  if (rest != 0U &&
      clustertest_read_exactly(socket, buffer + XAIOS_CLUSTER_HEADER_SIZE,
                               rest, timeout_nanos, &got) != 0) {
    return -1;
  }
  xaios_memzero(message, sizeof(*message));
  if (xaios_cluster_open(cluster, buffer, (size_t)length, message) !=
      XAIOS_ENGINE_OK) {
    return -1;
  }
  return 0;
}

#endif /* !XAIOS_CLUSTER_MESH_NODES */

int clustertest_fail(const char *why) {
  xaios_log("/bin/clustertest: ");
  xaios_log(why);
  xaios_log("\n");
  return 1;
}

#if XAIOS_CLUSTER_MESH_NODES
/* The mesh state the loop and the reports share. It is defined here, where
   the reports that read most of it live, and declared in
   clustertest_shared.h for the loop in clustertest_mesh.c. */
xaios_cluster_peer_t clustertest_mesh_peers[MESH_PEER_COUNT];
xaios_cluster_t clustertest_mesh;
uint64_t clustertest_mesh_peer_id[MESH_PEER_COUNT];
u64 clustertest_mesh_worst_dial_ns;
static u64 g_mesh_report_version;

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

void clustertest_mesh_line_reset(void) {
  g_mesh_line_len = 0;
  g_mesh_line[0] = 0;
}

void clustertest_mesh_line_text(const char *text) {
  while (*text != 0 && g_mesh_line_len + 1U < sizeof(g_mesh_line)) {
    g_mesh_line[g_mesh_line_len++] = *text++;
  }
  g_mesh_line[g_mesh_line_len] = 0;
}

void clustertest_mesh_line_u64(u64 value) {
  char digits[21];
  u64 count = 0;
  if (value == 0U) {
    clustertest_mesh_line_text("0");
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

void clustertest_mesh_line_emit(void) {
  clustertest_mesh_line_text("\n");
  xaios_log(g_mesh_line);
}

static int mesh_peer_online(uint64_t node_id) {
  for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
    if (clustertest_mesh_peer_id[i] == node_id) {
      return clustertest_mesh_peers[i].state == XAIOS_CLUSTER_NODE_ONLINE ? 1
                                                                         : 0;
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
void clustertest_mesh_report(const char *reason) {
  uint64_t live = 0;
  uint64_t total = 0;
  int quorum = 0;
  if (xaios_cluster_quorum(&clustertest_mesh, &live, &total, &quorum) !=
      XAIOS_ENGINE_OK) {
    xaios_log("/bin/clustertest: mesh quorum query failed\n");
    return;
  }
  ++g_mesh_report_version;
  clustertest_mesh_line_reset();
  clustertest_mesh_line_text("/bin/clustertest: mesh report node=");
  clustertest_mesh_line_u64((u64)MESH_LOCAL_ID);
  clustertest_mesh_line_text(" version=");
  clustertest_mesh_line_u64(g_mesh_report_version);
  clustertest_mesh_line_text(" live=");
  clustertest_mesh_line_u64((u64)live);
  clustertest_mesh_line_text(" total=");
  clustertest_mesh_line_u64((u64)total);
  clustertest_mesh_line_text(" quorum=");
  clustertest_mesh_line_u64((u64)(quorum ? 1 : 0));
  clustertest_mesh_line_text(" reason=");
  clustertest_mesh_line_text(reason);
  clustertest_mesh_line_text(" members=");
  int printed = 0;
  for (u64 id = 1; id <= MESH_TOTAL; ++id) {
    int up =
        id == (u64)MESH_LOCAL_ID ? 1 : mesh_peer_online((uint64_t)id);
    if (!up) continue;
    if (printed) clustertest_mesh_line_text(",");
    clustertest_mesh_line_u64(id);
    printed = 1;
  }
  if (!quorum) {
    /* A minority does not get to answer. Somewhere on the other side of this
       silence there may be two nodes that can still see each other, and they
       are entitled to decide; if this node decided as well, one expert would
       have two owners, which is not an error anybody detects -- it is just
       work done twice and a result nobody reconciles. Withholding is the
       whole practical content of quorum. */
    clustertest_mesh_line_text(" owners=withheld");
    clustertest_mesh_line_emit();
    return;
  }
  clustertest_mesh_line_text(" owners=");
  for (u64 expert = 0; expert < MESH_EXPERTS; ++expert) {
    xaios_expert_identity_t identity;
    uint64_t owner = 0;
    mesh_expert_identity(expert, &identity);
    if (xaios_cluster_select_owner(&clustertest_mesh, &identity, &owner) !=
        XAIOS_ENGINE_OK) {
      clustertest_mesh_line_text("error");
      clustertest_mesh_line_emit();
      return;
    }
    if (expert != 0U) clustertest_mesh_line_text(",");
    clustertest_mesh_line_u64((u64)owner);
  }
  clustertest_mesh_line_emit();
}

/* The worst dial this node has taken so far, against the deadline it has to
   respect. A dial blocks the whole loop, so a dial that approached the
   silence deadline would mean this node stopped heartbeating its living peers
   while it was busy trying to reach an unreachable one -- one broken link
   turning into three dead peers. The gate reads this line and refuses to pass
   if the margin is thin, which is the difference between a deadline that is
   safe and one that was assumed to be. */
void clustertest_mesh_worst_dial_line(void) {
  clustertest_mesh_line_reset();
  clustertest_mesh_line_text("/bin/clustertest: mesh worst_dial_ms=");
  clustertest_mesh_line_u64(clustertest_mesh_worst_dial_ns / 1000000ULL);
  clustertest_mesh_line_text(" deadline_ms=");
  clustertest_mesh_line_u64(MESH_SILENCE_NS / 1000000ULL);
  clustertest_mesh_line_emit();
}
#endif /* XAIOS_CLUSTER_MESH_NODES */
