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

#include "clustertest_shared.h"

#if XAIOS_CLUSTER_MESH_NODES

static const u64 k_mesh_port[3] = {
    (u64)XAIOS_CLUSTER_MESH_PORT_1,
    (u64)XAIOS_CLUSTER_MESH_PORT_2,
    (u64)XAIOS_CLUSTER_MESH_PORT_3,
};

static u64 g_mesh_out[MESH_PEER_COUNT];
static u64 g_mesh_last_sent[MESH_PEER_COUNT];
static u64 g_mesh_last_dial[MESH_PEER_COUNT];
static int g_mesh_seen_online[MESH_PEER_COUNT];
static u8 g_mesh_frame[XAIOS_CLUSTER_MAX_MESSAGE];
#if XAIOS_CLUSTER_MESH_HOLD
static u64 g_mesh_last_periodic;
#endif

/* Inbound connections. Two peers, but a peer that reconnects can briefly hold
   two, and a slot that is never freed would silently stop this node hearing
   from anyone -- so there is room to spare and a slot is released the moment
   its socket reports the far end gone. */
#define MESH_INBOUND 6
#define MESH_INBOUND_BUFFER (2U * XAIOS_CLUSTER_MAX_MESSAGE)
static u64 g_mesh_in[MESH_INBOUND];
static u8 g_mesh_in_buffer[MESH_INBOUND][MESH_INBOUND_BUFFER];
static u64 g_mesh_in_filled[MESH_INBOUND];

static void mesh_dial(u64 index) {
  xaios_ip_addr_user_t address;
  xaios_memzero(&address, sizeof(address));
  address.family = 4U;
  address.addr[0] = (u8)XAIOS_CLUSTER_PEER_IPV4_A;
  address.addr[1] = (u8)XAIOS_CLUSTER_PEER_IPV4_B;
  address.addr[2] = (u8)XAIOS_CLUSTER_PEER_IPV4_C;
  address.addr[3] = (u8)XAIOS_CLUSTER_PEER_IPV4_D;
  u64 port = k_mesh_port[clustertest_mesh_peer_id[index] - 1U];
  u64 socket = 0;
  u64 started = xaios_clock_nanos();
  int status = xaios_net_connect(&address, port, &socket);
  u64 took = xaios_clock_nanos() - started;
  /* Both outcomes are timed, and the worst is reported at the end. A dial
     blocks this node's whole loop, so its cost is the real risk to the
     deadline, and a number nobody prints is a number nobody checks. */
  if (took > clustertest_mesh_worst_dial_ns) {
    clustertest_mesh_worst_dial_ns = took;
  }
  clustertest_mesh_line_reset();
  clustertest_mesh_line_text("/bin/clustertest: mesh dial node=");
  clustertest_mesh_line_u64((u64)clustertest_mesh_peer_id[index]);
  clustertest_mesh_line_text(" port=");
  clustertest_mesh_line_u64(port);
  clustertest_mesh_line_text(status != 0 ? " result=failed took_ms="
                                         : " result=ok took_ms=");
  clustertest_mesh_line_u64(took / 1000000ULL);
  clustertest_mesh_line_emit();
  if (status != 0) return;
  g_mesh_out[index] = socket;
}

/* The senders own membership view, as a bitmap indexed by node id.
 *
 * A heartbeat used to carry no payload, which made it a statement that the
 * sender is alive and nothing else. That is half of what a receiver needs: a
 * node whose outbound links are cut still hears every heartbeat and still
 * counts a whole cluster, while the peers that cannot hear it have already
 * excluded it -- and both sides then pass a correct majority test at the same
 * instant. Carrying the view makes the other half sayable: a receiver can see
 * whether the sender lists it, and a peer that does not list us is a peer we
 * cannot agree with however clearly we hear it. */
/* Whether a peer has ever listed us in its view.
 *
 * "Absent from your view" and "excluded from your view" are different facts,
 * and only the second one means the link is one-way. A node's very first
 * heartbeat goes out before it has heard from anybody, so it lists only
 * itself -- and treating that as exclusion made every node conclude, from the
 * first frame it ever received, that its peer could not hear it. Nothing then
 * reached quorum and the cluster never formed: three nodes each reporting
 * live=1 total=3 quorum=0 while perfectly healthy.
 *
 * So exclusion is only believed once inclusion has been seen. Before that, a
 * peer that does not list us has simply not finished forming, which is the
 * ordinary state of a cluster that is still starting. */
static u8 g_mesh_listed_us[MESH_PEER_COUNT];

static u64 mesh_member_bitmap(void) {
  u64 bitmap = 1ULL << (MESH_LOCAL_ID & 63U);
  for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
    if (clustertest_mesh_peers[i].state == XAIOS_CLUSTER_NODE_ONLINE) {
      bitmap |= 1ULL << (clustertest_mesh_peers[i].node_id & 63U);
    }
  }
  return bitmap;
}

static void mesh_heartbeat(u64 index, u64 now) {
  size_t sealed = 0;
  u64 view = mesh_member_bitmap();
  u8 payload[8];
  for (u64 i = 0; i < 8U; ++i) payload[i] = (u8)((view >> (i * 8U)) & 0xFFU);
  if (xaios_cluster_seal(&clustertest_mesh, clustertest_mesh_peer_id[index],
                         (u16)XAIOS_CLUSTER_HEARTBEAT, payload,
                         (u16)sizeof(payload), g_mesh_frame,
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
      u64 length = clustertest_frame_length_from_header(g_mesh_in_buffer[slot]);
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
      if (xaios_cluster_open(&clustertest_mesh, g_mesh_in_buffer[slot],
                             (size_t)length,
                             &message) == XAIOS_ENGINE_OK) {
        /* `open` has already marked the sender online. What it cannot do is
           say when, because nothing in the engine reads a clock -- so the
           timestamp is stamped here, from the one clock this node trusts. */
        (void)xaios_cluster_note_heard(&clustertest_mesh, message.sender_node_id,
                                       now == 0U ? 1U : now);
        /* And whether the sender can hear us. A heartbeat with no payload is
           an older peer that cannot say; treated as reachable, because
           refusing quorum to a peer that simply predates this field would
           break a mixed cluster for a reason that has nothing to do with the
           network. */
        if (message.payload_length >= 8U) {
          u64 view = 0;
          for (u64 i = 0; i < 8U; ++i) {
            view |= ((u64)message.payload[i]) << (i * 8U);
          }
          const int listed =
              (view & (1ULL << (MESH_LOCAL_ID & 63U))) != 0U ? 1 : 0;
          for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
            if (clustertest_mesh_peers[i].node_id != message.sender_node_id) {
              continue;
            }
            if (listed) {
              g_mesh_listed_us[i] = 1U;
              (void)xaios_cluster_note_reachability(
                  &clustertest_mesh, message.sender_node_id, 1);
            } else if (g_mesh_listed_us[i] != 0U) {
              /* It listed us before and does not now: a one-way link, which
                 is the case quorum must not count. */
              (void)xaios_cluster_note_reachability(
                  &clustertest_mesh, message.sender_node_id, 0);
            }
            break;
          }
        }
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

int clustertest_mesh_main(void) {
  clustertest_mesh_line_reset();
  clustertest_mesh_line_text("/bin/clustertest: mesh node=");
  clustertest_mesh_line_u64((u64)MESH_LOCAL_ID);
  clustertest_mesh_line_text(" of=");
  clustertest_mesh_line_u64((u64)MESH_TOTAL);
  clustertest_mesh_line_text(" heartbeat_ms=");
  clustertest_mesh_line_u64(MESH_HEARTBEAT_NS / 1000000ULL);
  clustertest_mesh_line_text(" silence_deadline_ms=");
  clustertest_mesh_line_u64(MESH_SILENCE_NS / 1000000ULL);
#if XAIOS_CLUSTER_MESH_HOLD
  /* Which of the two programs this is, said by the machine itself. The gate
     that drives partitions builds every node with the hold, and a node built
     without it would leave the moment it lost quorum -- taking the second
     half of the test with it and failing in a way that reads like a heal that
     did not happen rather than a build that was wrong. */
  clustertest_mesh_line_text(" mode=hold");
#endif
  clustertest_mesh_line_emit();

  xaios_memzero(clustertest_mesh_peers, sizeof(clustertest_mesh_peers));
  u64 next = 0;
  for (u64 id = 1; id <= MESH_TOTAL; ++id) {
    if (id == (u64)MESH_LOCAL_ID) continue;
    clustertest_mesh_peer_id[next] = (uint64_t)id;
    clustertest_mesh_peers[next].node_id = (uint64_t)id;
    /* Every peer starts OFFLINE and unheard. Starting them online would mean
       this node's first report described a cluster it had not yet met, and
       the first thing the deadline did would be to correct an optimism this
       program had no reason to have. */
    clustertest_mesh_peers[next].state = XAIOS_CLUSTER_NODE_OFFLINE;
    clustertest_mesh_peers[next].last_heard_nanos = 0U;
    clustertest_mesh_peers[next].next_transmit_nonce = 1ULL;
    clustertest_mesh_peers[next].last_received_nonce = 0ULL;
    /* One key for every link in the mesh, which is weaker than it looks and
       is said out loud rather than left to be discovered: with a single
       shared key, node 3 can seal a frame that node 2 will accept as coming
       from node 1. Nothing in this test does that, and nothing in this test
       would notice. A deployment needs a key per ordered pair -- the peer
       table already has separate transmit and receive keys precisely so that
       it can -- and until it does, mutual authentication here means "a
       member of this cluster" rather than "this member of this cluster". */
    for (u64 i = 0; i < XAIOS_CLUSTER_KEY_SIZE; ++i) {
      clustertest_mesh_peers[next].transmit_key[i] = clustertest_shared_key[i];
      clustertest_mesh_peers[next].receive_key[i] = clustertest_shared_key[i];
    }
    ++next;
  }
  if (xaios_cluster_init(&clustertest_mesh, MESH_LOCAL_ID, 1ULL,
                         clustertest_mesh_peers,
                         (uint64_t)MESH_PEER_COUNT) != XAIOS_ENGINE_OK) {
    return clustertest_fail("mesh cluster init failed");
  }

  u64 listener = 0;
  u64 local_port = k_mesh_port[MESH_LOCAL_ID - 1U];
  if (xaios_net_listen(local_port, &listener) != 0) {
    return clustertest_fail("mesh could not listen");
  }
  clustertest_mesh_line_reset();
  clustertest_mesh_line_text("/bin/clustertest: mesh listening port=");
  clustertest_mesh_line_u64(local_port);
  clustertest_mesh_line_emit();

  u64 start = xaios_clock_nanos();
  int formed = 0;
  for (;;) {
    u64 now = xaios_clock_nanos();
    if (!formed && now - start > MESH_FORM_LIMIT_NS) {
      (void)xaios_net_close(listener);
      return clustertest_fail("mesh never formed: some peer was never heard from");
    }
    if (now - start > MESH_RUN_LIMIT_NS) {
      (void)xaios_net_close(listener);
      return clustertest_fail("mesh run limit reached with quorum still held");
    }

    for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
      if (g_mesh_out[i] == 0) {
        u64 backoff = g_mesh_seen_online[i] == 0 &&
                              clustertest_mesh_peers[i].last_heard_nanos != 0U
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
    if (xaios_cluster_expire_silent(&clustertest_mesh, now, MESH_SILENCE_NS,
                                    &expired) != XAIOS_ENGINE_OK) {
      (void)xaios_net_close(listener);
      return clustertest_fail("mesh silence expiry failed");
    }

    int lost = 0;
    int found = 0;
    for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
      int up = clustertest_mesh_peers[i].state == XAIOS_CLUSTER_NODE_ONLINE
                   ? 1
                   : 0;
      if (up == g_mesh_seen_online[i]) continue;
      g_mesh_seen_online[i] = up;
      if (up) {
        found = 1;
        clustertest_mesh_line_reset();
        clustertest_mesh_line_text("/bin/clustertest: mesh peer-found node=");
        clustertest_mesh_line_u64((u64)clustertest_mesh_peer_id[i]);
        clustertest_mesh_line_emit();
      } else {
        lost = 1;
        u64 silent_for =
            now - (u64)clustertest_mesh_peers[i].last_heard_nanos;
        clustertest_mesh_line_reset();
        clustertest_mesh_line_text("/bin/clustertest: mesh peer-lost node=");
        clustertest_mesh_line_u64((u64)clustertest_mesh_peer_id[i]);
        /* The reason is the point of this whole program: nothing was said,
           and the deadline ran out. No LEAVE was sent, and none could have
           been -- the machine that stopped was killed outright, which is what
           a power failure looks like from here. */
        clustertest_mesh_line_text(" reason=silence silent_for_ms=");
        clustertest_mesh_line_u64(silent_for / 1000000ULL);
        clustertest_mesh_line_text(" deadline_ms=");
        clustertest_mesh_line_u64(MESH_SILENCE_NS / 1000000ULL);
        clustertest_mesh_line_emit();
      }
    }

    if (!formed) {
      int all = 1;
      for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
        if (clustertest_mesh_peers[i].state != XAIOS_CLUSTER_NODE_ONLINE) {
          all = 0;
        }
      }
      if (all) {
        formed = 1;
        clustertest_mesh_report("formed");
      }
    } else if (lost || found) {
      clustertest_mesh_report(lost ? "peer-lost" : "peer-found");
      uint64_t live = 0;
      uint64_t total = 0;
      int quorum = 0;
      if (xaios_cluster_quorum(&clustertest_mesh, &live, &total, &quorum) ==
              XAIOS_ENGINE_OK &&
          !quorum) {
        /* Nothing left to decide and no right to decide it. Saying so and
           stopping is the honest end of a minority node's run; a node that
           carried on serving from here is the failure this gate exists to
           make visible. */
        clustertest_mesh_line_reset();
        clustertest_mesh_line_text("/bin/clustertest: mesh minority node=");
        clustertest_mesh_line_u64((u64)MESH_LOCAL_ID);
        clustertest_mesh_line_text(" live=");
        clustertest_mesh_line_u64((u64)live);
        clustertest_mesh_line_text(" total=");
        clustertest_mesh_line_u64((u64)total);
        clustertest_mesh_line_emit();
        clustertest_mesh_worst_dial_line();
#if XAIOS_CLUSTER_MESH_HOLD
        /* Under a partition this is not the end of anything. The other two
           machines are still running on the far side of a broken link, this
           one has correctly stood down, and the half of the test that has not
           happened yet is the repair. So it says the same thing and keeps
           going: it keeps dialling, keeps listening, and will report again
           the moment it hears a peer. Standing down is about withholding
           ownership, which mesh_report already does with owners=withheld --
           it was never about exiting. */
#else
        xaios_log("/bin/clustertest: mesh three-node membership passed\n");
        for (u64 i = 0; i < (u64)MESH_PEER_COUNT; ++i) {
          if (g_mesh_out[i] != 0) (void)xaios_net_close(g_mesh_out[i]);
        }
        for (u64 i = 0; i < (u64)MESH_INBOUND; ++i) {
          if (g_mesh_in[i] != 0) (void)xaios_net_close(g_mesh_in[i]);
        }
        (void)xaios_net_close(listener);
        return 0;
#endif
      }
    }

#if XAIOS_CLUSTER_MESH_HOLD
    /* One statement of belief per interval, whatever is or is not happening.
       It goes here, at the bottom of the loop, so that it describes the state
       AFTER this turn's receiving and expiry rather than the state this turn
       started with -- a report taken before the expiry runs would name a peer
       as live in the same tick the node decided it was not. */
    if (formed && (g_mesh_last_periodic == 0U ||
                   now - g_mesh_last_periodic >= MESH_PERIODIC_REPORT_NS)) {
      g_mesh_last_periodic = now;
      clustertest_mesh_report("periodic");
      clustertest_mesh_worst_dial_line();
    }
#endif

    /* Sleeping rather than spinning. A loop that polled these sockets as
       fast as it could would burn a core doing nothing, and on a machine
       running three of these at once that is three cores of noise underneath
       the thing being measured. */
    (void)xaios_sleep_ns(MESH_TICK_NS);
  }
}

#endif /* XAIOS_CLUSTER_MESH_NODES */
