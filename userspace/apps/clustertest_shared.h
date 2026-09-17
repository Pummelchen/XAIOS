/*
 * Declarations shared by clustertest's sources.
 *
 * clustertest is two programs in one image, chosen at compile time by
 * XAIOS_CLUSTER_MESH_NODES: a two-node data plane, and a three-node mesh. The
 * sealed-frame transport the two-node plane uses, and the mesh's peer table,
 * line assembly and reports, live in clustertest_support.c; the mesh's dial,
 * heartbeat, accept and receive loop and its entry point live in
 * clustertest_mesh.c. Everything that has to agree between them -- the
 * compile-time configuration, the constants, the shared state and the
 * functions that cross a translation unit -- is here, so that a change to a
 * mesh constant or a wire helper cannot reach one side and miss the other.
 */
#ifndef XAIOS_USERSPACE_APPS_CLUSTERTEST_SHARED_H
#define XAIOS_USERSPACE_APPS_CLUSTERTEST_SHARED_H

#include <xaios_user.h>

#include <xaios_engine/cluster.h>

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

/* What a node does after it has lost quorum, and how often it says what it
 * believes.
 *
 * Zero -- the default, and what the three-node kill gate runs -- is a node
 * that reports its minority and stops. That is the honest end of a run in
 * which the other machines are gone: they were SIGKILLed, they are not coming
 * back, and a node that kept looping would only hold the gate open until its
 * timeout.
 *
 * One is for a partition, where the premise is different in the way that
 * matters: the other machines are still running. A minority here is a node
 * that has been cut off, not a node that has outlived its cluster, and the
 * interesting half of the test happens after that -- the link is repaired and
 * the three have to become one cluster again. A node that exited at the
 * moment it lost quorum could never demonstrate a heal, so under this setting
 * it says the same things and keeps running.
 *
 * It also makes each node state its belief on a timer rather than only when
 * its membership changes. During a partition nothing changes for minutes at a
 * time, and the gate has to compare what the two sides believe AT THE SAME
 * MOMENT -- which is impossible if the only evidence is a report each node
 * emitted when it last saw a transition, one of them potentially long before
 * the cut. A periodic report is what makes "these two nodes disagreed while
 * both were running" a statement about one instant instead of a comparison
 * between two different pasts.
 *
 * It is a compile-time choice rather than a run-time one because this program
 * has no configuration channel -- no arguments, no file it reads -- and
 * inventing one for a test would be testing the invention. */
#ifndef XAIOS_CLUSTER_MESH_HOLD
#define XAIOS_CLUSTER_MESH_HOLD 0
#endif
#if XAIOS_CLUSTER_MESH_HOLD != 0 && XAIOS_CLUSTER_MESH_HOLD != 1
#error "XAIOS_CLUSTER_MESH_HOLD is 0 (stop on minority) or 1 (keep running)"
#endif
#if XAIOS_CLUSTER_MESH_HOLD && !XAIOS_CLUSTER_MESH_NODES
#error "XAIOS_CLUSTER_MESH_HOLD only means anything in the three-node mesh"
#endif

#if XAIOS_CLUSTER_MESH_NODES
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
/* How often a node states its belief when it is holding through a partition.
   Short against the twenty second deadline, so that the gate always has a
   statement from each side that is younger than the thing it is comparing,
   and long enough that three machines are not spending their consoles on it:
   at five seconds a four minute run is fifty lines a node. */
#define MESH_PERIODIC_REPORT_NS 5000000000ULL

/* The experts whose ownership is reported. Eight, because the point is to
   watch which ones move when a node dies and which do not, and one expert
   can only demonstrate the first. */
#define MESH_EXPERTS 8U
#endif /* XAIOS_CLUSTER_MESH_NODES */

/* The key both ends share. Defined once in clustertest_support.c. */
extern const u8 clustertest_shared_key[XAIOS_CLUSTER_KEY_SIZE];

/* The length of the frame whose header this is. */
u64 clustertest_frame_length_from_header(const u8 *header);

/* Say `/bin/clustertest: <why>` and return 1, the failure exit of every path
   in both programs. */
int clustertest_fail(const char *why);

#if !XAIOS_CLUSTER_MESH_NODES
/* The two-node data plane's sealed-frame transport. */
int clustertest_read_exactly(u64 socket, u8 *buffer, u64 want,
                             u64 timeout_nanos, u64 *out_total);
int clustertest_send_sealed(xaios_cluster_t *cluster, u64 socket, u16 opcode,
                            const void *payload, u16 length);
int clustertest_recv_sealed(xaios_cluster_t *cluster, u64 socket,
                            xaios_cluster_message_t *message,
                            u64 timeout_nanos);
void clustertest_log_ownership(xaios_cluster_t *cluster,
                               const xaios_cluster_peer_t *peers, u64 *version,
                               const char *phase);
#endif /* !XAIOS_CLUSTER_MESH_NODES */

#if XAIOS_CLUSTER_MESH_NODES
/* Mesh state written by the loop in clustertest_mesh.c and read by the
   reports in clustertest_support.c, defined once in the latter. */
extern xaios_cluster_t clustertest_mesh;
extern xaios_cluster_peer_t clustertest_mesh_peers[MESH_PEER_COUNT];
extern uint64_t clustertest_mesh_peer_id[MESH_PEER_COUNT];
extern u64 clustertest_mesh_worst_dial_ns;

/* One line, assembled and written once. */
void clustertest_mesh_line_reset(void);
void clustertest_mesh_line_text(const char *text);
void clustertest_mesh_line_u64(u64 value);
void clustertest_mesh_line_emit(void);
void clustertest_mesh_report(const char *reason);
void clustertest_mesh_worst_dial_line(void);

/* The mesh program, called by main in clustertest.c. */
int clustertest_mesh_main(void);
#endif /* XAIOS_CLUSTER_MESH_NODES */

#endif /* XAIOS_USERSPACE_APPS_CLUSTERTEST_SHARED_H */
