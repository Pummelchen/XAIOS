/*
 * The application/external-session plane of the network stack, moved out of
 * network_stack.c: the synthetic IPv4 frames the loopback echo and connect
 * tests build, the echo and connect entry points themselves, and the external
 * session dispatcher that formats their result.
 *
 * This module owns no state. It runs under the stack's guard,
 * g_network_guard, through network_stack_lock()/network_stack_unlock(); the
 * exported entry points take it themselves exactly where the functions they
 * replace took it, so no critical section is widened, narrowed or split. The
 * unlocked variants stay called with the guard already held and keep taking it
 * again through the reentrant lock, exactly as before.
 *
 * The one thing the moved code cannot reach directly is the TCP flow row it
 * reads to finish the loopback handshake it drives. network_stack.c owns
 * g_tcp_flows, so it lends the copy-out accessor declared below: two sequence
 * numbers into caller-owned locals, never a pointer into the table. The
 * declaration is shared with network_stack_selftest.c, which reads the same
 * row for the same reason.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_APP_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_APP_H

#include <xaios/network_stack.h>

/* Read the expected-sequence and next-send-sequence numbers of the half-open
   (XAIOS_NETWORK_FLOW_SYN_RECV) TCP flow with this port pair into
   caller-owned locals. Returns 1 on a hit, 0 and writes nothing when there is
   none. Defined in network_stack.c, which owns the flow table; caller holds
   the stack guard. */
int net_stack_tcp_flow_read_syn_recv_seqs(uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t *expected_seq,
                                          uint32_t *next_send_seq);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_APP_H */
