/* A datagram socket with a name of its own, which is what a QUIC client has
 * before its first packet.
 *
 * WT-35. The port already had UDP: `xaios_net_bind_udp` for a program that
 * knows the port it wants, and `xaios_net_sendto`/`xaios_net_recvfrom` for the
 * traffic. What it did not have was a way to be given a port, and that is the
 * one thing a client needs first. `xaios_net_listen` with the UDP protocol
 * carries a receive path and refuses a zero port; a client that has never
 * received anything has no port to name and no listener to stand behind. A
 * socket that was never bound has local port zero, and the send path refuses
 * a datagram from it outright -- so the client is not merely unnamed, it has
 * nothing it can send.
 *
 * This runs the four things that has to mean, in the order they can fail:
 *
 *   1. one open, port zero, and the port that comes back is a real one in the
 *      dynamic range rather than the zero that was asked for;
 *   2. a second open gets a different port, because two descriptors holding
 *      one port would leave one of them unreachable -- the reply is looked up
 *      by port, and the lookup stops at the first match;
 *   3. a port that was asked for by number is the port that comes back, so the
 *      caller's own address is what it said it was;
 *   4. a datagram leaves from the socket that was given a port, so the port is
 *      a source and not merely a record.
 *
 * WT-39 adds a fifth: with the datagram registry deliberately filled to its
 * refusal, a TCP listener is still registrable, because the two protocols no
 * longer share one sixteen-row table. That is measured here rather than argued
 * because it is exactly the case the old single table could not pass -- a QUIC
 * client and sshd asking at the same time.
 *
 * It reports and does not judge, like /bin/perfbench and /bin/netmqtest: the
 * gate reads the summary line and decides. A measurement program that returns
 * non-zero on a bad number makes a boot fail for a reason that belongs to the
 * test rather than to the machine.
 *
 * The fourth step sends to the network's host and does not wait for an answer.
 * Whether anything replies is the emulated network's business, and under SLIRP
 * it depends on a host service being up; requiring a reply would make this
 * app's verdict a statement about the host. The kernel's own receives are
 * covered by /bin/nettest, which drives the echo path. What is added here is
 * that the send happens at all from a port the kernel chose.
 */
#include <xaios_user.h>

#define OPEN_COUNT 2U
#define PAYLOAD_SIZE 256U

/* The dynamic range, RFC 6335. Repeated rather than included because the
   kernel side of the same number is not part of the userspace header. */
#define EPHEMERAL_MIN 49152U

/* The TCP port the independence probe listens on. A service port nobody in the
   boot-test profile uses, so a failure to register it is the registry and not
   a collision. */
#define TCP_PROBE_PORT 27400U

typedef struct open_result {
  u64 open_failed;
  u64 port;
  u64 sockfd;
} open_result_t;

typedef struct summary {
  u64 opens_attempted;
  u64 opens_failed;
  u64 port_zero_returned;
  u64 ports_out_of_range;
  u64 ports_duplicated;
  u64 explicit_port_mismatched;
  u64 sends_attempted;
  u64 sends_failed;
  u64 closes_failed;
  u64 first_port;
  u64 second_port;
  u64 explicit_port;
  u64 registry_fill_ok;
  u64 registry_refused;
  u64 tcp_after_udp_full;
} summary_t;

/* Port zero asks the kernel to choose. Both the descriptor and the port are
   taken from the call rather than assumed: the port is the caller's own
   address, and a caller that guessed it would be telling peers a lie.
 *
 * This used to say it could not tell whether the port the kernel returned is
 * one the reply path can reach, because a registry with no free row left the
 * socket unable to receive while the call still reported a port. That was
 * B-78, and it is no longer true: `net_open_udp` registers the listener before
 * it reports anything and fails the call when the registry is full, so a
 * refused row arrives here as a failed open. `fill_registry` below measures
 * exactly that. */
static void open_ephemeral(summary_t *summary, open_result_t *result) {
  result->open_failed = 0U;
  result->port = 0U;
  result->sockfd = 0U;
  summary->opens_attempted++;
  if (xaios_net_open_udp(0U, &result->sockfd, &result->port) < 0) {
    result->open_failed = 1U;
    summary->opens_failed++;
    return;
  }
  if (result->port == 0U) summary->port_zero_returned++;
  if (result->port < EPHEMERAL_MIN || result->port > 65535U) {
    summary->ports_out_of_range++;
  }
}

/* The datagram registry has its own capacity (WT-39 gave UDP and TCP separate
 * pools), so this opens until the kernel refuses and holds the sockets while
 * it counts, keeping every datagram row taken. It asserts nothing, like the
 * rest of this app: it records how many were handed out, whether a refusal
 * ever came, and whether a TCP listener could still be registered beside the
 * full datagram pool, and the gate requires the refusal and the probe.
 *
 * What makes the refusal worth measuring is how the two possible kernels
 * differ. One that refuses reports a failed open and the count stops at the
 * ceiling. One that does not -- which is what this was before B-78 -- answers
 * every open with a descriptor and a port, and the replies to that port are
 * dropped for want of a row, so the only difference visible from here is that
 * no refusal ever arrives. The TCP probe is the WT-39 half: while one shared
 * sixteen-row table served both protocols, the refusal this loop produces was
 * also the refusal a listener got, and a machine running sshd had already
 * spent one of the sixteen before this app started. */
static void fill_registry(summary_t *summary) {
  enum { FILL_ATTEMPTS = 64U };
  static u64 sockfds[FILL_ATTEMPTS];
  u64 opened = 0U;
  for (u64 i = 0U; i < FILL_ATTEMPTS; ++i) {
    u64 sockfd = 0U;
    u64 port = 0U;
    if (xaios_net_open_udp(0U, &sockfd, &port) < 0) {
      summary->registry_refused = 1U;
      break;
    }
    sockfds[opened++] = sockfd;
  }
  summary->registry_fill_ok = opened;

  /* Every datagram row is held. A TCP listener is a different pool and must
     still register; the datagram sockets stay open across the probe so the
     two really do overlap. */
  u64 tcp_sockfd = 0U;
  if (xaios_net_listen(TCP_PROBE_PORT, &tcp_sockfd) == 0) {
    summary->tcp_after_udp_full = 1U;
    if (xaios_net_close(tcp_sockfd) < 0) summary->closes_failed++;
  }

  for (u64 i = 0U; i < opened; ++i) {
    if (xaios_net_close(sockfds[i]) < 0) summary->closes_failed++;
  }
}

static u64 datagram_leaves(u64 sockfd) {
  /* A payload of a realistic size rather than one byte: a datagram that fits
     in a header is not evidence that a datagram path works. The destination
     is the emulated network's host, which is where /bin/netmqtest sends for
     the same reason -- it is on the guest's link and the frame is transmitted
     rather than dropped as unroutable. Port 9 is the discard port. */
  static unsigned char payload[PAYLOAD_SIZE];
  for (u64 i = 0U; i < PAYLOAD_SIZE; ++i) {
    payload[i] = (unsigned char)('a' + (i % 26U));
  }
  xaios_ip_addr_user_t destination;
  destination.family = 4U;
  for (u64 i = 0U; i < 16U; ++i) destination.addr[i] = 0U;
  destination.addr[0] = 10U;
  destination.addr[1] = 0U;
  destination.addr[2] = 2U;
  destination.addr[3] = 2U;
  u64 written = 0U;
  if (xaios_net_sendto(sockfd, payload, PAYLOAD_SIZE, &written, &destination,
                       9U) < 0) {
    return 0U;
  }
  return written;
}

int main(void) {
  static summary_t summary;
  xaios_log("/bin/netsocktest: datagram sockets with kernel-chosen ports\n");

  open_result_t opened[OPEN_COUNT];
  for (u64 i = 0U; i < OPEN_COUNT; ++i) open_ephemeral(&summary, &opened[i]);

  summary.first_port = opened[0].port;
  summary.second_port = opened[1].port;
  /* Only compared once both opens reported, so a failed one is counted as a
     failure and not as the duplicate it would look like against a zero. */
  if (opened[0].open_failed == 0U && opened[1].open_failed == 0U &&
      opened[0].port == opened[1].port) {
    summary.ports_duplicated++;
  }

  /* A port asked for by number comes back as itself. 0 is not usable as the
     expected value here, so the number is one in the dynamic range that the
     two ephemeral draws are unlikely to have taken.
   *
     A collision with a port already held is NOT detected: the explicit branch
     allocates whatever number it is given, so a shadowed port would be
     reported as explicit_port_mismatch == 0 and read as success. The first
     version of this comment claimed a collision "is a fair failure and says
     so", which was wrong. The gate reads the kernel's allocation log as well,
     which is where a wrong answer would show up. */
  open_result_t explicit_open;
  explicit_open.open_failed = 0U;
  explicit_open.port = 0U;
  explicit_open.sockfd = 0U;
  const u64 explicit_wanted = 52400U;
  summary.opens_attempted++;
  if (xaios_net_open_udp(explicit_wanted, &explicit_open.sockfd,
                         &explicit_open.port) < 0) {
    explicit_open.open_failed = 1U;
    summary.opens_failed++;
  } else if (explicit_open.port != explicit_wanted) {
    summary.explicit_port_mismatched++;
  }
  summary.explicit_port = explicit_open.port;

  /* The first socket, which has the port nobody named, is the one that sends.
     That is the whole point of the port existing. */
  if (opened[0].open_failed == 0U) {
    summary.sends_attempted++;
    if (datagram_leaves(opened[0].sockfd) == 0U) summary.sends_failed++;
  }

  /* Filled while the three sockets above are still open, so what it walks
     towards is the ceiling rather than the whole registry. */
  fill_registry(&summary);

  for (u64 i = 0U; i < OPEN_COUNT; ++i) {
    if (opened[i].sockfd != 0U && xaios_net_close(opened[i].sockfd) < 0) {
      summary.closes_failed++;
    }
  }
  if (explicit_open.sockfd != 0U &&
      xaios_net_close(explicit_open.sockfd) < 0) {
    summary.closes_failed++;
  }

  /* One line, whatever the numbers, because a line that appears only when they
     flatter is silent in the ordinary case and reads as an absent feature. */
  xaios_log_u64("/bin/netsocktest: summary opens=", summary.opens_attempted,
                "");
  xaios_log_u64(" opens_failed=", summary.opens_failed, "");
  xaios_log_u64(" port_zero=", summary.port_zero_returned, "");
  xaios_log_u64(" out_of_range=", summary.ports_out_of_range, "");
  xaios_log_u64(" duplicated=", summary.ports_duplicated, "");
  xaios_log_u64(" explicit_mismatch=", summary.explicit_port_mismatched, "");
  xaios_log_u64(" sends=", summary.sends_attempted, "");
  xaios_log_u64(" sends_failed=", summary.sends_failed, "");
  xaios_log_u64(" closes_failed=", summary.closes_failed, "");
  xaios_log_u64(" first_port=", summary.first_port, "");
  xaios_log_u64(" second_port=", summary.second_port, "");
  xaios_log_u64(" explicit_port=", summary.explicit_port, "");
  xaios_log_u64(" registry_fill_ok=", summary.registry_fill_ok, "");
  xaios_log_u64(" registry_refused=", summary.registry_refused, "");
  xaios_log_u64(" tcp_after_udp_full=", summary.tcp_after_udp_full, "\n");

  xaios_log("/bin/netsocktest: complete\n");
  return 0;
}
