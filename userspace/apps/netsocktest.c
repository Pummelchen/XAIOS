/* A datagram socket with a name of its own, which is what a QUIC client has
 * before its first packet.
 *
 * WT-35. The port already had UDP: `xaios_net_bind_udp` for a program that
 * knows the port it wants, and `xaios_net_sendto`/`xaios_net_recvfrom` for the
 * traffic. What it did not have was a way to be given a port, and that is the
 * one thing a client needs first. `xaios_net_listen` with the UDP protocol
 * carries a receive path and refuses a zero port; a client that has never
 * received anything has no port to name and no listener to stand behind, and
 * `xaios_net_sendto` on a socket that was never bound sends from port zero,
 * which no peer can reply to.
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
} summary_t;

/* Port zero asks the kernel to choose. Both the descriptor and the port are
   taken from the call rather than assumed: the port is the caller's own
   address, and a caller that guessed it would be telling peers a lie. */
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
     two ephemeral draws are unlikely to have taken; a collision is a fair
     failure and says so. */
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
  xaios_log_u64(" explicit_port=", summary.explicit_port, "\n");

  xaios_log("/bin/netsocktest: complete\n");
  return 0;
}
