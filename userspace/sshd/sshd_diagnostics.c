/*
 * sshd's console-visible diagnostics: how a connection ended and what held the
 * service loop.
 *
 * The counters live here; sshd.c's service loop calls in once per refused
 * connection, once per close, and once per pass. See sshd_diagnostics.h for
 * what crosses and why.
 */

#include "sshd_diagnostics.h"

#include "sshd.h"
#include "sshd_audit.h"

/* Say on the console why a connection was refused before it was served.
 *
 * ssh_log writes to the audit file on the durable volume. That is right for an
 * audit record and useless for diagnosis: B-28 was a single refused SFTP
 * session in 586, and the guest's console -- the only thing the soak captures
 * -- said nothing, because the rate-limit path logged only to that file, the
 * capacity path announced itself to the console once per boot and never again,
 * and the slot-exhaustion path said nothing anywhere.
 *
 * Every refusal now names its reason and carries the count for that reason, so
 * a client-side "Connection closed" can be attributed instead of guessed at.
 * They are rare by construction; if they are not, that is the finding. */
void log_connection_refusal(const char *reason, uint32_t observed,
                          uint32_t detail) {
  char line[192];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset,
                    "sshd: connection refused reason=");
  xaios_append_cstr(line, sizeof(line), &offset, reason);
  xaios_append_cstr(line, sizeof(line), &offset, " count=");
  xaios_append_u64(line, sizeof(line), &offset, observed);
  xaios_append_cstr(line, sizeof(line), &offset, " detail=");
  xaios_append_u64(line, sizeof(line), &offset, detail);
  xaios_append_cstr(line, sizeof(line), &offset, "\n");
  xaios_log(line);
}

/* Why a connection that *was* served is being let go, on the console.
 *
 * The refusal lines above cover the three ways a connection is turned away
 * before a byte of SSH is spoken. Everything past that point ended with
 * `ssh_log(... "Connection closed")` and nothing else -- the audit file on the
 * durable volume, which no soak and no gate reads. So the console's account of
 * a connection the server accepted and then gave up on was one kernel line,
 * `syscall: net_close`, with no reason attached to it and nothing at all until
 * the close actually happened.
 *
 * That is what makes B-43 unreadable. Its evidence is an accept with nothing
 * after it, and "the server closed this connection thirty seconds later
 * because the client never sent a version" and "the server never looked at
 * this connection" print exactly the same thing: nothing. The connect-timeout
 * path is the one that matters most there and it is the quietest, because a
 * client that has said nothing gives the console nothing either.
 *
 * One line per close, with the reason and a running count, so the two can be
 * told apart without a debugger on a laptop in another room. */

void log_connection_close(const char *reason, uint64_t sockfd,
                          uint32_t state, uint64_t held_ns,
                          uint32_t count) {
  char line[192];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset,
                    "sshd: connection closed reason=");
  xaios_append_cstr(line, sizeof(line), &offset, reason);
  xaios_append_cstr(line, sizeof(line), &offset, " sockfd=");
  xaios_append_u64(line, sizeof(line), &offset, sockfd);
  xaios_append_cstr(line, sizeof(line), &offset, " state=");
  xaios_append_u64(line, sizeof(line), &offset, state);
  xaios_append_cstr(line, sizeof(line), &offset, " held_ms=");
  xaios_append_u64(line, sizeof(line), &offset, held_ns / UINT64_C(1000000));
  xaios_append_cstr(line, sizeof(line), &offset, " count=");
  xaios_append_u64(line, sizeof(line), &offset, count);
  xaios_append_cstr(line, sizeof(line), &offset, "\n");
  xaios_log(line);
}

/* When one pass of the service loop took long enough to be a network outage.
 *
 * This process is not merely the SSH server: on this machine it is the thing
 * that drives the network. `network_poll_tick` -- which drains the device's
 * receive ring, runs the TCP state machine, sends the ACKs, retransmits what
 * was not acknowledged and expires dead flows -- has no timer behind it and no
 * interrupt handler and no kernel thread. It runs inside the network syscalls
 * a process makes, and inside `wait_events`. The network stack's own comment
 * says as much: "a poll that runs only inside network syscalls". sshd is
 * ordinarily the only process making those calls, so for the length of any
 * pause anywhere else in this loop the guest's networking does not exist: no
 * ACK leaves the machine, nothing is taken off the ring, and a peer that is
 * waiting is waiting on a stack that is not running.
 *
 * That is what makes this worth a console line. A pause here is invisible from
 * inside -- no timeout fires, no path is refused, nothing is closed -- and
 * from outside it is indistinguishable from the machine having gone away. B-43
 * is an accepted connection with nothing after it and a peer that gave up
 * about eighteen seconds later, twice, at two unrelated points in the
 * protocol; a pause of the whole stack is the only mechanism found that
 * produces the same duration at both, because the duration is then the
 * *client's* patience rather than any timer of ours.
 *
 * So the loop times itself, and a pass over the threshold names the phase it
 * was spent in. Three of the four phases contain blocking work that is not a
 * network syscall -- the console and its child, a transmit waiting on a peer,
 * a channel's turn, every `ssh_log` write to the durable volume along the way
 * -- and knowing which of them it was is the difference between a fix and
 * another round of guessing.
 *
 * The threshold is not a performance budget. An ordinary pass is microseconds
 * to low milliseconds; SSHD_LOOP_STALL_REPORT_NS is set where a pause has
 * stopped being slow and started being an absence, and it stays well clear of
 * ordinary work so that the line means something when it appears. */
static uint32_t g_loop_stall_count;

void report_service_loop_stall(uint64_t started, uint64_t after_console,
                               uint64_t after_udp, uint64_t after_accept,
                               uint64_t after_connections, uint64_t ended) {
  if (ended <= started || ended - started < SSHD_LOOP_STALL_REPORT_NS) return;

  /* The longest phase, which is the one worth naming. Computed from the marks
     rather than from a phase counter, so a pass whose time went somewhere this
     does not split out still reports the total honestly. */
  const char *phase = "console";
  uint64_t longest = after_console - started;
  if (after_udp - after_console > longest) {
    longest = after_udp - after_console;
    phase = "udp-echo";
  }
  if (after_accept - after_udp > longest) {
    longest = after_accept - after_udp;
    phase = "accept";
  }
  if (after_connections - after_accept > longest) {
    longest = after_connections - after_accept;
    phase = "connections";
  }
  if (ended - after_connections > longest) {
    longest = ended - after_connections;
    phase = "channels";
  }

  ++g_loop_stall_count;
  char line[288];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset,
                    "sshd: service loop stalled ms=");
  xaios_append_u64(line, sizeof(line), &offset,
                   (ended - started) / UINT64_C(1000000));
  xaios_append_cstr(line, sizeof(line), &offset, " phase=");
  xaios_append_cstr(line, sizeof(line), &offset, phase);
  xaios_append_cstr(line, sizeof(line), &offset, " phase_ms=");
  xaios_append_u64(line, sizeof(line), &offset, longest / UINT64_C(1000000));
  xaios_append_cstr(line, sizeof(line), &offset, " active=");
  xaios_append_u64(line, sizeof(line), &offset,
                   sshd_active_connections());
  xaios_append_cstr(line, sizeof(line), &offset, " durable_ms=");
  xaios_append_u64(line, sizeof(line), &offset,
                   ssh_audit_pass_durable_ns() / UINT64_C(1000000));
  xaios_append_cstr(line, sizeof(line), &offset, " count=");
  xaios_append_u64(line, sizeof(line), &offset, g_loop_stall_count);
  xaios_append_cstr(line, sizeof(line), &offset, "\n");
  xaios_log(line);
}

/* When the wait itself came back far later than it was asked to.
 *
 * The measurement above deliberately excludes the wait, because it is asking
 * what sshd *did* with the time. This asks the other question, and the two
 * answers are not interchangeable: a pass that took eighteen seconds says this
 * process held the machine, and a fifty-millisecond wait that took eighteen
 * seconds says this process was not running at all -- and neither was anything
 * else, because a guest that is not scheduled is a guest whose network stack
 * is not being driven either. From a peer both look identical, which is why
 * the console has to be able to tell them apart.
 *
 * On a hypervisor the second is a real answer rather than a defect of ours: a
 * VM can be descheduled, its disk can stall behind the host's, a snapshot can
 * be taken. B-43 was seen on a laptop running Fusion, so "the machine was not
 * running for eighteen seconds" is a hypothesis that has to be either
 * confirmed or ruled out before anything in this process is blamed, and until
 * now nothing on the console could do either.
 *
 * Allowance rather than a bare threshold: the wait is asked for fifty
 * milliseconds and may legitimately return a little after that, so what is
 * reported is the overrun beyond what was requested. */
static uint32_t g_wait_overrun_count;

void report_wait_overrun(uint64_t requested, uint64_t started,
                         uint64_t ended) {
  if (ended <= started) return;
  uint64_t elapsed = ended - started;
  if (elapsed < requested + SSHD_LOOP_STALL_REPORT_NS) return;

  ++g_wait_overrun_count;
  char line[224];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset,
                    "sshd: service loop wait overran ms=");
  xaios_append_u64(line, sizeof(line), &offset, elapsed / UINT64_C(1000000));
  xaios_append_cstr(line, sizeof(line), &offset, " requested_ms=");
  xaios_append_u64(line, sizeof(line), &offset, requested / UINT64_C(1000000));
  xaios_append_cstr(line, sizeof(line), &offset, " active=");
  xaios_append_u64(line, sizeof(line), &offset,
                   sshd_active_connections());
  xaios_append_cstr(line, sizeof(line), &offset, " count=");
  xaios_append_u64(line, sizeof(line), &offset, g_wait_overrun_count);
  xaios_append_cstr(line, sizeof(line), &offset, "\n");
  xaios_log(line);
}
