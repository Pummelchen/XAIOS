#ifndef SSHD_H
#define SSHD_H

#include <stdint.h>
#include <xaios_user.h>

#define SSHD_PORT 22U
#define SSHD_UDP_ECHO_PORT 2223U

/* Connection limits */
#define SSHD_MAX_WORKER_THREADS 16
#define SSHD_MAX_CONNECTIONS_PER_IP 10

/* Timeout values in nanoseconds. */
#define SSHD_TIMEOUT_CONNECT UINT64_C(30000000000)
#define SSHD_TIMEOUT_AUTH UINT64_C(120000000000)
#define SSHD_TIMEOUT_IDLE UINT64_C(300000000000)
#define SSHD_KEEPALIVE_INTERVAL UINT64_C(30000000000)
#define SSHD_REKEY_INTERVAL UINT64_C(3600000000000)

/* How long a peer may keep the server waiting for its socket, and how little
   it may take in that time. This is B-40.
 *
 * sshd is one thread. A send that cannot complete does not stall one session:
 * the loop that serves every other session, and the accept that admits new
 * ones, is inside it. So the transmit path has always had a bound -- but the
 * bound asked the wrong question. It measured the gap since the last byte and
 * reset on any byte at all, so a peer that took one byte every nine seconds
 * renewed it forever and held the whole machine while doing so.
 *
 * The question a bound has to ask is not "has this peer taken a byte" but "is
 * this peer taking the data". So the window keeps the ten seconds the gap
 * bound used -- a peer that goes quiet for ten seconds is dropped exactly as
 * before -- and adds the floor that makes it mean something: in each such
 * window the peer must have taken at least SSHD_TRANSMIT_WINDOW_MIN_BYTES.
 * Below that it is not a slow link, it is a peer holding the server. A window
 * the peer clears starts another, so a genuinely slow session runs as long as
 * it keeps taking its data.
 *
 * The floor is 10 KiB per ten seconds, which is 1 KiB/s. The largest packet
 * this server writes is SSH_MAX_PACKET_SIZE, 35000 bytes, so a peer at exactly
 * the floor can hold the loop for about thirty-five seconds and no longer. A
 * link that cannot sustain 1 KiB/s is slower than a 9600-baud data call, and
 * four orders of magnitude below what this guest's own network does; the
 * emulated link in the gates measures in megabytes per second. The trade is
 * deliberate and it is the single-threaded server's to make: a peer slower
 * than that loses its connection, rather than every other session losing the
 * server. */
#define SSHD_TIMEOUT_TRANSMIT_WINDOW UINT64_C(10000000000)
#define SSHD_TRANSMIT_WINDOW_MIN_BYTES UINT64_C(10240)

/* What a connection's close_requested says about the transport underneath it.
 *
 * POLITE is the ordinary request: the main loop writes a disconnect message
 * and closes. SILENT says the byte stream is already unusable -- a transmit
 * was abandoned part way through an encrypted packet, so what the peer would
 * read next is not a packet boundary -- and, more to the point here, that the
 * socket which would not take the last packet will not take a disconnect
 * either. Writing one costs another full transmit window with the whole
 * server waiting on it and tells the peer nothing it can use. */
#define SSHD_CLOSE_REQUEST_POLITE 1U
#define SSHD_CLOSE_REQUEST_SILENT 2U

/* Rate limiting */
#define SSHD_RATE_LIMIT_MAX_ENTRIES 256
#define SSHD_RATE_LIMIT_MAX_FAILURES 10
#define SSHD_RATE_LIMIT_BAN_DURATION UINT64_C(3600000000000)
#define SSHD_CONNECTION_RATE_WINDOW UINT64_C(60000000000)
#define SSHD_CONNECTION_RATE_LIMIT 120U

/* The mutable filesystem stores at most 8 KiB per file. */
#define SSHD_LOG_ROTATE_BYTES 7168U

/* How long one pass of the service loop may take before the console is told.
 *
 * This is not a latency budget; it is the point at which a pause stops being
 * slowness and becomes an outage of the machine's networking. The guest's TCP
 * state machine runs inside the network syscalls this process makes and inside
 * its wait -- there is no timer and no interrupt behind it -- so while this
 * loop is busy elsewhere nothing is taken off the receive ring, no ACK is
 * sent, and nothing is retransmitted. A peer cannot tell that from the machine
 * having gone away, and after a few seconds of it a peer's own TCP starts to
 * conclude the latter.
 *
 * One second, because an ordinary pass is microseconds to a few milliseconds
 * even under emulation -- three orders of magnitude of headroom, so the line
 * never appears for ordinary work -- while the two things known to be able to
 * hold this loop are measured in tens of seconds: a transmit waiting on a peer
 * is bounded by SSHD_TIMEOUT_TRANSMIT_WINDOW and may take several of those for
 * one packet, and a write to the durable volume is bounded by nothing here at
 * all. Below a second the line would be noise; far above it, the stall this
 * exists to catch would be over before anything was said. */
#define SSHD_LOOP_STALL_REPORT_NS UINT64_C(1000000000)

/* Authentication */
#define SSHD_MAX_AUTH_ATTEMPTS 5
#define SSHD_MAX_USERS 100
#define SSHD_USERNAME_MAX 64
#define SSHD_PASSWORD_HASH_SIZE 32
#define SSHD_PASSWORD_SALT_MAX 32
#define SSHD_PASSWORD_ITERATIONS_MIN 100000U
#define SSHD_PASSWORD_ITERATIONS_MAX 1000000U

/* User database entry */
typedef struct {
  char username[SSHD_USERNAME_MAX];
  uint8_t password_salt[SSHD_PASSWORD_SALT_MAX];
  uint32_t password_salt_len;
  uint32_t password_iterations;
  uint8_t password_hash[SSHD_PASSWORD_HASH_SIZE];
  int active;
} sshd_user_t;

/* Rate limiting entry — supports both IPv4 and IPv6 addresses */
typedef struct {
  xaios_ip_addr_user_t ip_address;
  uint64_t last_attempt_time;
  uint32_t failure_count;
  uint64_t ban_until;
  uint64_t connection_window_start;
  uint32_t connection_count;
} sshd_rate_limit_entry_t;

/* Connection statistics */
typedef struct {
  uint32_t active_connections;
  uint32_t total_connections;
  uint32_t rejected_connections;
  /* Why a connection was refused before it was ever served, counted apart.
     B-28 was one refusal in 586 sessions with no guest-side account of it at
     all: the three pre-serve refusal paths reported to the audit log on the
     durable volume, which no gate reads, and one of them reported nothing.
     A refusal nobody can attribute is indistinguishable from a defect. */
  uint32_t rate_limited_connections;
  uint32_t capacity_refused_connections;
  uint32_t slot_exhausted_connections;
  uint64_t bytes_sent;
  uint64_t bytes_received;
} sshd_stats_t;

/* Active connection tracking for multi-client support */
typedef struct {
  u64 sockfd;
  int active;
  xaios_ip_addr_user_t client_addr;
  uint64_t last_activity;
} sshd_active_conn_t;

#define SSHD_MAX_ACTIVE_CONNECTIONS 64

/* Logging levels */
#define SSH_LOG_INFO  0
#define SSH_LOG_WARN  1
#define SSH_LOG_ERROR 2

void ssh_log(int level, const char *fmt, ...);
int sshd_run(void);
uint32_t sshd_max_channels_per_connection(void);
uint32_t sshd_command_rate_per_minute(void);
int sshd_reload_control_state(const char *command);

#endif
