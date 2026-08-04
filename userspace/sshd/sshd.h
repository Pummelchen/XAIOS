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

/* Rate limiting */
#define SSHD_RATE_LIMIT_MAX_ENTRIES 256
#define SSHD_RATE_LIMIT_MAX_FAILURES 10
#define SSHD_RATE_LIMIT_BAN_DURATION UINT64_C(3600000000000)
#define SSHD_CONNECTION_RATE_WINDOW UINT64_C(60000000000)
#define SSHD_CONNECTION_RATE_LIMIT 120U

/* The mutable filesystem stores at most 8 KiB per file. */
#define SSHD_LOG_ROTATE_BYTES 7168U

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
