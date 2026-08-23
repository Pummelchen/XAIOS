#ifndef SSH_CHANNEL_H
#define SSH_CHANNEL_H

#include <xaios/types.h>
#include "less_pager.h"
#include "nano_editor.h"
#include "pong_game.h"

/* Interactive process-monitor session state.
   Held apart from the transport so the SSH channel and the local console can
   drive the same state machine instead of each keeping their own copy, which
   is what let the two surfaces disagree about how htop behaves. */
typedef struct xaios_htop_session {
  uint32_t active;
  uint32_t show_all;
  uint32_t show_cpus;
  uint32_t sort_key;
  uint32_t reverse;
  uint32_t cpu_start;
  uint32_t cpu_count;
  uint32_t process_start;
  uint32_t selected;
  uint32_t refresh_ms;
  uint32_t filter_mode;
  uint32_t help;
  uint32_t filter_length;
  uint32_t columns;
  uint32_t rows;
  uint64_t last_frame_ns;
  uint64_t next_refresh_ns;
  char filter[32];
} xaios_htop_session_t;

/* Where an htop session sends output and how it runs a sampling command.
   The SSH channel fills this in with its own transport, the local console with
   direct console writes, so both drive the identical session logic. */
typedef struct xaios_htop_sink {
  int (*write)(void *context, const uint8_t *data, uint32_t length);
  int (*run)(void *context, const char *command, char *output,
             unsigned long long capacity,
             unsigned long long *output_length);
  int (*busy)(void *context);
  void *context;
} xaios_htop_sink_t;

void xaios_htop_start(xaios_htop_session_t *session, const char *command,
                      uint32_t columns, uint32_t rows);
int xaios_htop_build_command(const xaios_htop_session_t *session,
                             char *command, uint32_t capacity);
int xaios_htop_frame_ready(xaios_htop_session_t *session,
                           uint64_t now_ns);
void xaios_htop_frame_sent(xaios_htop_session_t *session,
                           uint64_t now_ns);
int xaios_htop_render(xaios_htop_session_t *session,
                      const xaios_htop_sink_t *sink, uint64_t now_ns);
int xaios_htop_send_help(xaios_htop_session_t *session,
                         const xaios_htop_sink_t *sink,
                         uint64_t now_ns);
int xaios_htop_send_filter_prompt(xaios_htop_session_t *session,
                                  const xaios_htop_sink_t *sink,
                                  uint64_t now_ns);
/* Writes the terminal restore sequence and clears the session. Surface
   lifecycle (returning to a shell, closing a channel) stays with the caller. */
int xaios_htop_stop(xaios_htop_session_t *session,
                    const xaios_htop_sink_t *sink);
/* Returns negative on error. The session ends by clearing session->active,
   which the caller checks so it can run its own teardown -- returning to a
   shell, closing a channel, or reprinting the console prompt. */
int xaios_htop_input(xaios_htop_session_t *session,
                     const xaios_htop_sink_t *sink, uint64_t now_ns,
                     const unsigned char *data, uint32_t length);
#include "ssh_protocol.h"

#define SSH_CHANNELS_PER_CONNECTION 2U
#define SSH_CHANNEL_MAX 64U
#define SSH_CHANNEL_PENDING_SIZE 36864U
#define SSH_CHANNEL_SHELL_LINE_SIZE 256U
#define SSH_CHANNEL_INITIAL_WINDOW 65536U
#define SSH_CHANNEL_MAX_PACKET 10240U
#define SSH_CHANNEL_SFTP_REQUEST_MAX SSH_MAX_PACKET_SIZE
#define SSH_CHANNEL_SFTP_BUFFER_SIZE \
  (SSH_CHANNEL_SFTP_REQUEST_MAX + SSH_CHANNEL_MAX_PACKET)

typedef struct ssh_channel {
  uint32_t active;
  uint64_t owner_sockfd;
  uint32_t local_id;
  uint32_t remote_id;
  uint32_t window_size;
  uint32_t remote_window;
  uint32_t remote_max_packet;
  uint32_t pending_offset;
  uint32_t pending_used;
  uint32_t close_after_flush;
  uint32_t close_sent;
  uint32_t exit_status;
  uint32_t is_sftp;
  uint32_t is_forward;
  uint32_t is_agent;
  uint32_t agent_forwarding;
  uint32_t agent_open_pending;
  uint32_t agent_session_local_id;
  unsigned long long forward_fd;
  uint32_t pty_requested;
  uint32_t terminal_columns;
  uint32_t terminal_rows;
  xaios_htop_session_t htop;
  uint32_t shell_active;
  uint32_t shell_line_length;
  uint32_t shell_ignore_lf;
  uint32_t ssh_client_slot;
  uint32_t interactive_returns_to_shell;
  char shell_line[SSH_CHANNEL_SHELL_LINE_SIZE];
  nano_editor_t nano;
  less_pager_t less;
  pong_game_t pong;
  uint32_t sftp_rx_used;
  uint8_t sftp_rx[SSH_CHANNEL_SFTP_BUFFER_SIZE];
  uint8_t pending[SSH_CHANNEL_PENDING_SIZE];
} ssh_channel_t;

void ssh_channel_init(void);
void ssh_channel_close_connection(int sockfd);
int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt);
int ssh_channel_tick(uint64_t now_ns);
int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t len);
int ssh_channel_agent_send(const ssh_channel_t *session, const uint8_t *data,
                           uint32_t len);


/* Apply the terminal-application option promotion used for a PTY session.
   Exposed so the local console launches applications exactly as the SSH
   channel does, instead of maintaining a second copy of the rules. */
int ssh_terminal_promote_command(char *command, uint32_t capacity,
                                 uint32_t columns, uint32_t rows);

#endif
