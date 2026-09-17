#include "sshd.h"
#include "sshd_auth.h"
#include "sshd_audit.h"
#include "sshd_console_screen.h"
#include "sshd_console_programs.h"
#include "ssh_connection.h"
#include "ssh_crypto.h"
#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_host_key.h"
#include "ssh_mlkem.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include "less_pager.h"
#include <xaios_screen.h>
#include "nano_editor.h"
#include "pong_game.h"
#include <xaios_user.h>
#include "sshd_internal.h"
#include "sshd_diagnostics.h"
#include "sshd_console_ui.h"
#include "sshd_config.h"
#include "sshd_console_session.h"
#include "sshd_connection_support.h"
#include "sshd_service.h"

/* Connection statistics and close accounting. They moved here with the accept
   path that updates them; sshd_diagnostics.c reads the active count back
   through sshd_active_connections() below rather than touching the block. */
static sshd_stats_t g_server_stats;

/* Running count of closed connections; log_durable_cost() is given it after
   each close and sshd_diagnostics.c prints it in its per-close line. */
static uint32_t g_connection_close_count;

/* The active-connection count sshd_diagnostics.c prints in its stall lines.
   A value, not the statistics block: the counters stay here with the accept
   path that updates them. */
uint32_t sshd_active_connections(void) {
  return __atomic_load_n(&g_server_stats.active_connections, __ATOMIC_ACQUIRE);
}

static void console_tick(void) {
  for (uint32_t count = 0U; count < 32U; ++count) {
    char value = 0;
    int received = xaios_console_read(&value);
    if (received <= 0) return;
    if (g_console_nano.active != 0U) {
      uint32_t frame_size = 0U;
      uint32_t should_exit = 0U;
      if (nano_editor_input(&g_console_nano, (const uint8_t *)&value, 1U,
                            &should_exit) != 0) {
        should_exit = 1U;
      }
      if (should_exit != 0U) {
        g_console_nano.active = 0U;
        console_write(
            "\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r");
        console_prompt();
      } else if (nano_editor_render(&g_console_nano, g_console_output,
                                    sizeof(g_console_output),
                                    &frame_size) == 0) {
        (void)sshd_console_write_bytes(g_console_output, frame_size);
      }
      continue;
    }
    if (g_console_less.active != 0U) {
      uint32_t frame_size = 0U;
      uint32_t should_exit = 0U;
      if (less_pager_input(&g_console_less, (const uint8_t *)&value, 1U,
                           &should_exit) != 0) {
        should_exit = 1U;
      }
      if (should_exit != 0U) {
        console_finish_less();
      } else if (less_pager_render(&g_console_less, g_console_output,
                                   sizeof(g_console_output),
                                   &frame_size) == 0) {
        (void)sshd_console_write_bytes(g_console_output, frame_size);
      }
      continue;
    }
    if (sshd_console_program_active() != 0) {
      sshd_console_program_input(value);
      continue;
    }
    if (g_console_pong.active != 0U) {
      uint32_t should_exit = 0U;
      uint64_t now_ns = xaios_clock_nanos();
      if (pong_game_input(&g_console_pong, (const uint8_t *)&value, 1U,
                          &should_exit, now_ns) != 0 ||
          should_exit != 0U) {
        console_finish_pong();
      } else if (console_render_pong(now_ns) != 0) {
        console_finish_pong();
      }
      continue;
    }
    if (value == '\n' && g_console_ignore_lf != 0U) {
      g_console_ignore_lf = 0U;
      continue;
    }
    g_console_ignore_lf = 0U;
    if (value == '\r' || value == '\n') {
      g_console_ignore_lf = value == '\r' ? 1U : 0U;
      if (g_console_auth_state == SSHD_CONSOLE_AUTH_SHELL) {
        console_execute_command();
      } else if (g_console_auth_state != SSHD_CONSOLE_AUTH_LOCKED) {
        console_submit_auth();
      }
    } else if (value == '\b' || (uint8_t)value == UINT8_C(0x7f)) {
      if (g_console_command_length != 0U) {
        --g_console_command_length;
        if (g_console_auth_state != SSHD_CONSOLE_AUTH_PASSWORD) {
          console_write("\b \b");
        }
      }
    } else if ((uint8_t)value == UINT8_C(0x03)) {
      g_console_command_length = 0U;
      console_write("^C\n");
      if (g_console_auth_state == SSHD_CONSOLE_AUTH_SHELL) {
        console_prompt();
      } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_USER) {
        console_write_login_prompt();
      } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_PASSWORD) {
        console_write("Password: ");
      }
    } else if ((uint8_t)value == UINT8_C(0x0c)) {
      console_render_boot_status();
    } else if (g_console_auth_state != SSHD_CONSOLE_AUTH_LOCKED &&
               value >= ' ' && value <= '~' &&
               g_console_command_length + 1U < sizeof(g_console_command)) {
      g_console_command[g_console_command_length++] = value;
      if (g_console_auth_state == SSHD_CONSOLE_AUTH_PASSWORD) {
        /* Never echo a password. */
      } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_USER &&
                 sshd_auth_pin_available() != 0U &&
                 sshd_auth_pin_prefix(g_console_command,
                                      g_console_command_length)) {
        /* An all-digit entry at the login prompt may be a PIN, which is a
           secret rather than a user name, so mask it while it is typed. A
           user name that merely starts with digits is masked for those
           leading digits only. */
        static const char masked = '*';
        (void)xaios_console_write(&masked, 1U);
      } else {
        (void)xaios_console_write(&value, 1U);
      }
    }
  }
}

/* ---- Cooperative Polling Main Loop ---- */
int sshd_run(void) {
  u64 listen_fd = 0U;
  u64 udp_fd = 0U;
  int crypto_status;
  int network_status;

  g_console_ipv4 = xaios_net_local_ipv4();
  g_console_ssh_ready = 0U;
  g_console_boot_error = 0;
  network_status = sshd_verify_ipv4_ready();
  if (network_status != 0) {
    ssh_log(SSH_LOG_ERROR,
            "IPv4 network readiness check failed; refusing SSH startup status=%u\n",
            (uint64_t)(uint32_t)(-network_status));
    g_console_boot_error = 1000 - network_status;
    goto service_loop;
  }
  console_render_ssh_loading();

  if (crypto_random_init() != 0) {
    ssh_log(SSH_LOG_ERROR, "Secure entropy unavailable; refusing SSH startup\n");
    g_console_boot_error = 2001;
    goto service_loop;
  }
  if (ssh_host_key_init() != 0) {
    ssh_log(SSH_LOG_ERROR, "Persistent SSH host key unavailable\n");
    g_console_boot_error = 2002;
    goto service_loop;
  }
  crypto_status = ssh_crypto_self_test();
  if (crypto_status != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH crypto self-test failed check=%u\n",
            (uint64_t)(uint32_t)(-crypto_status));
    g_console_boot_error = 2100 - crypto_status;
    goto service_loop;
  }
  ssh_log(SSH_LOG_INFO, "SSH crypto self-test passed\n");
  if (ssh_mlkem768_self_test() != 0) {
    ssh_log(SSH_LOG_ERROR, "ML-KEM-768 self-test failed\n");
    g_console_boot_error = 2101;
    goto service_loop;
  }
  ssh_log(SSH_LOG_INFO, "ML-KEM-768 self-test passed\n");

  if (load_runtime_config() != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH runtime configuration rejected\n");
    g_console_boot_error = 2201;
    goto service_loop;
  }

  if (sshd_auth_load_users(g_password_auth_enabled) != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH user database rejected\n");
    g_console_boot_error = 2202;
    goto service_loop;
  }
  if (sshd_auth_load_pin(g_password_auth_enabled) != 0) {
    ssh_log(SSH_LOG_ERROR, "Local console PIN record rejected\n");
    g_console_boot_error = 2203;
    goto service_loop;
  }
  (void)sshd_keys_load();
  if (sshd_keys_database_invalid() != 0) {
    g_console_boot_error = 2203;
    goto service_loop;
  }

  ssh_mem_zero(&g_server_stats, sizeof(g_server_stats));

  ssh_conn_pool_init();

  /* A machine set up without remote access serves its console and nothing
     else. It says so, because "SSH is not running" should never be something
     a person has to discover by trying it. */
  if (!service_enabled("ssh")) {
    ssh_log(SSH_LOG_INFO,
            "Remote access is turned off for this machine; console only\n");
    console_write(
        "Remote access is turned off for this machine.\n"
        "The console below is the only way in.\n");
    goto service_loop;
  }

  if (xaios_net_listen(SSHD_PORT, &listen_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to listen on port %u\n", SSHD_PORT);
    g_console_boot_error = 2301;
    goto service_loop;
  }
  if (xaios_net_bind_udp(SSHD_UDP_ECHO_PORT, &udp_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to bind UDP port %u\n",
            SSHD_UDP_ECHO_PORT);
    xaios_net_close(listen_fd);
    listen_fd = 0U;
    g_console_boot_error = 2302;
    goto service_loop;
  }
  ssh_log(SSH_LOG_INFO, "SSH server listening on port %u\n", SSHD_PORT);
  ssh_log(SSH_LOG_INFO, "UDP echo service listening on port %u\n",
          SSHD_UDP_ECHO_PORT);
  ssh_log(SSH_LOG_INFO, "Cooperative polling: max %u concurrent connections\n",
          (uint64_t)SSH_MAX_CONNECTIONS);

  ssh_channel_init();
  xaios_log("sshd: Phase 2 runtime ready\n");
  xaios_log("boot-ui: progress=100 loaded=SSH-server loading=complete remaining=0\n");
  g_console_ssh_ready = 1U;

service_loop:
  console_render_boot_status();
  for (;;) {
    uint64_t pass_started = sshd_timer_now();
    /* Per pass, so a stall reports what this pass spent on the durable volume
       rather than what every pass has spent since boot. */
    ssh_audit_pass_reset();
    uint64_t now = pass_started;
    console_refresh_boot_ui(now);
    console_service_pong(now);
    sshd_console_program_service();
    console_tick();
    uint64_t after_console = sshd_timer_now();
    for (uint32_t i = 0; g_console_ssh_ready != 0U && i < 4U; ++i) {
      uint8_t udp_buffer[1478];
      xaios_ip_addr_user_t source_addr;
      u64 bytes_read = 0;
      u64 bytes_written = 0;
      xaios_memzero(&source_addr, sizeof(source_addr));
      if (xaios_net_recvfrom(udp_fd, udp_buffer, sizeof(udp_buffer),
                             &bytes_read, &source_addr) != 0 ||
          bytes_read == 0) {
        break;
      }
      if (xaios_net_send(udp_fd, udp_buffer, bytes_read, &bytes_written) != 0 ||
          bytes_written != bytes_read) {
        ssh_log(SSH_LOG_WARN, "UDP echo send failed\n");
      } else {
        ssh_log(SSH_LOG_INFO, "UDP payload delivered bytes=%u\n", bytes_read);
      }
    }

    uint64_t after_udp = sshd_timer_now();

    /* Try to accept new connections (non-blocking) */
    for (uint32_t i = 0; g_console_ssh_ready != 0U && i < 4U; ++i) {
      u64 conn_fd = 0;
      xaios_ip_addr_user_t peer_addr;
      u64 peer_port = 0;
      xaios_memzero(&peer_addr, sizeof(peer_addr));
      if (xaios_net_accept_addr(listen_fd, &conn_fd, &peer_addr, &peer_port) != 0) {
        break;
      }

      if (record_connection_attempt(&peer_addr) != 0) {
        ssh_log(SSH_LOG_WARN, "Connection rate limit reached\n");
        uint32_t limited = __atomic_add_fetch(
            &g_server_stats.rate_limited_connections, 1, __ATOMIC_RELEASE);
        log_connection_refusal("rate-limit", limited,
                               SSHD_CONNECTION_RATE_LIMIT);
        xaios_net_close(conn_fd);
        continue;
      }

      uint32_t active = __atomic_load_n(&g_server_stats.active_connections,
                                         __ATOMIC_ACQUIRE);
      if (active >= g_runtime_config.max_connections) {
        ssh_log(SSH_LOG_WARN, "Max connections reached\n");
        uint32_t rejected = __atomic_add_fetch(
            &g_server_stats.rejected_connections, 1, __ATOMIC_RELEASE);
        (void)__atomic_add_fetch(&g_server_stats.capacity_refused_connections,
                                 1, __ATOMIC_RELEASE);
        log_connection_refusal("capacity", rejected,
                               g_runtime_config.max_connections);
        xaios_net_close(conn_fd);
        continue;
      }

      ssh_connection_t *conn = ssh_conn_alloc();
      if (!conn) {
        /* The connection table had no free slot while the active count said
           there was room. That disagreement is a defect in itself, so it is
           reported rather than quietly dropped, which is what it used to be. */
        uint32_t exhausted = __atomic_add_fetch(
            &g_server_stats.slot_exhausted_connections, 1, __ATOMIC_RELEASE);
        log_connection_refusal("slot-exhausted", exhausted, active);
        xaios_net_close(conn_fd);
        continue;
      }

      conn->sockfd = conn_fd;
      conn->client_addr = peer_addr;
      conn->client_port = (uint16_t)peer_port;
      conn->state = SSH_STATE_INIT;
      conn->last_activity = sshd_timer_now();
      conn->last_keepalive = conn->last_activity;
      conn->connect_time = conn->last_activity;
      conn->version_len = 0;
      conn->auth_attempts = 0;

      __atomic_add_fetch(&g_server_stats.total_connections, 1, __ATOMIC_RELEASE);
      __atomic_add_fetch(&g_server_stats.active_connections, 1, __ATOMIC_RELEASE);
      ssh_log(SSH_LOG_INFO, "Accepted connection %llx (total: %u)\n",
              conn_fd, active + 1);
    }

    uint64_t after_accept = sshd_timer_now();

    /* Process each active connection (cooperative time-slicing) */
    for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
      ssh_connection_t *conn = ssh_conn_by_index(i);
      if (!conn) continue;
      sshd_close_reason_set(0);

      /* Check for timeouts */
      uint64_t now = sshd_timer_now();
      if (conn->state == SSH_STATE_INIT || conn->state == SSH_STATE_KEX ||
          conn->state == SSH_STATE_KEX_SENT || conn->state == SSH_STATE_NEWKEYS ||
          conn->state == SSH_STATE_NEWKEYS_SENT ||
          conn->state == SSH_STATE_REKEY_KEXINIT ||
          conn->state == SSH_STATE_REKEY_DH ||
          conn->state == SSH_STATE_REKEY_NEWKEYS) {
        uint64_t exchange_start = conn->state >= SSH_STATE_REKEY_KEXINIT ?
                                      conn->kex_start_time : conn->connect_time;
        if (now - exchange_start > SSHD_TIMEOUT_CONNECT) {
          ssh_log(SSH_LOG_WARN, "Connect timeout\n");
          sshd_close_reason_set("connect-timeout");
          goto close_conn;
        }
      }
      if (conn->state == SSH_STATE_AUTH) {
        if (now - conn->connect_time > SSHD_TIMEOUT_AUTH) {
          ssh_log(SSH_LOG_WARN, "Auth timeout\n");
          sshd_close_reason_set("auth-timeout");
          goto close_conn;
        }
      }

      int result = conn->close_requested != 0U ? -1 : process_connection(conn);
      if (result != 0) {
close_conn:
        /* Send disconnect message if encrypted -- unless the transport is
           the thing that failed. A connection marked SILENT was closed
           because a transmit was abandoned part way through a packet, so a
           disconnect message would be appended to a truncated one, and the
           socket that would not take those bytes will not take these. It
           would cost another full transmit window with the whole server
           waiting on it: B-40's symptom, produced by B-40's cure. */
        if (conn->state >= SSH_STATE_AUTH &&
            conn->close_requested != SSHD_CLOSE_REQUEST_SILENT) {
          uint8_t disconnect_msg[17];
          ssh_mem_zero(disconnect_msg, sizeof(disconnect_msg));
          disconnect_msg[0] = SSH_MSG_DISCONNECT;
          ssh_write_u32_be(disconnect_msg + 1, SSH_DISCONNECT_BY_APPLICATION);
          ssh_write_u32_be(disconnect_msg + 5, 0);
          ssh_write_u32_be(disconnect_msg + 9, 0);
          conn_packet_write_encrypted(conn, disconnect_msg, 13);
        }

        ssh_channel_close_connection((int)conn->sockfd);
        /* Read before the slot is zeroed: ssh_conn_free wipes the struct, and
           the console line is about the connection, not about the slot. */
        uint64_t closed_sockfd = conn->sockfd;
        uint32_t closed_state = (uint32_t)conn->state;
        uint64_t closed_connect_time = conn->connect_time;
        uint32_t closed_silently =
            conn->close_requested == SSHD_CLOSE_REQUEST_SILENT;
        xaios_net_close(conn->sockfd);
        __atomic_sub_fetch(&g_server_stats.active_connections, 1,
                           __ATOMIC_RELEASE);
        ssh_conn_free(conn);
        ++g_connection_close_count;
        const char *close_reason = sshd_close_reason();
        log_connection_close(
            close_reason != 0 ? close_reason
                              : (closed_silently != 0U ? "transport"
                                                       : "protocol"),
            closed_sockfd, closed_state,
            sshd_timer_now() - closed_connect_time, g_connection_close_count);
        ssh_log(SSH_LOG_INFO, "Connection closed\n");
        /* After the audit line above, so the totals include this connection's
           last record rather than all of it but that. The key-loader counters
           live with the cache in sshd_keys.c and are read out here. */
        uint32_t key_load_calls = 0U;
        uint32_t key_load_file_reads = 0U;
        uint64_t key_load_ns = 0U;
        sshd_keys_load_stats(&key_load_calls, &key_load_file_reads,
                             &key_load_ns);
        log_durable_cost(g_connection_close_count, key_load_calls,
                         key_load_file_reads, key_load_ns);
        /* Only when there is enough to be worth the fsync.
         *
         * Flushing at every close made it one fsync per connection, which was
         * already five times better than one per line. But the cost of a flush
         * does not depend on how much is in it -- it is a host fsync either
         * way -- so paying one for forty bytes is the same window as paying
         * one for three kilobytes, and the window is what drops connections.
         *
         * Half the buffer is the threshold rather than "when it is full"
         * because a machine that goes quiet should not sit on records
         * indefinitely: a connection's worth of traffic is enough to cross it,
         * a handful of idle probes is not. Records still reach the file in
         * order and no line is dropped; what changes is how long the last few
         * may wait, and this file is read by no soak and no gate. */
        if (ssh_audit_buffered() >= SSHD_AUDIT_BUFFER_BYTES / 2U) {
          ssh_audit_flush();
        }
      }
    }
    uint64_t after_connections = sshd_timer_now();
    if (g_console_ssh_ready != 0U && ssh_channel_tick(sshd_timer_now()) != 0) {
      ssh_log(SSH_LOG_WARN, "Interactive channel refresh failed\n");
    }
    report_service_loop_stall(pass_started, after_console, after_udp,
                              after_accept, after_connections, sshd_timer_now());
    /* Nothing above blocks, so left to itself this loop spins and keeps a
       whole core at a hundred percent from boot -- which the process
       monitor showed on every machine once it was honest about who was
       running. The kernel wait returns the moment there is console input,
       a packet or connection on a socket sshd owns, or output from a child;
       otherwise after a timeout that only paces the timed housekeeping
       above. A game on the console wants frames, and gets a shorter one. */
    uint64_t wait_requested = g_console_pong.active != 0U
                                  ? UINT64_C(16000000)
                                  : UINT64_C(50000000);
    uint64_t wait_started = sshd_timer_now();
    (void)xaios_wait_events(wait_requested);
    report_wait_overrun(wait_requested, wait_started, sshd_timer_now());
  }

  return 0;
}
