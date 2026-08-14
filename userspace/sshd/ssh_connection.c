#include "ssh_connection.h"
#include "ssh_utils.h"
#include <xaios_user.h>

static ssh_connection_t g_connections[SSH_MAX_CONNECTIONS];
static ssh_connection_t g_client_connections[SSH_MAX_CLIENT_CONNECTIONS];
static ssh_connection_scratch_t g_scratch;

void ssh_conn_pool_init(void) {
  for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
    g_connections[i].active = 0;
  }
  for (uint32_t i = 0; i < SSH_MAX_CLIENT_CONNECTIONS; ++i) {
    g_client_connections[i].active = 0;
  }
}

ssh_connection_t *ssh_conn_client_alloc(void) {
  for (uint32_t i = 0; i < SSH_MAX_CLIENT_CONNECTIONS; ++i) {
    if (!g_client_connections[i].active) {
      ssh_mem_zero(&g_client_connections[i], sizeof(ssh_connection_t));
      g_client_connections[i].active = 1;
      return &g_client_connections[i];
    }
  }
  return (ssh_connection_t *)0;
}

ssh_connection_scratch_t *ssh_conn_scratch(void) {
  return &g_scratch;
}

int ssh_conn_send(ssh_connection_t *conn, const uint8_t *data,
                  u64 length, u64 *sent) {
  if (conn == 0 || data == 0 || sent == 0) return -1;
  if (conn->send_fn != 0)
    return conn->send_fn(conn->io_context, data, length, sent);
  return xaios_net_send(conn->sockfd, data, length, sent);
}

int ssh_conn_recv(ssh_connection_t *conn, uint8_t *data,
                  u64 length, u64 *received) {
  if (conn == 0 || data == 0 || received == 0) return -1;
  if (conn->recv_fn != 0)
    return conn->recv_fn(conn->io_context, data, length, received);
  return xaios_net_recv(conn->sockfd, data, length, received);
}

ssh_connection_t *ssh_conn_alloc(void) {
  for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
    if (!g_connections[i].active) {
      ssh_mem_zero(&g_connections[i], sizeof(ssh_connection_t));
      g_connections[i].active = 1;
      return &g_connections[i];
    }
  }
  return (ssh_connection_t *)0;
}

void ssh_conn_free(ssh_connection_t *conn) {
  if (!conn) return;
  ssh_mem_zero(conn, sizeof(ssh_connection_t));
}

ssh_connection_t *ssh_conn_find(uint64_t sockfd) {
  for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
    if (g_connections[i].active && g_connections[i].sockfd == sockfd) {
      return &g_connections[i];
    }
  }
  for (uint32_t i = 0; i < SSH_MAX_CLIENT_CONNECTIONS; ++i) {
    if (g_client_connections[i].active &&
        g_client_connections[i].sockfd == sockfd) {
      return &g_client_connections[i];
    }
  }
  return (ssh_connection_t *)0;
}

ssh_connection_t *ssh_conn_by_index(uint32_t idx) {
  if (idx >= SSH_MAX_CONNECTIONS) return (ssh_connection_t *)0;
  if (!g_connections[idx].active) return (ssh_connection_t *)0;
  return &g_connections[idx];
}
