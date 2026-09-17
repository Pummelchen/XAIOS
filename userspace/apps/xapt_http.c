#include <xaios_user.h>

#include "xapt_tls.h"

#include "xapt_internal.h"

/* Everything that moves bytes between xapt and the repository host: the
   address it dials, the request it frames, the response headers it validates,
   and the body it hands to a caller's sink -- over a plain socket or a
   xapt_tls session, chosen by the loaded config. Callers above it supply the
   sink and the local paths; no command logic lives here. */

static int parse_ipv4(const char *text, xaios_ip_addr_user_t *address) {
  u32 part = 0U;
  u32 value = 0U;
  u32 digits = 0U;
  xaios_memzero(address, sizeof(*address));
  for (u32 i = 0U;; ++i) {
    char character = text[i];
    if (character >= '0' && character <= '9') {
      value = value * 10U + (u32)(character - '0');
      if (value > 255U || ++digits > 3U) return -1;
    } else if (character == '.' || character == '\0') {
      if (digits == 0U || part >= 4U) return -1;
      address->addr[part++] = (unsigned char)value;
      value = 0U;
      digits = 0U;
      if (character == '\0') break;
    } else {
      return -1;
    }
  }
  if (part != 4U) return -1;
  address->family = 4U;
  return 0;
}

static int resolve_host(const char *host, xaios_ip_addr_user_t *address) {
  u64 deadline = xaios_clock_nanos() + 5000000000ULL;
  if (parse_ipv4(host, address) == 0) return 0;
  while (xaios_clock_nanos() < deadline) {
    int status = xaios_net_resolve_address(host, 4U, address);
    if (status == 0) return 0;
    if (status != XAIOS_ERR_BUSY) return -1;
  }
  return -1;
}

static int send_all(u64 socket, const char *data, u64 size,
                    u32 tls_required) {
  if (tls_required != 0U) return xapt_tls_write(data, size);
  u64 offset = 0U;
  while (offset < size) {
    u64 sent = 0U;
    int status = xaios_net_send(socket, data + offset, size - offset, &sent);
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0 || sent == 0U) return -1;
    offset += sent;
  }
  return 0;
}

static int build_path(char *output, u64 capacity, const char *base,
                      const char *path) {
  u64 used = 0U;
  if (!xapt_path_valid(path)) return -1;
  if (base[0] != '\0' && !xapt_text_equal(base, "/")) {
    xaios_append_cstr(output, capacity, &used, base);
  }
  xaios_append_cstr(output, capacity, &used, path);
  return used + 1U < capacity ? 0 : -1;
}

static int parse_content_length(const char *header, u64 header_size,
                                u64 *content_length) {
  static const char key[] = "Content-Length:";
  for (u64 i = 0U; i + sizeof(key) - 1U < header_size; ++i) {
    u64 j = 0U;
    while (j < sizeof(key) - 1U && header[i + j] == key[j]) ++j;
    if (j != sizeof(key) - 1U) continue;
    u64 start = i + j;
    while (start < header_size && header[start] == ' ') ++start;
    u64 end = start;
    while (end < header_size && header[end] >= '0' && header[end] <= '9')
      ++end;
    return xapt_parse_u64(header + start, end - start, content_length);
  }
  return -1;
}

int xapt_http_get(const xapt_config_t *config, const char *catalog_path,
                  xapt_sink_t sink, void *sink_context, u64 *body_size) {
  xaios_ip_addr_user_t address;
  char path[XAPT_PATH_BYTES];
  char request[512];
  u64 request_used = 0U;
  u64 socket = 0U;
  u64 received_total = 0U;
  u64 content_length = 0U;
  u64 header_used = 0U;
  u32 header_complete = 0U;
  u64 deadline = xaios_clock_nanos() + 600000000000ULL;
  xapt_http_error = 0U;
  xapt_http_received = 0U;
  xapt_http_expected = 0U;
  if (build_path(path, sizeof(path), config->base, catalog_path) != 0) {
    xapt_http_error = 1U;
    return -1;
  }
  if (resolve_host(config->address[0] != '\0' ? config->address : config->host,
                   &address) != 0) {
    xapt_http_error = 2U;
    return -1;
  }
  if (xaios_net_connect(&address, config->port, &socket) != 0) {
    xapt_http_error = 3U;
    return -1;
  }
  xaios_memzero(request, sizeof(request));
  xaios_append_cstr(request, sizeof(request), &request_used, "GET ");
  xaios_append_cstr(request, sizeof(request), &request_used, path);
  xaios_append_cstr(request, sizeof(request), &request_used,
                    " HTTP/1.1\r\nHost: ");
  xaios_append_cstr(request, sizeof(request), &request_used, config->host);
  xaios_append_cstr(request, sizeof(request), &request_used,
                    "\r\nConnection: close\r\nAccept: application/octet-stream\r\n\r\n");
  if (config->tls_required != 0U &&
      xapt_tls_open(socket, config->host, config->tls_rsa_modulus) != 0) {
    xapt_http_error = 100U + (u32)xapt_tls_last_error();
    (void)xaios_net_close(socket);
    return -1;
  }
  if (send_all(socket, request, request_used, config->tls_required) != 0) {
    xapt_http_error = 4U;
    (void)xaios_net_close(socket);
    return -1;
  }

  while (xaios_clock_nanos() < deadline) {
    u64 received = 0U;
    int status;
    if (config->tls_required != 0U) {
      status = xapt_tls_read(xapt_buffer, sizeof(xapt_buffer));
      received = status > 0 ? (u64)status : 0U;
      if (status < 0) {
        xapt_http_error = 200U + (u32)xapt_tls_last_error();
        status = -1;
      } else {
        status = 0;
      }
    } else {
      status = xaios_net_recv(socket, xapt_buffer, sizeof(xapt_buffer),
                              &received);
    }
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0) break;
    if (received == 0U) continue;
    u64 cursor = 0U;
    if (header_complete == 0U) {
      while (cursor < received && header_complete == 0U) {
        /* Headers accumulate in xapt_catalog before the body claims it, so the
           cap must hold against that buffer, not xapt_buffer: the old test only
           worked because xapt_buffer happens to be the smaller of the two. */
        if (header_used + 1U >= sizeof(xapt_buffer) ||
            header_used + 1U >= sizeof(xapt_catalog)) {
          xapt_http_error = 5U;
          (void)xaios_net_close(socket);
          return -1;
        }
        xapt_catalog[header_used++] = xapt_buffer[cursor++];
        if (header_used >= 4U && xapt_catalog[header_used - 4U] == '\r' &&
            xapt_catalog[header_used - 3U] == '\n' &&
            xapt_catalog[header_used - 2U] == '\r' &&
            xapt_catalog[header_used - 1U] == '\n') {
          header_complete = 1U;
        }
      }
      if (header_complete != 0U) {
        if (header_used < 12U ||
            !xapt_text_starts(xapt_catalog, "HTTP/1.1 200") ||
            parse_content_length(xapt_catalog, header_used, &content_length) !=
                0) {
          xapt_http_error = 6U;
          (void)xaios_net_close(socket);
          return -1;
        }
      }
    }
    if (header_complete != 0U && cursor < received) {
      u32 body = (u32)(received - cursor);
      if (received_total + body > content_length ||
          sink((const unsigned char *)xapt_buffer + cursor, body,
               sink_context) != 0) {
        xapt_http_error = 7U;
        (void)xaios_net_close(socket);
        return -1;
      }
      received_total += body;
    }
    if (header_complete != 0U && received_total == content_length) break;
  }
  if (config->tls_required != 0U) (void)xapt_tls_close();
  (void)xaios_net_close(socket);
  xapt_http_received = received_total;
  xapt_http_expected = content_length;
  if (header_complete == 0U || received_total != content_length) {
    xapt_http_error = 8U;
    return -1;
  }
  if (body_size != 0) *body_size = received_total;
  return 0;
}

typedef struct file_sink_context {
  int fd;
} file_sink_context_t;

static int file_sink(const unsigned char *data, u32 size, void *context) {
  file_sink_context_t *file = (file_sink_context_t *)context;
  u32 offset = 0U;
  while (offset < size) {
    int written = xaios_fs_write(file->fd, data + offset, size - offset);
    if (written <= 0) return -1;
    offset += (u32)written;
  }
  return 0;
}

int xapt_http_download(const xapt_config_t *config, const char *remote_path,
                       const char *local_path, u64 *size) {
  file_sink_context_t context;
  context.fd = xaios_fs_open(local_path, XAIOS_XBFS_OPEN_WRITE |
                                             XAIOS_XBFS_OPEN_CREATE |
                                             XAIOS_XBFS_OPEN_TRUNCATE);
  if (context.fd < 0) {
    xapt_http_error = 9U;
    return -1;
  }
  int status = xapt_http_get(config, remote_path, file_sink, &context, size);
  if (xaios_fs_fsync(context.fd) != 0) {
    xapt_http_error = 10U;
    status = -1;
  }
  if (xaios_fs_close(context.fd) != 0) {
    xapt_http_error = 11U;
    status = -1;
  }
  if (status != 0) (void)xaios_fs_delete(local_path);
  return status;
}
