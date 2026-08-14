#include <xaios_user.h>

#include "xapt_tls.h"

#define XAPT_BUFFER_BYTES 4096U
#define XAPT_LINE_BYTES 1024U
#define XAPT_PATH_BYTES 160U
#define XAPT_HOST_BYTES 80U
#define XAPT_CONFIG_PATH "/state/xapt/config"
#define XAPT_CATALOG_PATH "/state/xapt/catalog"
#define XAPT_STAGED_CATALOG_PATH "/update/xapt/catalog"
#define XAPT_STAGED_TRUST_PATH "/update/xapt/trust"
#define XAPT_OS_VERSION "0.1.0"
#define XAPT_TLS_MODULUS_HEX_BYTES 512U

typedef struct xapt_config {
  char host[XAPT_HOST_BYTES];
  char base[64];
  u64 port;
  u32 tls_required;
  char tls_rsa_modulus[XAPT_TLS_MODULUS_HEX_BYTES + 1U];
} xapt_config_t;

typedef struct xapt_app_record {
  char name[32];
  char version[24];
  char architecture[16];
  char minimum_os[24];
  char manifest_path[XAPT_PATH_BYTES];
  char binary_path[XAPT_PATH_BYTES];
  char description[128];
} xapt_app_record_t;

typedef struct xapt_os_record {
  char version[24];
  u32 generation;
  char architecture[16];
  u64 size;
  unsigned char hash[32];
  char signature[320];
  char image_path[XAPT_PATH_BYTES];
} xapt_os_record_t;

typedef int (*xapt_sink_t)(const unsigned char *data, u32 size, void *context);

static char g_buffer[XAPT_BUFFER_BYTES];
static char g_catalog[131073U];
static u64 g_request_id = 1000U;
static u32 g_http_error;
static u32 g_control_status;
static u64 g_http_received;
static u64 g_http_expected;

static int text_equal(const char *left, const char *right) {
  u64 i = 0U;
  if (left == 0 || right == 0) return 0;
  while (left[i] != '\0' && left[i] == right[i]) ++i;
  return left[i] == right[i];
}

static int text_starts(const char *text, const char *prefix) {
  u64 i = 0U;
  while (prefix[i] != '\0') {
    if (text[i] != prefix[i]) return 0;
    ++i;
  }
  return 1;
}

static void print(const char *text) {
  (void)xaios_console_write(text, xaios_strlen(text));
}

static void print_u64(u64 value) {
  char line[32];
  u64 used = 0U;
  xaios_memzero(line, sizeof(line));
  xaios_append_u64(line, sizeof(line), &used, value);
  print(line);
}

static int copy_text(char *output, u64 capacity, const char *input,
                     u64 length) {
  if (length >= capacity) return -1;
  for (u64 i = 0U; i < length; ++i) output[i] = input[i];
  output[length] = '\0';
  return 0;
}

static int parse_u64(const char *text, u64 length, u64 *value) {
  u64 result = 0U;
  if (length == 0U) return -1;
  for (u64 i = 0U; i < length; ++i) {
    u64 digit;
    if (text[i] < '0' || text[i] > '9') return -1;
    digit = (u64)(text[i] - '0');
    if (result > (~0ULL - digit) / 10U) return -1;
    result = result * 10U + digit;
  }
  *value = result;
  return 0;
}

static int hex_digit(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_hash(const char *text, unsigned char hash[32]) {
  for (u32 i = 0U; i < 32U; ++i) {
    int high = hex_digit(text[i * 2U]);
    int low = hex_digit(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return -1;
    hash[i] = (unsigned char)((high << 4) | low);
  }
  return 0;
}

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

static int path_valid(const char *path) {
  if (path == 0 || path[0] != '/') return 0;
  for (u64 i = 0U; path[i] != '\0'; ++i) {
    if (path[i] == '\\' || path[i] == '\r' || path[i] == '\n' ||
        (path[i] == '.' && path[i + 1U] == '.' &&
         (i == 0U || path[i - 1U] == '/') &&
         (path[i + 2U] == '/' || path[i + 2U] == '\0'))) {
      return 0;
    }
  }
  return 1;
}

static int build_path(char *output, u64 capacity, const char *base,
                      const char *path) {
  u64 used = 0U;
  if (!path_valid(path)) return -1;
  if (base[0] != '\0' && !text_equal(base, "/")) {
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
    return parse_u64(header + start, end - start, content_length);
  }
  return -1;
}

static int http_get(const xapt_config_t *config, const char *catalog_path,
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
  g_http_error = 0U;
  g_http_received = 0U;
  g_http_expected = 0U;
  if (build_path(path, sizeof(path), config->base, catalog_path) != 0) {
    g_http_error = 1U;
    return -1;
  }
  if (resolve_host(config->host, &address) != 0) {
    g_http_error = 2U;
    return -1;
  }
  if (xaios_net_connect(&address, config->port, &socket) != 0) {
    g_http_error = 3U;
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
    g_http_error = 100U + (u32)xapt_tls_last_error();
    (void)xaios_net_close(socket);
    return -1;
  }
  if (send_all(socket, request, request_used, config->tls_required) != 0) {
    g_http_error = 4U;
    (void)xaios_net_close(socket);
    return -1;
  }

  while (xaios_clock_nanos() < deadline) {
    u64 received = 0U;
    int status;
    if (config->tls_required != 0U) {
      status = xapt_tls_read(g_buffer, sizeof(g_buffer));
      received = status > 0 ? (u64)status : 0U;
      if (status < 0) {
        g_http_error = 200U + (u32)xapt_tls_last_error();
        status = -1;
      } else {
        status = 0;
      }
    } else {
      status = xaios_net_recv(socket, g_buffer, sizeof(g_buffer), &received);
    }
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0) break;
    if (received == 0U) continue;
    u64 cursor = 0U;
    if (header_complete == 0U) {
      while (cursor < received && header_complete == 0U) {
        if (header_used + 1U >= sizeof(g_buffer)) {
          g_http_error = 5U;
          (void)xaios_net_close(socket);
          return -1;
        }
        g_catalog[header_used++] = g_buffer[cursor++];
        if (header_used >= 4U && g_catalog[header_used - 4U] == '\r' &&
            g_catalog[header_used - 3U] == '\n' &&
            g_catalog[header_used - 2U] == '\r' &&
            g_catalog[header_used - 1U] == '\n') {
          header_complete = 1U;
        }
      }
      if (header_complete != 0U) {
        if (header_used < 12U || !text_starts(g_catalog, "HTTP/1.1 200") ||
            parse_content_length(g_catalog, header_used, &content_length) != 0) {
          g_http_error = 6U;
          (void)xaios_net_close(socket);
          return -1;
        }
      }
    }
    if (header_complete != 0U && cursor < received) {
      u32 body = (u32)(received - cursor);
      if (received_total + body > content_length ||
          sink((const unsigned char *)g_buffer + cursor, body, sink_context) !=
              0) {
        g_http_error = 7U;
        (void)xaios_net_close(socket);
        return -1;
      }
      received_total += body;
    }
    if (header_complete != 0U && received_total == content_length) break;
  }
  if (config->tls_required != 0U) (void)xapt_tls_close();
  (void)xaios_net_close(socket);
  g_http_received = received_total;
  g_http_expected = content_length;
  if (header_complete == 0U || received_total != content_length) {
    g_http_error = 8U;
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

static int download_file(const xapt_config_t *config, const char *remote_path,
                         const char *local_path, u64 *size) {
  file_sink_context_t context;
  context.fd = xaios_fs_open(local_path, XAIOS_MFS_OPEN_WRITE |
                                             XAIOS_MFS_OPEN_CREATE |
                                             XAIOS_MFS_OPEN_TRUNCATE);
  if (context.fd < 0) {
    g_http_error = 9U;
    return -1;
  }
  int status = http_get(config, remote_path, file_sink, &context, size);
  if (xaios_fs_fsync(context.fd) != 0) {
    g_http_error = 10U;
    status = -1;
  }
  if (xaios_fs_close(context.fd) != 0) {
    g_http_error = 11U;
    status = -1;
  }
  if (status != 0) (void)xaios_fs_delete(local_path);
  return status;
}

static int load_config(xapt_config_t *config) {
  int bytes;
  xaios_memzero(config, sizeof(*config));
  config->port = 80U;
  config->tls_required = 1U;
  bytes = xaios_read_file(XAPT_CONFIG_PATH, g_buffer, sizeof(g_buffer));
  if (bytes <= 0)
    bytes = xaios_read_file("/etc/xapt.conf", g_buffer, sizeof(g_buffer));
  if (bytes <= 0) return -1;
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    while (cursor < (u64)bytes && g_buffer[cursor] != '\n') ++cursor;
    u64 length = cursor - start;
    if (text_starts(g_buffer + start, "host=")) {
      if (copy_text(config->host, sizeof(config->host), g_buffer + start + 5U,
                    length - 5U) != 0)
        return -1;
    } else if (text_starts(g_buffer + start, "base=")) {
      if (copy_text(config->base, sizeof(config->base), g_buffer + start + 5U,
                    length - 5U) != 0)
        return -1;
    } else if (text_starts(g_buffer + start, "port=")) {
      if (parse_u64(g_buffer + start + 5U, length - 5U, &config->port) != 0)
        return -1;
    } else if (text_starts(g_buffer + start, "tls=")) {
      if (length == 12U && text_starts(g_buffer + start + 4U, "required"))
        config->tls_required = 1U;
      else if (length == 7U && text_starts(g_buffer + start + 4U, "off"))
        config->tls_required = 0U;
      else
        return -1;
    } else if (text_starts(g_buffer + start, "tls_rsa_modulus=")) {
      if (copy_text(config->tls_rsa_modulus,
                    sizeof(config->tls_rsa_modulus), g_buffer + start + 16U,
                    length - 16U) != 0)
        return -1;
    }
    ++cursor;
  }
  return config->host[0] != '\0' && config->port > 0U &&
                 config->port <= 65535U &&
                 (config->tls_required == 0U ||
                  xaios_strlen(config->tls_rsa_modulus) ==
                      XAPT_TLS_MODULUS_HEX_BYTES) &&
                 (config->base[0] == '\0' || path_valid(config->base))
             ? 0
             : -1;
}

static int control_call(u16 operation, u32 payload_type, const void *payload,
                        u64 payload_size) {
  unsigned char request[512];
  unsigned char response[128];
  xaios_control_request_header_user_t header;
  xaios_control_response_header_user_t response_header;
  u64 response_size = 0U;
  g_control_status = 0xffffffffU;
  if (sizeof(header) + payload_size > sizeof(request)) return -1;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = operation;
  header.payload_type = payload_type;
  header.request_id = ++g_request_id;
  header.principal_role = XAIOS_CONTROL_ROLE_ADMIN;
  header.timeout_ms = 60000U;
  header.payload_length = payload_size;
  xaios_memcpy(request, &header, sizeof(header));
  if (payload_size != 0U)
    xaios_memcpy(request + sizeof(header), payload, payload_size);
  if (xaios_control_query(request, sizeof(header) + payload_size, response,
                          sizeof(response), &response_size) != 0 ||
      response_size < sizeof(response_header)) {
    return -1;
  }
  xaios_memcpy(&response_header, response, sizeof(response_header));
  g_control_status = response_header.status;
  return response_header.magic == XAIOS_CONTROL_MAGIC &&
                 response_header.request_id == header.request_id &&
                 response_header.status == XAIOS_CONTROL_STATUS_OK
             ? 0
             : -1;
}

static int app_control(u16 operation, const char *name) {
  xaios_control_app_request_payload_user_t request;
  u64 length = xaios_strlen(name);
  if (length == 0U || length >= sizeof(request.name)) return -1;
  xaios_memzero(&request, sizeof(request));
  xaios_memcpy(request.name, name, length);
  return control_call(operation, XAIOS_CONTROL_PAYLOAD_APP_REQUEST, &request,
                      sizeof(request));
}

static const char *architecture(void) {
#if defined(__aarch64__)
  return "aarch64";
#elif defined(__x86_64__)
  return "x86_64";
#else
  return "unknown";
#endif
}

static int read_file_bounded(const char *path, char *buffer, u64 capacity) {
  u64 used = 0U;
  int fd;
  if (capacity < 2U) return -1;
  fd = xaios_fs_open(path, XAIOS_MFS_OPEN_READ);
  if (fd < 0) return -1;
  while (used + 1U < capacity) {
    u64 available = capacity - used - 1U;
    u64 amount = available < XAPT_BUFFER_BYTES ? available : XAPT_BUFFER_BYTES;
    int bytes = xaios_fs_read(fd, buffer + used, amount);
    if (bytes < 0) {
      (void)xaios_fs_close(fd);
      return -1;
    }
    if (bytes == 0) break;
    used += (u64)bytes;
  }
  if (xaios_fs_close(fd) != 0 || used + 1U == capacity) return -1;
  buffer[used] = '\0';
  return (int)used;
}

static int read_catalog(void) {
  int bytes = read_file_bounded(XAPT_CATALOG_PATH, g_catalog,
                                sizeof(g_catalog));
  return bytes > 0 && text_starts(g_catalog, "XAIOS-CATALOG-V1\n") ? bytes : -1;
}

static int split_fields(const char *line, u64 length, char *fields[],
                        u64 capacities[], u32 count) {
  u64 start = 0U;
  for (u32 field = 0U; field < count; ++field) {
    u64 end = start;
    while (end < length && line[end] != '|') ++end;
    if (copy_text(fields[field], capacities[field], line + start, end - start) !=
        0)
      return -1;
    if (field + 1U < count) {
      if (end == length) return -1;
      start = end + 1U;
    } else if (end != length) {
      return -1;
    }
  }
  return 0;
}

static int parse_app_line(const char *line, u64 length,
                          xapt_app_record_t *record) {
  char *fields[] = {record->name, record->version, record->architecture,
                    record->minimum_os, record->manifest_path,
                    record->binary_path, record->description};
  u64 capacities[] = {sizeof(record->name), sizeof(record->version),
                      sizeof(record->architecture), sizeof(record->minimum_os),
                      sizeof(record->manifest_path), sizeof(record->binary_path),
                      sizeof(record->description)};
  xaios_memzero(record, sizeof(*record));
  return length > 4U && line[0] == 'a' && line[1] == 'p' && line[2] == 'p' &&
                 line[3] == '=' &&
                 split_fields(line + 4U, length - 4U, fields, capacities, 7U) ==
                     0 &&
                 text_equal(record->architecture, architecture()) &&
                 path_valid(record->manifest_path) &&
                 path_valid(record->binary_path)
             ? 0
             : -1;
}

static int parse_os_line(const char *line, u64 length,
                         xapt_os_record_t *record) {
  char generation[16];
  char size[24];
  char hash[65];
  char *fields[] = {record->version, generation, record->architecture, size,
                    hash, record->signature, record->image_path};
  u64 capacities[] = {sizeof(record->version), sizeof(generation),
                      sizeof(record->architecture), sizeof(size), sizeof(hash),
                      sizeof(record->signature), sizeof(record->image_path)};
  u64 parsed_generation = 0U;
  xaios_memzero(record, sizeof(*record));
  if (length <= 3U || line[0] != 'o' || line[1] != 's' || line[2] != '=' ||
      split_fields(line + 3U, length - 3U, fields, capacities, 7U) != 0 ||
      parse_u64(generation, xaios_strlen(generation), &parsed_generation) != 0 ||
      parsed_generation == 0U || parsed_generation > 0xffffffffULL ||
      parse_u64(size, xaios_strlen(size), &record->size) != 0 ||
      xaios_strlen(hash) != 64U || parse_hash(hash, record->hash) != 0 ||
      !text_equal(record->architecture, architecture()) ||
      !path_valid(record->image_path)) {
    return -1;
  }
  record->generation = (u32)parsed_generation;
  return 0;
}

static int find_app(const char *name, xapt_app_record_t *record) {
  int bytes = read_catalog();
  if (bytes < 0) return -1;
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    while (cursor < (u64)bytes && g_catalog[cursor] != '\n') ++cursor;
    if (parse_app_line(g_catalog + start, cursor - start, record) == 0 &&
        text_equal(record->name, name))
      return 0;
    ++cursor;
  }
  return -1;
}

static int find_os(xapt_os_record_t *record) {
  int bytes = read_catalog();
  if (bytes < 0) return -1;
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    while (cursor < (u64)bytes && g_catalog[cursor] != '\n') ++cursor;
    if (parse_os_line(g_catalog + start, cursor - start, record) == 0) return 0;
    ++cursor;
  }
  return -1;
}

static int installed_version(const char *name, char version[24]) {
  char path[96];
  u64 used = 0U;
  xaios_memzero(path, sizeof(path));
  xaios_append_cstr(path, sizeof(path), &used, "/apps/");
  xaios_append_cstr(path, sizeof(path), &used, name);
  xaios_append_cstr(path, sizeof(path), &used, "/current.manifest");
  int bytes = xaios_read_file(path, g_buffer, sizeof(g_buffer));
  if (bytes <= 0) return -1;
  for (u64 i = 0U; i + 8U < (u64)bytes; ++i) {
    if ((i == 0U || g_buffer[i - 1U] == '\n') &&
        text_starts(g_buffer + i, "version=")) {
      u64 end = i + 8U;
      while (end < (u64)bytes && g_buffer[end] != '\n') ++end;
      return copy_text(version, 24U, g_buffer + i + 8U, end - i - 8U);
    }
  }
  return -1;
}

static int version_compare(const char *left, const char *right) {
  u64 li = 0U;
  u64 ri = 0U;
  for (u32 part = 0U; part < 3U; ++part) {
    u64 lv = 0U;
    u64 rv = 0U;
    while (left[li] >= '0' && left[li] <= '9')
      lv = lv * 10U + (u64)(left[li++] - '0');
    while (right[ri] >= '0' && right[ri] <= '9')
      rv = rv * 10U + (u64)(right[ri++] - '0');
    if (lv != rv) return lv > rv ? 1 : -1;
    if (part < 2U) {
      if (left[li++] != '.' || right[ri++] != '.') return 0;
    }
  }
  return 0;
}

static int catalog_update(const xapt_config_t *config) {
  char remote[64];
  u64 used = 0U;
  u64 bytes = 0U;
  xaios_memzero(remote, sizeof(remote));
  xaios_append_cstr(remote, sizeof(remote), &used, "/catalog-");
  xaios_append_cstr(remote, sizeof(remote), &used, architecture());
  xaios_append_cstr(remote, sizeof(remote), &used, ".txt");
  print("xapt: checking trust-root transitions\n");
  if (download_file(config, "/trust.txt", XAPT_STAGED_TRUST_PATH, &bytes) !=
      0) {
    /* A repository without a transition remains valid under the active root. */
    (void)xaios_fs_delete(XAPT_STAGED_TRUST_PATH);
  }
  bytes = 0U;
  print("xapt: fetching signed catalog\n");
  if (download_file(config, remote, XAPT_STAGED_CATALOG_PATH, &bytes) != 0 ||
      control_call(XAIOS_CONTROL_OP_CATALOG_ACTIVATE,
                   XAIOS_CONTROL_PAYLOAD_NONE, 0, 0U) != 0) {
    print("xapt: catalog update failed (http_stage=");
    print_u64(g_http_error);
    print(", received=");
    print_u64(g_http_received);
    print("/");
    print_u64(g_http_expected);
    print(", control_status=");
    print_u64(g_control_status);
    print(")\n");
    return -1;
  }
  print("xapt: catalog verified and activated (bytes=");
  print_u64(bytes);
  print(")\n");
  return 0;
}

static int install_app(const xapt_config_t *config, const char *name,
                       int require_newer) {
  xapt_app_record_t app;
  char current[24];
  char manifest_target[96];
  char binary_target[96];
  u64 used = 0U;
  u64 ignored = 0U;
  if (find_app(name, &app) != 0) {
    print("xapt: application not found in active catalog\n");
    return -1;
  }
  if (installed_version(name, current) == 0) {
    int comparison = version_compare(app.version, current);
    if (comparison <= 0) {
      print(require_newer ? "xapt: already up to date\n"
                          : "xapt: version already installed\n");
      return require_newer ? 0 : -1;
    }
  }
  xaios_memzero(manifest_target, sizeof(manifest_target));
  xaios_memzero(binary_target, sizeof(binary_target));
  xaios_append_cstr(manifest_target, sizeof(manifest_target), &used,
                    "/update/xapt/");
  xaios_append_cstr(manifest_target, sizeof(manifest_target), &used, name);
  xaios_append_cstr(manifest_target, sizeof(manifest_target), &used,
                    ".manifest");
  used = 0U;
  xaios_append_cstr(binary_target, sizeof(binary_target), &used,
                    "/update/xapt/");
  xaios_append_cstr(binary_target, sizeof(binary_target), &used, name);
  xaios_append_cstr(binary_target, sizeof(binary_target), &used, ".elf");
  print("xapt: downloading ");
  print(name);
  print(" ");
  print(app.version);
  print("\n");
  if (download_file(config, app.manifest_path, manifest_target, &ignored) != 0 ||
      download_file(config, app.binary_path, binary_target, &ignored) != 0 ||
      app_control(XAIOS_CONTROL_OP_APP_ACTIVATE, name) != 0) {
    print("xapt: package rejected or download failed (http_stage=");
    print_u64(g_http_error);
    print(", received=");
    print_u64(g_http_received);
    print("/");
    print_u64(g_http_expected);
    print(", control_status=");
    print_u64(g_control_status);
    print(")\n");
    return -1;
  }
  print("xapt: activated ");
  print(name);
  print(" ");
  print(app.version);
  print(" without reboot\n");
  return 0;
}

static int list_apps(const char *filter, int upgradable_only) {
  int bytes = read_catalog();
  u32 count = 0U;
  if (bytes < 0) {
    print("xapt: no active catalog; run 'xapt update'\n");
    return -1;
  }
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    xapt_app_record_t app;
    char current[24];
    while (cursor < (u64)bytes && g_catalog[cursor] != '\n') ++cursor;
    if (parse_app_line(g_catalog + start, cursor - start, &app) == 0 &&
        (filter == 0 || text_equal(filter, app.name))) {
      int installed = installed_version(app.name, current) == 0;
      int newer = installed && version_compare(app.version, current) > 0;
      if (!upgradable_only || newer) {
        print(app.name);
        print(" ");
        print(app.version);
        print(installed ? (newer ? " [upgradable] " : " [installed] ")
                        : " [available] ");
        print(app.description);
        print("\n");
        ++count;
      }
    }
    ++cursor;
  }
  if (filter == 0) {
    xapt_os_record_t os;
    if (find_os(&os) == 0 && version_compare(os.version, XAPT_OS_VERSION) > 0) {
      print("xaios ");
      print(os.version);
      print(" [OS upgrade; reboot required]\n");
      ++count;
    }
  }
  if (count == 0U) print("xapt: no matching applications\n");
  return filter != 0 && count == 0U ? -1 : 0;
}

typedef struct system_sink_context {
  int failed;
} system_sink_context_t;

static int system_sink(const unsigned char *data, u32 size, void *context) {
  system_sink_context_t *state = (system_sink_context_t *)context;
  u32 offset = 0U;
  while (offset < size) {
    xaios_control_system_update_chunk_payload_user_t chunk;
    u32 amount = size - offset;
    if (amount > sizeof(chunk.data)) amount = sizeof(chunk.data);
    xaios_memzero(&chunk, sizeof(chunk));
    chunk.size = amount;
    xaios_memcpy(chunk.data, data + offset, amount);
    if (control_call(XAIOS_CONTROL_OP_SYSTEM_UPDATE_CHUNK,
                     XAIOS_CONTROL_PAYLOAD_SYSTEM_UPDATE_CHUNK, &chunk,
                     sizeof(chunk)) != 0) {
      state->failed = 1;
      return -1;
    }
    offset += amount;
  }
  return 0;
}

static int os_upgrade(const xapt_config_t *config) {
  xapt_os_record_t os;
  xaios_control_system_update_begin_payload_user_t begin;
  system_sink_context_t sink;
  u64 received = 0U;
  if (find_os(&os) != 0) {
    print("xapt: no compatible OS image in active catalog\n");
    return -1;
  }
  if (version_compare(os.version, XAPT_OS_VERSION) <= 0) {
    print("xapt: OS is already up to date\n");
    return 0;
  }
  xaios_memzero(&begin, sizeof(begin));
  begin.payload_size = os.size;
  begin.generation = os.generation;
  xaios_memcpy(begin.payload_hash, os.hash, sizeof(begin.payload_hash));
  xaios_memcpy(begin.signature, os.signature, xaios_strlen(os.signature));
  if (control_call(XAIOS_CONTROL_OP_SYSTEM_UPDATE_BEGIN,
                   XAIOS_CONTROL_PAYLOAD_SYSTEM_UPDATE_BEGIN, &begin,
                   sizeof(begin)) != 0) {
    print("xapt: OS update authorization failed\n");
    return -1;
  }
  sink.failed = 0;
  print("xapt: streaming OS image into inactive verified boot slot\n");
  if (http_get(config, os.image_path, system_sink, &sink, &received) != 0 ||
      sink.failed != 0 || received != os.size ||
      control_call(XAIOS_CONTROL_OP_SYSTEM_UPDATE_COMMIT,
                   XAIOS_CONTROL_PAYLOAD_NONE, 0, 0U) != 0) {
    (void)control_call(XAIOS_CONTROL_OP_SYSTEM_UPDATE_ABORT,
                       XAIOS_CONTROL_PAYLOAD_NONE, 0, 0U);
    print("xapt: OS update failed; active slot unchanged\n");
    print("xapt: diagnostics http_stage=");
    print_u64(g_http_error);
    print(" received=");
    print_u64(g_http_received);
    print("/");
    print_u64(g_http_expected);
    print(" control_status=");
    print_u64(g_control_status);
    print("\n");
    return -1;
  }
  print("xapt: OS update staged and verified; reboot to try the pending slot\n");
  return 0;
}

static void usage(void) {
  print("usage: xapt update | list [--upgradable] | search NAME | show NAME | "
        "install NAME | upgrade NAME | remove NAME | rollback NAME | "
        "os-upgrade\n");
}

int main(int argc, char **argv) {
  xapt_config_t config;
  if (argc < 2 || argv == 0) {
    usage();
    return 2;
  }
  if (text_equal(argv[1], "list")) {
    return list_apps(0, argc == 3 && text_equal(argv[2], "--upgradable"));
  }
  if ((text_equal(argv[1], "search") || text_equal(argv[1], "show")) &&
      argc == 3) {
    return list_apps(argv[2], 0);
  }
  if (text_equal(argv[1], "remove") && argc == 3) {
    if (app_control(XAIOS_CONTROL_OP_APP_REMOVE, argv[2]) != 0) {
      print("xapt: remove failed\n");
      return 1;
    }
    print("xapt: removed ");
    print(argv[2]);
    print("\n");
    return 0;
  }
  if (text_equal(argv[1], "rollback") && argc == 3) {
    if (app_control(XAIOS_CONTROL_OP_APP_ROLLBACK, argv[2]) != 0) {
      print("xapt: rollback failed\n");
      return 1;
    }
    print("xapt: rollback activated\n");
    return 0;
  }
  if (load_config(&config) != 0) {
    print("xapt: invalid or missing /state/xapt/config\n");
    return 1;
  }
  if (text_equal(argv[1], "update") && argc == 2)
    return catalog_update(&config) == 0 ? 0 : 1;
  if (text_equal(argv[1], "install") && argc == 3)
    return install_app(&config, argv[2], 0) == 0 ? 0 : 1;
  if (text_equal(argv[1], "upgrade") && argc == 3)
    return install_app(&config, argv[2], 1) == 0 ? 0 : 1;
  if (text_equal(argv[1], "os-upgrade") && argc == 2)
    return os_upgrade(&config) == 0 ? 0 : 1;
  usage();
  return 2;
}
