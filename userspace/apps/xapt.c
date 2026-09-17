#include <xaios_user.h>

#include "xapt_internal.h"

/* The xapt command surface: config loading, the control-plane calls that
   authorize an install or a system update, the four commands, and `main`.
   The repository index is parsed in xapt_catalog.c and the transfer lives in
   xapt_http.c; the buffers below are the only state those two share with this
   file. */

/* A build number from a catalog record. Returns -1 for anything that is not a
   whole number, so a malformed record reads as older than this system rather
   than newer -- refusing an upgrade is recoverable, installing one described
   by a field nobody could parse is not. */
static long parse_build(const char *text) {
  if (text == 0 || *text == '\0') return -1;
  long value = 0;
  for (const char *cursor = text; *cursor != '\0'; ++cursor) {
    if (*cursor < '0' || *cursor > '9') return -1;
    if (value > (2147483647L - (*cursor - '0')) / 10) return -1;
    value = value * 10 + (*cursor - '0');
  }
  return value;
}

char xapt_buffer[XAPT_BUFFER_BYTES];
char xapt_catalog[131073U];
u64 xapt_request_id = 1000U;
u32 xapt_http_error;
u32 xapt_control_status;
u64 xapt_http_received;
u64 xapt_http_expected;

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

static int load_config(xapt_config_t *config) {
  int bytes;
  xaios_memzero(config, sizeof(*config));
  config->port = 80U;
  config->tls_required = 1U;
  bytes = xaios_read_file(XAPT_CONFIG_PATH, xapt_buffer, sizeof(xapt_buffer));
  if (bytes <= 0)
    bytes = xaios_read_file("/etc/xapt.conf", xapt_buffer, sizeof(xapt_buffer));
  if (bytes <= 0) return -1;
  /* The key matches below compare fixed prefixes against the raw buffer, so
     the content must end inside it: a full buffer is either truncated or
     leaves a final unterminated line for a prefix compare to walk past. */
  if ((u64)bytes >= sizeof(xapt_buffer)) return -1;
  xapt_buffer[bytes] = '\0';
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    while (cursor < (u64)bytes && xapt_buffer[cursor] != '\n') ++cursor;
    u64 length = cursor - start;
    if (xapt_text_starts(xapt_buffer + start, "host=")) {
      if (xapt_copy_text(config->host, sizeof(config->host),
                         xapt_buffer + start + 5U, length - 5U) != 0)
        return -1;
    } else if (xapt_text_starts(xapt_buffer + start, "address=")) {
      if (xapt_copy_text(config->address, sizeof(config->address),
                         xapt_buffer + start + 8U, length - 8U) != 0)
        return -1;
    } else if (xapt_text_starts(xapt_buffer + start, "base=")) {
      if (xapt_copy_text(config->base, sizeof(config->base),
                         xapt_buffer + start + 5U, length - 5U) != 0)
        return -1;
    } else if (xapt_text_starts(xapt_buffer + start, "port=")) {
      if (xapt_parse_u64(xapt_buffer + start + 5U, length - 5U, &config->port) !=
          0)
        return -1;
    } else if (xapt_text_starts(xapt_buffer + start, "tls=")) {
      if (length == 12U && xapt_text_starts(xapt_buffer + start + 4U, "required"))
        config->tls_required = 1U;
      else if (length == 7U && xapt_text_starts(xapt_buffer + start + 4U, "off"))
        config->tls_required = 0U;
      else
        return -1;
    } else if (xapt_text_starts(xapt_buffer + start, "tls_rsa_modulus=")) {
      if (xapt_copy_text(config->tls_rsa_modulus,
                         sizeof(config->tls_rsa_modulus),
                         xapt_buffer + start + 16U, length - 16U) != 0)
        return -1;
    }
    ++cursor;
  }
  return config->host[0] != '\0' && config->port > 0U &&
                 config->port <= 65535U &&
                 (xaios_strlen(config->tls_rsa_modulus) == 0U ||
                  xaios_strlen(config->tls_rsa_modulus) ==
                      XAPT_TLS_MODULUS_HEX_BYTES) &&
                 (config->base[0] == '\0' || xapt_path_valid(config->base))
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
  xapt_control_status = 0xffffffffU;
  if (sizeof(header) + payload_size > sizeof(request)) return -1;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = operation;
  header.payload_type = payload_type;
  header.request_id = ++xapt_request_id;
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
  xapt_control_status = response_header.status;
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

static int catalog_update(const xapt_config_t *config) {
  char remote[64];
  u64 used = 0U;
  u64 bytes = 0U;
  xaios_memzero(remote, sizeof(remote));
  xaios_append_cstr(remote, sizeof(remote), &used, "/catalog-");
  xaios_append_cstr(remote, sizeof(remote), &used, xapt_architecture());
  xaios_append_cstr(remote, sizeof(remote), &used, ".txt");
  print("xapt: checking trust-root transitions\n");
  if (xapt_http_download(config, "/trust.txt", XAPT_STAGED_TRUST_PATH,
                         &bytes) != 0) {
    /* A repository without a transition remains valid under the active root. */
    (void)xaios_fs_delete(XAPT_STAGED_TRUST_PATH);
  }
  bytes = 0U;
  print("xapt: fetching signed catalog\n");
  if (xapt_http_download(config, remote, XAPT_STAGED_CATALOG_PATH, &bytes) !=
          0 ||
      control_call(XAIOS_CONTROL_OP_CATALOG_ACTIVATE,
                   XAIOS_CONTROL_PAYLOAD_NONE, 0, 0U) != 0) {
    print("xapt: catalog update failed (http_stage=");
    print_u64(xapt_http_error);
    print(", received=");
    print_u64(xapt_http_received);
    print("/");
    print_u64(xapt_http_expected);
    print(", control_status=");
    print_u64(xapt_control_status);
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
  if (xapt_find_app(name, &app) != 0) {
    print("xapt: application not found in active catalog\n");
    return -1;
  }
  if (xapt_installed_version(name, current) == 0) {
    int comparison = xapt_version_compare(app.version, current);
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
  if (xapt_http_download(config, app.manifest_path, manifest_target,
                         &ignored) != 0 ||
      xapt_http_download(config, app.binary_path, binary_target, &ignored) !=
          0 ||
      app_control(XAIOS_CONTROL_OP_APP_ACTIVATE, name) != 0) {
    print("xapt: package rejected or download failed (http_stage=");
    print_u64(xapt_http_error);
    print(", received=");
    print_u64(xapt_http_received);
    print("/");
    print_u64(xapt_http_expected);
    print(", control_status=");
    print_u64(xapt_control_status);
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
  int bytes = xapt_read_catalog();
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
    while (cursor < (u64)bytes && xapt_catalog[cursor] != '\n') ++cursor;
    if (xapt_parse_app_line(xapt_catalog + start, cursor - start, &app) == 0 &&
        (filter == 0 || xapt_text_equal(filter, app.name))) {
      int installed = xapt_installed_version(app.name, current) == 0;
      int newer = installed && xapt_version_compare(app.version, current) > 0;
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
    if (xapt_find_os(&os) == 0 &&
        parse_build(os.version) > (long)XAPT_OS_BUILD) {
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
  if (xapt_find_os(&os) != 0) {
    print("xapt: no compatible OS image in active catalog\n");
    return -1;
  }
  if (parse_build(os.version) <= (long)XAPT_OS_BUILD) {
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
  if (xapt_http_get(config, os.image_path, system_sink, &sink, &received) != 0 ||
      sink.failed != 0 || received != os.size ||
      control_call(XAIOS_CONTROL_OP_SYSTEM_UPDATE_COMMIT,
                   XAIOS_CONTROL_PAYLOAD_NONE, 0, 0U) != 0) {
    (void)control_call(XAIOS_CONTROL_OP_SYSTEM_UPDATE_ABORT,
                       XAIOS_CONTROL_PAYLOAD_NONE, 0, 0U);
    print("xapt: OS update failed; active slot unchanged\n");
    print("xapt: diagnostics http_stage=");
    print_u64(xapt_http_error);
    print(" received=");
    print_u64(xapt_http_received);
    print("/");
    print_u64(xapt_http_expected);
    print(" control_status=");
    print_u64(xapt_control_status);
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
  if (xapt_text_equal(argv[1], "list")) {
    return list_apps(0, argc == 3 && xapt_text_equal(argv[2], "--upgradable"));
  }
  if ((xapt_text_equal(argv[1], "search") || xapt_text_equal(argv[1], "show")) &&
      argc == 3) {
    return list_apps(argv[2], 0);
  }
  if (xapt_text_equal(argv[1], "remove") && argc == 3) {
    if (app_control(XAIOS_CONTROL_OP_APP_REMOVE, argv[2]) != 0) {
      print("xapt: remove failed\n");
      return 1;
    }
    print("xapt: removed ");
    print(argv[2]);
    print("\n");
    return 0;
  }
  if (xapt_text_equal(argv[1], "rollback") && argc == 3) {
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
  if (xapt_text_equal(argv[1], "update") && argc == 2)
    return catalog_update(&config) == 0 ? 0 : 1;
  if (xapt_text_equal(argv[1], "install") && argc == 3)
    return install_app(&config, argv[2], 0) == 0 ? 0 : 1;
  if (xapt_text_equal(argv[1], "upgrade") && argc == 3)
    return install_app(&config, argv[2], 1) == 0 ? 0 : 1;
  if (xapt_text_equal(argv[1], "os-upgrade") && argc == 2)
    return os_upgrade(&config) == 0 ? 0 : 1;
  usage();
  return 2;
}
