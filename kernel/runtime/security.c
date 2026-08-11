#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/syscall.h>

/*
 * Picard — “I will not sacrifice the Enterprise. Not again! The line must be
 * drawn here! This far, no further!”
 */

#define XAIOS_UPDATE_SIGNATURE_PREFIX "xaios-update:v2:"
#define XAIOS_UPDATE_SIGNATURE_GEN_FIELD "gen="
#define XAIOS_UPDATE_SIGNATURE_SHA_FIELD "sha256="
#define XAIOS_UPDATE_SIGNATURE_KEY_HEX                                      \
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
#define XAIOS_UPDATE_SIGNATURE_KEY_FIELD "key=" XAIOS_UPDATE_SIGNATURE_KEY_HEX
#define XAIOS_UPDATE_SIGNATURE_SIG_FIELD "sig="
#define XAIOS_UPDATE_SIGNATURE_BYTES 64U

static const uint8_t k_update_public_key[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

extern int xaios_ed25519_verify(const uint8_t signature[64],
                                const uint8_t *message,
                                uint32_t message_len,
                                const uint8_t public_key[32]);

static uint64_t g_denied_operations;
static uint64_t g_capability_denials;
static uint64_t g_fs_denials;
static uint64_t g_workspace_denials;
static uint64_t g_sandbox_denials;
static uint64_t g_rollback_denials;
static uint64_t g_update_policy_rejects;
static uint64_t g_signature_accepts;
static uint64_t g_signature_rejects;
static uint64_t g_credential_rejects;
static uint64_t g_admin_denials;
static uint64_t g_update_authorizations;
static uint64_t g_update_replay_rejects;
static uint64_t g_key_accepts;
static uint64_t g_key_rejects;
static uint64_t g_sandbox_escape_rejects;
static uint64_t g_last_update_generation;

static const char k_pat_credential_pattern[] = {
    'g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_', '\0'};
static const char k_short_credential_pattern[] = {'g', 'h', 'p', '_', '\0'};
static const char k_pass_field_pattern[] = {
    'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '=', '\0'};
static const char k_token_field_pattern[] = {
    't', 'o', 'k', 'e', 'n', '=', '\0'};
static const char k_secret_field_pattern[] = {
    's', 'e', 'c', 'r', 'e', 't', '=', '\0'};
static const char k_private_begin_pattern[] = {
    'B', 'E', 'G', 'I', 'N', ' ', '\0'};
static const char k_private_key_pattern[] = {
    'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y', '\0'};

static int starts_with(const char *text, const char *prefix) {
  if (text == 0 || prefix == 0) {
    return 0;
  }
  while (*prefix != '\0') {
    if (*text != *prefix) {
      return 0;
    }
    ++text;
    ++prefix;
  }
  return 1;
}

static int contains(const char *text, const char *needle) {
  if (text == 0 || needle == 0 || *needle == '\0') {
    return 0;
  }

  for (const char *cursor = text; *cursor != '\0'; ++cursor) {
    const char *hay = cursor;
    const char *pat = needle;
    while (*hay != '\0' && *pat != '\0' && *hay == *pat) {
      ++hay;
      ++pat;
    }
    if (*pat == '\0') {
      return 1;
    }
  }

  return 0;
}

static uint64_t cstr_length(const char *text) {
  uint64_t len = 0;
  if (text == 0) {
    return 0;
  }
  while (text[len] != '\0') {
    ++len;
  }
  return len;
}

static int path_in_tree(const char *path, const char *root) {
  uint64_t root_len = cstr_length(root);
  if (!starts_with(path, root)) {
    return 0;
  }
  return path[root_len] == '\0' || path[root_len] == '/';
}

static int contains_buffer(const char *text, uint64_t length,
                           const char *needle) {
  uint64_t needle_len = cstr_length(needle);
  if (text == 0 || needle == 0 || needle_len == 0 || length < needle_len) {
    return 0;
  }

  for (uint64_t cursor = 0; cursor <= length - needle_len; ++cursor) {
    uint64_t i = 0;
    while (i < needle_len && text[cursor + i] == needle[i]) {
      ++i;
    }
    if (i == needle_len) {
      return 1;
    }
  }

  return 0;
}

static xaios_status_t reject_security_operation(const char *reason) {
  ++g_denied_operations;
  klog("security: denied operation reason=%s\n", reason);
  return XAIOS_ERR_INVALID;
}

static int hex_value(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static int parse_hex_bytes(const char *text, uint8_t *output,
                           uint32_t byte_count) {
  if (text == 0 || output == 0) return 0;
  for (uint32_t index = 0U; index < byte_count; ++index) {
    int high = hex_value(text[index * 2U]);
    int low = hex_value(text[index * 2U + 1U]);
    if (high < 0 || low < 0) return 0;
    output[index] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

static int is_digit(char ch) {
  return ch >= '0' && ch <= '9';
}

static xaios_status_t parse_generation(const char **cursor,
                                      uint64_t *generation) {
  uint64_t parsed = 0;
  const char *value = 0;
  if (cursor == 0 || cursor[0] == 0 || generation == 0 ||
      !starts_with(cursor[0], XAIOS_UPDATE_SIGNATURE_GEN_FIELD)) {
    return XAIOS_ERR_INVALID;
  }
  value = cursor[0] + sizeof(XAIOS_UPDATE_SIGNATURE_GEN_FIELD) - 1U;
  if (!is_digit(*value)) {
    return XAIOS_ERR_INVALID;
  }
  while (*value != '\0' && *value != ':') {
    if (!is_digit(*value) ||
        parsed > (UINT64_MAX - (uint64_t)(*value - '0')) / 10U) {
      return XAIOS_ERR_INVALID;
    }
    parsed = (parsed * 10U) + (uint64_t)(*value - '0');
    ++value;
  }
  if (*value != ':' || parsed == 0) {
    return XAIOS_ERR_INVALID;
  }
  *generation = parsed;
  *cursor = value + 1U;
  return XAIOS_OK;
}

static xaios_status_t reject_update_signature(const char *reason) {
  ++g_signature_rejects;
  ++g_update_policy_rejects;
  return reject_security_operation(reason);
}

static xaios_status_t reject_update_key(const char *reason) {
  ++g_key_rejects;
  return reject_update_signature(reason);
}

static xaios_status_t reject_update_replay(void) {
  ++g_update_replay_rejects;
  return reject_update_signature("update-replay-denied");
}

void security_policy_init(void) {
  g_denied_operations = 0;
  g_capability_denials = 0;
  g_fs_denials = 0;
  g_workspace_denials = 0;
  g_sandbox_denials = 0;
  g_rollback_denials = 0;
  g_update_policy_rejects = 0;
  g_signature_accepts = 0;
  g_signature_rejects = 0;
  g_credential_rejects = 0;
  g_admin_denials = 0;
  g_update_authorizations = 0;
  g_update_replay_rejects = 0;
  g_key_accepts = 0;
  g_key_rejects = 0;
  g_sandbox_escape_rejects = 0;
  g_last_update_generation = 0;
  klog("security: policy initialized mode=qemu-dev signed_updates=dev-public-key admin=required replay=monotonic\n");
}

void security_record_denied_operation(void) {
  ++g_denied_operations;
}

xaios_status_t security_authorize_capability(const char *operation,
                                            uint64_t granted,
                                            uint64_t required) {
  (void)operation;
  if ((granted & required) == required) {
    return XAIOS_OK;
  }
  ++g_capability_denials;
  return reject_security_operation("missing-capability");
}

xaios_status_t security_authorize_fs_read(const char *path) {
  if (security_reject_credential_material(path) != XAIOS_OK) {
    ++g_fs_denials;
    return XAIOS_ERR_INVALID;
  }
  if (starts_with(path, "/etc/") || path_in_tree(path, "/tmp") ||
      path_in_tree(path, "/home") || path_in_tree(path, "/apps") ||
      path_in_tree(path, "/state") || path_in_tree(path, "/logs") ||
      path_in_tree(path, "/models")) {
    return XAIOS_OK;
  }
  ++g_fs_denials;
  return reject_security_operation("fs-read-denied");
}

xaios_status_t security_authorize_fs_write(const char *path) {
  if (security_reject_credential_material(path) != XAIOS_OK) {
    ++g_fs_denials;
    return XAIOS_ERR_INVALID;
  }
  if (path_in_tree(path, "/tmp") || path_in_tree(path, "/home") ||
      path_in_tree(path, "/apps") || path_in_tree(path, "/state") ||
      path_in_tree(path, "/logs") ||
      path_in_tree(path, "/models/.staging")) {
    return XAIOS_OK;
  }
  ++g_fs_denials;
  return reject_security_operation("fs-write-denied");
}

xaios_status_t security_authorize_git_workspace(uint32_t workspace_id,
                                               uint32_t owner_cell_id,
                                               uint32_t actor_cell_id,
                                               const char *operation) {
  (void)workspace_id;
  if (security_reject_credential_material(operation) != XAIOS_OK) {
    ++g_workspace_denials;
    return XAIOS_ERR_INVALID;
  }
  if (actor_cell_id == owner_cell_id) {
    return XAIOS_OK;
  }
  ++g_workspace_denials;
  return reject_security_operation("git-workspace-owner-mismatch");
}

xaios_status_t security_authorize_sandbox(uint32_t sandbox_id,
                                         uint32_t owner_cell_id,
                                         uint32_t actor_cell_id,
                                         const char *operation) {
  (void)sandbox_id;
  if (security_reject_credential_material(operation) != XAIOS_OK) {
    ++g_sandbox_denials;
    return XAIOS_ERR_INVALID;
  }
  if (actor_cell_id == owner_cell_id) {
    return XAIOS_OK;
  }
  ++g_sandbox_denials;
  return reject_security_operation("sandbox-owner-mismatch");
}

xaios_status_t security_authorize_rollback(const char *target,
                                          uint32_t authorized) {
  if (security_reject_credential_material(target) != XAIOS_OK) {
    ++g_rollback_denials;
    return XAIOS_ERR_INVALID;
  }
  if (authorized != 0) {
    return XAIOS_OK;
  }
  ++g_rollback_denials;
  return reject_security_operation("rollback-denied");
}

xaios_status_t security_authorize_admin(const char *operation,
                                       uint64_t granted) {
  if (security_reject_credential_material(operation) != XAIOS_OK) {
    ++g_admin_denials;
    return XAIOS_ERR_INVALID;
  }
  if ((granted & XAIOS_CAP_ADMIN) == XAIOS_CAP_ADMIN) {
    return XAIOS_OK;
  }
  ++g_admin_denials;
  ++g_capability_denials;
  return reject_security_operation("admin-capability-denied");
}

xaios_status_t security_reject_credential_material(const char *text) {
  if (text == 0) {
    ++g_credential_rejects;
    return reject_security_operation("null-input");
  }

  if (contains(text, k_pat_credential_pattern) ||
      contains(text, k_short_credential_pattern) ||
      contains(text, k_private_begin_pattern) ||
      contains(text, k_private_key_pattern) ||
      contains(text, k_pass_field_pattern) ||
      contains(text, k_token_field_pattern) ||
      contains(text, k_secret_field_pattern)) {
    ++g_credential_rejects;
    return reject_security_operation("credential-material");
  }

  return XAIOS_OK;
}

xaios_status_t security_reject_credential_material_buffer(const char *text,
                                                         uint64_t length) {
  if (text == 0) {
    ++g_credential_rejects;
    return reject_security_operation("null-input");
  }
  if (contains_buffer(text, length, k_pat_credential_pattern) ||
      contains_buffer(text, length, k_short_credential_pattern) ||
      contains_buffer(text, length, k_private_begin_pattern) ||
      contains_buffer(text, length, k_private_key_pattern) ||
      contains_buffer(text, length, k_pass_field_pattern) ||
      contains_buffer(text, length, k_token_field_pattern) ||
      contains_buffer(text, length, k_secret_field_pattern)) {
    ++g_credential_rejects;
    return reject_security_operation("credential-material");
  }
  return XAIOS_OK;
}

static xaios_status_t validate_update_signature(
    const char *signature, uint64_t expected_generation,
    uint8_t expected_hash[32]) {
  uint64_t generation = 0;
  uint8_t signature_bytes[XAIOS_UPDATE_SIGNATURE_BYTES];
  uint8_t signed_hash[32];
  if (security_reject_credential_material(signature) != XAIOS_OK) {
    ++g_signature_rejects;
    ++g_update_policy_rejects;
    return XAIOS_ERR_INVALID;
  }

  if (!starts_with(signature, XAIOS_UPDATE_SIGNATURE_PREFIX)) {
    return reject_update_signature("bad-update-signature-prefix");
  }

  const char *cursor = signature + sizeof(XAIOS_UPDATE_SIGNATURE_PREFIX) - 1U;
  if (parse_generation(&cursor, &generation) != XAIOS_OK) {
    return reject_update_signature("bad-update-generation");
  }
  if (expected_generation != 0U && generation != expected_generation) {
    return reject_update_signature("update-generation-mismatch");
  }
  if (generation <= g_last_update_generation) {
    return reject_update_replay();
  }

  if (!starts_with(cursor, XAIOS_UPDATE_SIGNATURE_SHA_FIELD)) {
    return reject_update_signature("missing-update-sha256");
  }
  cursor += sizeof(XAIOS_UPDATE_SIGNATURE_SHA_FIELD) - 1U;
  if (!parse_hex_bytes(cursor, signed_hash, sizeof(signed_hash))) {
    return reject_update_signature("bad-update-sha256");
  }
  cursor += 64U;
  if (*cursor != ':') {
    return reject_update_signature("bad-update-signature-format");
  }
  ++cursor;

  if (!starts_with(cursor, XAIOS_UPDATE_SIGNATURE_KEY_FIELD)) {
    return reject_update_key("bad-update-key");
  }
  cursor += sizeof(XAIOS_UPDATE_SIGNATURE_KEY_FIELD) - 1U;
  const char *signed_end = cursor;
  if (*cursor != ':') {
    return reject_update_signature("bad-update-signature-format");
  }
  ++cursor;

  if (!starts_with(cursor, XAIOS_UPDATE_SIGNATURE_SIG_FIELD)) {
    return reject_update_signature("missing-update-signature");
  }
  cursor += sizeof(XAIOS_UPDATE_SIGNATURE_SIG_FIELD) - 1U;
  if (!parse_hex_bytes(cursor, signature_bytes, sizeof(signature_bytes))) {
    return reject_update_signature("bad-update-signature-bytes");
  }
  cursor += sizeof(signature_bytes) * 2U;
  if (*cursor != '\0') {
    return reject_update_signature("bad-update-signature-format");
  }

  uint64_t signed_length = (uint64_t)(signed_end - signature);
  if (signed_length == 0U || signed_length > UINT32_MAX ||
      xaios_ed25519_verify(signature_bytes, (const uint8_t *)signature,
                           (uint32_t)signed_length,
                           k_update_public_key) != 0) {
    return reject_update_signature("bad-update-cryptographic-signature");
  }

  g_last_update_generation = generation;
  if (expected_hash != 0) {
    for (uint32_t index = 0U; index < sizeof(signed_hash); ++index) {
      expected_hash[index] = signed_hash[index];
    }
  }
  ++g_key_accepts;
  ++g_signature_accepts;
  klog("security: update signature accepted policy=ed25519 generation=%lu key=qemu-test-public\n",
       generation);
  return XAIOS_OK;
}

xaios_status_t security_validate_update_signature(const char *signature) {
  return validate_update_signature(signature, 0U, 0);
}

xaios_status_t security_authorize_update_signature(const char *signature,
                                                  uint64_t granted) {
  if ((granted & XAIOS_CAP_UPDATE) != XAIOS_CAP_UPDATE) {
    (void)security_authorize_capability("service.update", granted,
                                        XAIOS_CAP_UPDATE);
    return XAIOS_ERR_INVALID;
  }
  if (security_authorize_admin("service.update", granted) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (security_validate_update_signature(signature) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++g_update_authorizations;
  return XAIOS_OK;
}

xaios_status_t security_authorize_update_signature_for_generation(
    const char *signature, uint64_t granted, uint64_t expected_generation,
    uint8_t expected_hash[32]) {
  if (expected_generation == 0U || expected_hash == 0 ||
      (granted & XAIOS_CAP_UPDATE) != XAIOS_CAP_UPDATE) {
    (void)security_authorize_capability("service.update", granted,
                                        XAIOS_CAP_UPDATE);
    return XAIOS_ERR_INVALID;
  }
  if (security_authorize_admin("service.update", granted) != XAIOS_OK ||
      validate_update_signature(signature, expected_generation,
                                expected_hash) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++g_update_authorizations;
  return XAIOS_OK;
}

xaios_status_t security_validate_sandbox_path(const char *path) {
  const char *cursor = path;
  if (security_reject_credential_material(path) != XAIOS_OK) {
    ++g_sandbox_escape_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (path == 0 || path[0] != '/') {
    ++g_sandbox_escape_rejects;
    return reject_security_operation("sandbox-path-relative");
  }
  while (*cursor != '\0') {
    if (cursor[0] == '/' && cursor[1] == '/') {
      ++g_sandbox_escape_rejects;
      return reject_security_operation("sandbox-path-escape");
    }
    if (cursor[0] == '.' && cursor[1] == '.' &&
        (cursor == path || cursor[-1] == '/') &&
        (cursor[2] == '/' || cursor[2] == '\0')) {
      ++g_sandbox_escape_rejects;
      return reject_security_operation("sandbox-path-escape");
    }
    ++cursor;
  }
  return XAIOS_OK;
}

xaios_status_t security_validate_benchmark_record(const char *record) {
  if (security_reject_credential_material(record) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (record == 0 || !contains(record, "\"design_targets\":true")) {
    return reject_security_operation("benchmark-record-policy");
  }
  return XAIOS_OK;
}

uint64_t security_denied_operation_count(void) {
  return g_denied_operations;
}

uint64_t security_capability_denial_count(void) {
  return g_capability_denials;
}

uint64_t security_fs_denial_count(void) {
  return g_fs_denials;
}

uint64_t security_workspace_denial_count(void) {
  return g_workspace_denials;
}

uint64_t security_sandbox_denial_count(void) {
  return g_sandbox_denials;
}

uint64_t security_rollback_denial_count(void) {
  return g_rollback_denials;
}

uint64_t security_update_policy_reject_count(void) {
  return g_update_policy_rejects;
}

uint64_t security_signature_accept_count(void) {
  return g_signature_accepts;
}

uint64_t security_signature_reject_count(void) {
  return g_signature_rejects;
}

uint64_t security_credential_reject_count(void) {
  return g_credential_rejects;
}

uint64_t security_admin_denial_count(void) {
  return g_admin_denials;
}

uint64_t security_update_authorization_count(void) {
  return g_update_authorizations;
}

uint64_t security_update_replay_reject_count(void) {
  return g_update_replay_rejects;
}

uint64_t security_key_accept_count(void) {
  return g_key_accepts;
}

uint64_t security_key_reject_count(void) {
  return g_key_rejects;
}

uint64_t security_sandbox_escape_reject_count(void) {
  return g_sandbox_escape_rejects;
}

void security_self_test(void) {
  security_policy_init();
  const char credential_fixture[] = {
      'g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_',
      'e', 'x', 'a', 'm', 'p', 'l', 'e', '\0'};
  kassert(security_reject_credential_material("normal-update-request") ==
          XAIOS_OK);
  kassert(security_reject_credential_material(credential_fixture) ==
          XAIOS_ERR_INVALID);
  kassert(security_validate_update_signature("unsigned-update") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_capability("service.update", 0U, 16U) ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_fs_read("/etc/services/source-index.svc") ==
          XAIOS_OK);
  kassert(security_authorize_fs_write("/etc/services/source-index.svc") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_fs_read("/models/active-package") == XAIOS_OK);
  kassert(security_authorize_fs_write("/models/active-package") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_fs_write("/models/.staging/package") ==
          XAIOS_OK);
  kassert(security_authorize_git_workspace(0, 1, 2, "patch") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_sandbox(0, 1, 2, "build") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_rollback("/init", 0) == XAIOS_ERR_INVALID);
  kassert(security_authorize_admin("admin.shell", 0) == XAIOS_ERR_INVALID);
  kassert(security_validate_sandbox_path("/workspace/1/../escape") ==
          XAIOS_ERR_INVALID);
  kassert(security_validate_benchmark_record(
              "{\"design_targets\":true,\"latency\":\"target\"}") ==
          XAIOS_OK);
  kassert(security_validate_benchmark_record("token=bad") ==
          XAIOS_ERR_INVALID);
  kassert(security_validate_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=BAD:sig=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c9c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e",
              XAIOS_CAP_UPDATE) == XAIOS_ERR_INVALID);
  kassert(security_validate_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c8c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c9c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e",
              XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN) ==
          XAIOS_OK);
  kassert(security_validate_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c9c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e") ==
          XAIOS_ERR_INVALID);
  kassert(g_credential_rejects == 2);
  kassert(g_signature_rejects == 4);
  kassert(g_signature_accepts == 1);
  kassert(g_capability_denials == 3);
  kassert(g_fs_denials == 2);
  kassert(g_workspace_denials == 1);
  kassert(g_sandbox_denials == 1);
  kassert(g_rollback_denials == 1);
  kassert(g_update_policy_rejects == 4);
  kassert(g_admin_denials == 2);
  kassert(g_update_authorizations == 1);
  kassert(g_update_replay_rejects == 1);
  kassert(g_key_accepts == 1);
  kassert(g_key_rejects == 1);
  kassert(g_sandbox_escape_rejects == 1);
  kassert(g_denied_operations == 15);
  klog("security: self-test passed denied=%lu capability_denials=%lu fs_denials=%lu workspace_denials=%lu sandbox_denials=%lu rollback_denials=%lu update_policy_rejects=%lu credential_rejects=%lu signature_accepts=%lu signature_rejects=%lu admin_denials=%lu update_authorizations=%lu update_replay_rejects=%lu key_accepts=%lu key_rejects=%lu sandbox_escape_rejects=%lu\n",
       g_denied_operations, g_capability_denials, g_fs_denials,
       g_workspace_denials, g_sandbox_denials, g_rollback_denials,
       g_update_policy_rejects, g_credential_rejects, g_signature_accepts,
       g_signature_rejects, g_admin_denials, g_update_authorizations,
       g_update_replay_rejects, g_key_accepts, g_key_rejects,
       g_sandbox_escape_rejects);
}
