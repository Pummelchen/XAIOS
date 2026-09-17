/*
 * The signed-update policy, moved out of kernel/runtime/security.c so no
 * source file exceeds 500 lines.
 *
 * This file owns the pinned development and recovery public keys, the live
 * release key, the last accepted update generation, and the
 * "xaios-update:v2:" signature grammar that admits an update. Every body is
 * the one the unsplit file held; the denial counters themselves stay
 * file-scope in security.c, and the single atomic increments this code
 * performed inline are performed through the security_note_* seeds the
 * private header declares, at the same point in the same order.
 */

#include "security_internal.h"

#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/syscall.h>

#define XAIOS_UPDATE_SIGNATURE_PREFIX "xaios-update:v2:"
#define XAIOS_UPDATE_SIGNATURE_GEN_FIELD "gen="
#define XAIOS_UPDATE_SIGNATURE_SHA_FIELD "sha256="
#define XAIOS_UPDATE_SIGNATURE_KEY_FIELD "key="
#define XAIOS_UPDATE_SIGNATURE_SIG_FIELD "sig="
#define XAIOS_UPDATE_SIGNATURE_BYTES 64U

static const uint8_t k_update_public_key[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
static const uint8_t k_recovery_public_key[32] = {
    0x5c, 0x34, 0xb6, 0x58, 0x2a, 0x13, 0xd1, 0x4a,
    0x95, 0x4e, 0x08, 0x2f, 0x33, 0x3d, 0xf3, 0x3b,
    0x0b, 0xa6, 0x22, 0x2f, 0xb0, 0x19, 0xcf, 0x3a,
    0xd4, 0x5a, 0xe3, 0xed, 0x5e, 0x9f, 0x9d, 0xe4};
static uint8_t g_release_public_key[32];
static uint64_t g_last_update_generation;

extern int xaios_ed25519_verify(const uint8_t signature[64],
                                const uint8_t *message,
                                uint32_t message_len,
                                const uint8_t public_key[32]);

/* Called from security_policy_init(); the order -- forget the generation,
   then restore the built-in key -- is the order the unsplit file used. */
void security_reset_update_key_state(void) {
  g_last_update_generation = 0;
  for (uint32_t i = 0U; i < sizeof(g_release_public_key); ++i)
    g_release_public_key[i] = k_update_public_key[i];
}

static int constant_time_equal(const uint8_t *left, const uint8_t *right,
                               uint32_t size) {
  uint8_t difference = 0U;
  for (uint32_t i = 0U; i < size; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
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
      !security_starts_with(cursor[0], XAIOS_UPDATE_SIGNATURE_GEN_FIELD)) {
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
  security_note_signature_reject();
  security_note_update_policy_reject();
  return reject_security_operation(reason);
}

static xaios_status_t reject_update_key(const char *reason) {
  security_note_key_reject();
  return reject_update_signature(reason);
}

static xaios_status_t reject_update_replay(void) {
  security_note_update_replay_reject();
  return reject_update_signature("update-replay-denied");
}

static xaios_status_t validate_update_signature(
    const char *signature, uint64_t expected_generation,
    uint8_t expected_hash[32]) {
  uint64_t generation = 0;
  uint8_t signature_bytes[XAIOS_UPDATE_SIGNATURE_BYTES];
  uint8_t signed_hash[32];
  if (security_reject_credential_material(signature) != XAIOS_OK) {
    security_note_signature_reject();
    security_note_update_policy_reject();
    return XAIOS_ERR_INVALID;
  }

  if (!security_starts_with(signature, XAIOS_UPDATE_SIGNATURE_PREFIX)) {
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

  if (!security_starts_with(cursor, XAIOS_UPDATE_SIGNATURE_SHA_FIELD)) {
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

  if (!security_starts_with(cursor, XAIOS_UPDATE_SIGNATURE_KEY_FIELD)) {
    return reject_update_key("bad-update-key");
  }
  cursor += sizeof(XAIOS_UPDATE_SIGNATURE_KEY_FIELD) - 1U;
  uint8_t supplied_key[32];
  if (!parse_hex_bytes(cursor, supplied_key, sizeof(supplied_key)) ||
      !security_release_key_matches(supplied_key)) {
    return reject_update_key("bad-update-key");
  }
  cursor += sizeof(supplied_key) * 2U;
  const char *signed_end = cursor;
  if (*cursor != ':') {
    return reject_update_signature("bad-update-signature-format");
  }
  ++cursor;

  if (!security_starts_with(cursor, XAIOS_UPDATE_SIGNATURE_SIG_FIELD)) {
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
                           g_release_public_key) != 0) {
    return reject_update_signature("bad-update-cryptographic-signature");
  }

  g_last_update_generation = generation;
  if (expected_hash != 0) {
    for (uint32_t index = 0U; index < sizeof(signed_hash); ++index) {
      expected_hash[index] = signed_hash[index];
    }
  }
  security_note_key_accept();
  security_note_signature_accept();
  klog("security: update signature accepted policy=ed25519 generation=%lu key=development-test-public\n",
       generation);
  return XAIOS_OK;
}

xaios_status_t security_validate_update_signature(const char *signature) {
  return validate_update_signature(signature, 0U, 0);
}

xaios_status_t security_verify_release_signature(
    const void *message, uint32_t message_size,
    const uint8_t signature[64]) {
  if (message == 0 || message_size == 0U || signature == 0 ||
      xaios_ed25519_verify(signature, (const uint8_t *)message, message_size,
                           g_release_public_key) != 0) {
    security_note_signature_reject();
    return XAIOS_ERR_INVALID;
  }
  security_note_signature_accept();
  return XAIOS_OK;
}

xaios_status_t security_verify_signature_with_key(
    const void *message, uint32_t message_size, const uint8_t signature[64],
    const uint8_t public_key[32]) {
  if (message == 0 || message_size == 0U || signature == 0 ||
      public_key == 0 ||
      xaios_ed25519_verify(signature, (const uint8_t *)message, message_size,
                           public_key) != 0) {
    security_note_signature_reject();
    return XAIOS_ERR_INVALID;
  }
  security_note_signature_accept();
  return XAIOS_OK;
}

int security_release_key_matches(const uint8_t public_key[32]) {
  return public_key != 0 &&
         constant_time_equal(public_key, g_release_public_key, 32U);
}

int security_recovery_key_matches(const uint8_t public_key[32]) {
  return public_key != 0 &&
         constant_time_equal(public_key, k_recovery_public_key, 32U);
}

xaios_status_t security_set_release_key(const uint8_t public_key[32]) {
  if (public_key == 0) return XAIOS_ERR_INVALID;
  int changed = !constant_time_equal(public_key, g_release_public_key, 32U);
  for (uint32_t i = 0U; i < sizeof(g_release_public_key); ++i)
    g_release_public_key[i] = public_key[i];
  if (changed) g_last_update_generation = 0U;
  return XAIOS_OK;
}

void security_get_release_key(uint8_t public_key[32]) {
  if (public_key == 0) return;
  for (uint32_t i = 0U; i < sizeof(g_release_public_key); ++i)
    public_key[i] = g_release_public_key[i];
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
  security_note_update_authorization();
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
  security_note_update_authorization();
  return XAIOS_OK;
}
