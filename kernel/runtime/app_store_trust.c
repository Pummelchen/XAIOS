/* The app store's release trust chain: key revocation, the signed
 * XAIOS-TRUST-V1 line parser, the bootstrap trust state and the persisted
 * trust-and-catalog loader.
 *
 * kernel/runtime/app_store.c keeps the store's public entry points and the
 * on-disk activation order; this file validates the chain and mutates the
 * release key register exactly where the callers previously did. Declared in
 * app_store_internal.h. */
#include "app_store_internal.h"

#include <xaios/kheap.h>
#include <xaios/security.h>

static int trust_key_is_revoked(const app_trust_state_t *state,
                                const uint8_t key[APP_PUBLIC_KEY_BYTES]) {
  for (uint32_t i = 0U; i < state->revoked_count; ++i) {
    if (app_store_bytes_equal(state->revoked_keys[i], key,
                              APP_PUBLIC_KEY_BYTES))
      return 1;
  }
  return 0;
}

static int trust_revoke_key(app_trust_state_t *state,
                            const uint8_t key[APP_PUBLIC_KEY_BYTES]) {
  if (trust_key_is_revoked(state, key)) return 1;
  if (state->revoked_count >= APP_REVOKED_KEY_MAX) return 0;
  app_store_bytes_copy(state->revoked_keys[state->revoked_count++], key,
                       APP_PUBLIC_KEY_BYTES);
  return 1;
}

static xaios_status_t parse_trust_line(const char *line, uint64_t size,
                                       const app_trust_state_t *current,
                                       app_trust_state_t *next) {
  static const char prefix[] = "XAIOS-TRUST-V1:gen=";
  static const char mode_field[] = ":mode=";
  static const char active_field[] = ":active=";
  static const char revoke_field[] = ":revoke=";
  static const char signer_field[] = ":signer=";
  static const char signature_field[] = ":sig=";
  uint64_t cursor = sizeof(prefix) - 1U;
  uint64_t start;
  uint64_t generation = 0U;
  uint8_t active[APP_PUBLIC_KEY_BYTES];
  uint8_t revoked[APP_PUBLIC_KEY_BYTES];
  uint8_t signer[APP_PUBLIC_KEY_BYTES];
  uint8_t signature[64];
  int recovery = 0;
  if (line == 0 || current == 0 || next == 0 || size > APP_TRUST_LINE_MAX ||
      size < sizeof(prefix) + 250U || line[size - 1U] != '\n')
    return XAIOS_ERR_INVALID;
  for (uint64_t i = 0U; i < sizeof(prefix) - 1U; ++i)
    if (line[i] != prefix[i]) return XAIOS_ERR_INVALID;
  start = cursor;
  while (cursor < size && line[cursor] >= '0' && line[cursor] <= '9')
    ++cursor;
  if (!app_store_parse_u64(line + start, cursor - start, &generation) ||
      generation <= current->generation || generation > UINT32_MAX)
    return XAIOS_ERR_INVALID;
#define TRUST_EXPECT(field)                                                   \
  do {                                                                        \
    for (uint64_t i = 0U; i < sizeof(field) - 1U; ++i)                        \
      if (cursor + i >= size || line[cursor + i] != field[i])                 \
        return XAIOS_ERR_INVALID;                                              \
    cursor += sizeof(field) - 1U;                                              \
  } while (0)
  TRUST_EXPECT(mode_field);
  if (cursor + 6U <= size && line[cursor] == 'r' && line[cursor + 1U] == 'o' &&
      line[cursor + 2U] == 't' && line[cursor + 3U] == 'a' &&
      line[cursor + 4U] == 't' && line[cursor + 5U] == 'e') {
    cursor += 6U;
  } else if (cursor + 8U <= size && line[cursor] == 'r' &&
             line[cursor + 1U] == 'e' && line[cursor + 2U] == 'c' &&
             line[cursor + 3U] == 'o' && line[cursor + 4U] == 'v' &&
             line[cursor + 5U] == 'e' && line[cursor + 6U] == 'r' &&
             line[cursor + 7U] == 'y') {
    recovery = 1;
    cursor += 8U;
  } else {
    return XAIOS_ERR_INVALID;
  }
  TRUST_EXPECT(active_field);
  if (cursor + APP_PUBLIC_KEY_HEX_BYTES > size ||
      !app_store_parse_hex(line + cursor, active, sizeof(active)))
    return XAIOS_ERR_INVALID;
  cursor += APP_PUBLIC_KEY_HEX_BYTES;
  TRUST_EXPECT(revoke_field);
  if (cursor + APP_PUBLIC_KEY_HEX_BYTES > size ||
      !app_store_parse_hex(line + cursor, revoked, sizeof(revoked)))
    return XAIOS_ERR_INVALID;
  cursor += APP_PUBLIC_KEY_HEX_BYTES;
  TRUST_EXPECT(signer_field);
  if (cursor + APP_PUBLIC_KEY_HEX_BYTES > size ||
      !app_store_parse_hex(line + cursor, signer, sizeof(signer)))
    return XAIOS_ERR_INVALID;
  cursor += APP_PUBLIC_KEY_HEX_BYTES;
  uint64_t signed_size = cursor;
  TRUST_EXPECT(signature_field);
  if (cursor + APP_SIGNATURE_HEX_BYTES + 1U != size ||
      !app_store_parse_hex(line + cursor, signature, sizeof(signature)))
    return XAIOS_ERR_INVALID;
  if (recovery) {
    if (!security_recovery_key_matches(signer)) return XAIOS_ERR_INVALID;
  } else if (!app_store_bytes_equal(signer, current->active_key,
                                    sizeof(signer)) ||
             !app_store_bytes_equal(revoked, current->active_key,
                                    sizeof(revoked)) ||
             trust_key_is_revoked(current, active)) {
    return XAIOS_ERR_INVALID;
  }
  if (app_store_bytes_equal(active, revoked, sizeof(active)) ||
      security_verify_signature_with_key(line, (uint32_t)signed_size,
                                         signature, signer) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  *next = *current;
  if (recovery) next->revoked_count = 0U;
  if (!trust_revoke_key(next, revoked)) return XAIOS_ERR_NO_MEMORY;
  next->generation = (uint32_t)generation;
  app_store_bytes_copy(next->active_key, active, sizeof(active));
#undef TRUST_EXPECT
  return XAIOS_OK;
}

void app_store_default_trust_state(app_trust_state_t *state) {
  app_store_bytes_zero(state, sizeof(*state));
  state->generation = 1U;
  (void)app_store_parse_hex(XAIOS_RELEASE_PUBLIC_KEY_HEX, state->active_key,
                            sizeof(state->active_key));
}

xaios_status_t app_store_load_trust_and_catalog(const char *trust_path,
                                                const char *catalog_path,
                                                app_trust_state_t *trust) {
  void *trust_data = 0;
  uint64_t trust_size = 0U;
  void *catalog_data = 0;
  uint64_t catalog_size = 0U;
  uint32_t generation = 0U;
  app_store_default_trust_state(trust);
  xaios_status_t trust_status = app_store_read_file_alloc(
      trust_path, APP_TRUST_CHAIN_MAX, &trust_data, &trust_size);
  if (trust_status == XAIOS_OK &&
      app_store_validate_trust_chain((const char *)trust_data, trust_size,
                                     trust) != XAIOS_OK) {
    kheap_free(trust_data);
    return XAIOS_ERR_INVALID;
  }
  kheap_free(trust_data);
  (void)security_set_release_key(trust->active_key);
  xaios_status_t catalog_status = app_store_read_file_alloc(
      catalog_path, XAIOS_APP_CATALOG_MAX, &catalog_data, &catalog_size);
  if (trust_status == XAIOS_OK && catalog_status != XAIOS_OK) {
    kheap_free(catalog_data);
    return XAIOS_ERR_INVALID;
  }
  if (catalog_status == XAIOS_OK &&
      app_store_parse_catalog_identity((const char *)catalog_data,
                                       catalog_size,
                                       &generation) != XAIOS_OK) {
    kheap_free(catalog_data);
    return XAIOS_ERR_INVALID;
  }
  kheap_free(catalog_data);
  return catalog_status == XAIOS_ERR_INVALID ? XAIOS_OK : catalog_status;
}

xaios_status_t app_store_validate_trust_chain(const char *data, uint64_t size,
                                              app_trust_state_t *state) {
  app_trust_state_t current;
  app_store_default_trust_state(&current);
  uint64_t cursor = 0U;
  while (cursor < size) {
    uint64_t start = cursor;
    while (cursor < size && data[cursor] != '\n') ++cursor;
    if (cursor >= size || cursor == start ||
        parse_trust_line(data + start, cursor - start + 1U, &current,
                         state) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    current = *state;
    ++cursor;
  }
  *state = current;
  return XAIOS_OK;
}
