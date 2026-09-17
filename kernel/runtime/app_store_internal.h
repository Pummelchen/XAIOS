/* Private declarations shared by the app-store translation units.
 *
 * kernel/runtime/app_store.c keeps the store's public entry points and the
 * on-disk activation order; app_store_codec.c owns the small text and byte
 * helpers, the release-signed document reader and the manifest/catalog
 * identities; app_store_trust.c owns the release trust chain. These names
 * cross translation units, so they carry the app_store_ module prefix.
 * Nothing declared here is public kernel API. */
#ifndef XAIOS_KERNEL_RUNTIME_APP_STORE_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_APP_STORE_INTERNAL_H

#include <xaios/app_store.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define APP_PATH_MAX 96U
#define APP_SIGNATURE_HEX_BYTES 128U
#define APP_PUBLIC_KEY_BYTES 32U
#define APP_PUBLIC_KEY_HEX_BYTES 64U
#define APP_TRUST_CHAIN_MAX 4096U
#define APP_TRUST_LINE_MAX 384U
#define APP_REVOKED_KEY_MAX 8U

typedef struct app_trust_state {
  uint32_t generation;
  uint8_t active_key[APP_PUBLIC_KEY_BYTES];
  uint32_t revoked_count;
  uint8_t revoked_keys[APP_REVOKED_KEY_MAX][APP_PUBLIC_KEY_BYTES];
} app_trust_state_t;

/* app_store_codec.c */
void app_store_bytes_zero(void *buffer, uint64_t size);
void app_store_bytes_copy(void *dst, const void *src, uint64_t size);
uint64_t app_store_text_length(const char *text);
int app_store_text_equal(const char *left, const char *right);
int app_store_bytes_equal(const uint8_t *left, const uint8_t *right,
                          uint64_t size);
int app_store_name_valid(const char *name);
int app_store_append_text(char *path, uint64_t capacity, uint64_t *offset,
                          const char *text);
int app_store_app_path(char *path, uint64_t capacity, const char *name,
                       const char *leaf, int staging);
int app_store_parse_hex(const char *text, uint8_t *output, uint32_t size);
int app_store_parse_u64(const char *text, uint64_t length, uint64_t *value);
xaios_status_t app_store_parse_manifest(const char *data, uint64_t size,
                                        xaios_app_manifest_t *manifest);
xaios_status_t app_store_parse_catalog_identity(const char *data, uint64_t size,
                                                uint32_t *generation);
xaios_status_t app_store_read_file_alloc(const char *path, uint64_t maximum,
                                         void **data, uint64_t *size);

/* app_store_trust.c */
void app_store_default_trust_state(app_trust_state_t *state);
xaios_status_t app_store_load_trust_and_catalog(const char *trust_path,
                                                const char *catalog_path,
                                                app_trust_state_t *trust);
xaios_status_t app_store_validate_trust_chain(const char *data, uint64_t size,
                                              app_trust_state_t *state);

#endif
