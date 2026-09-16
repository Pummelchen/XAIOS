/* TLS 1.3 extensions (RFC 8446 section 4.2).
 *
 * An extension is a two-byte type, a two-byte length and that many bytes of opaque
 * data, and every message that carries them carries a LIST of them behind another
 * length. That is the whole of the generic layer: `wt_tls_extension_t` is a view into
 * the message being parsed, and a list is a fixed array of views, so parsing a
 * ClientHello allocates nothing and the bytes stay where they arrived.
 *
 * The typed layer above it knows the shape of the extensions this implementation
 * uses. There are two directions and they are deliberately different in shape:
 *
 *   - READING is view-based (`wt_tls_key_share_client` hands back pointers into the
 *     message), because a peer's extension is read once and then used, and copying it
 *     would be a way for a length mistake to go unnoticed.
 *   - WRITING is parameter-based (`wt_tls_extension_key_share_client` takes the
 *     values and writes type, length and body through a writer), because what we
 *     send is built from values we chose rather than from bytes we received.
 *
 * WHY THE READERS TAKE A CAPACITY. Every list in TLS is prefixed with a length in
 * bytes, and the number of entries in it is that length divided by the entry size --
 * which a peer chooses. A reader that looped until the length ran out would write
 * past whatever array it was given as soon as a peer sent more entries than the
 * array holds, so each of these refuses with WT_ERR_LIMIT instead: the bound is this
 * implementation's, and a peer that exceeds it is refused rather than believed.
 *
 * NOT HERE: the 0-RTT and resumption extensions (`early_data`,
 * `pre_shared_key`), which need the ticket machinery this implementation does not
 * have, and the `cookie` and `key_share` retry paths, which need HelloRetryRequest.
 * Neither is implemented, so neither is exported.
 */

#ifndef WEBTRANSPORT_TLS_EXTENSION_H
#define WEBTRANSPORT_TLS_EXTENSION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The extension types this implementation knows, from the TLS and QUIC registries. */
#define WT_TLS_EXTENSION_SERVER_NAME 0x0000U
#define WT_TLS_EXTENSION_SUPPORTED_GROUPS 0x000aU
#define WT_TLS_EXTENSION_SIGNATURE_ALGORITHMS 0x000dU
#define WT_TLS_EXTENSION_ALPN 0x0010U
#define WT_TLS_EXTENSION_SUPPORTED_VERSIONS 0x002bU
#define WT_TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES 0x002dU
#define WT_TLS_EXTENSION_KEY_SHARE 0x0033U
#define WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS 0x0039U

/* Bounds. Every one of them is this implementation's limit and not the protocol's:
 * the protocol's limits are 2^16 entries, which is not a number an array can hold. */
#define WT_TLS_MAX_EXTENSIONS 24U
#define WT_TLS_MAX_NAMED_GROUPS 16U
#define WT_TLS_MAX_SIGNATURE_SCHEMES 16U
#define WT_TLS_MAX_KEY_SHARES 4U
#define WT_TLS_MAX_PROTOCOLS 8U
#define WT_TLS_MAX_PROTOCOL_NAME 255U

/* TLS 1.3, the ciphersuite and the groups this implementation offers. Mandatory in
 * RFC 8446 section 9.1 and the only ones with code behind them. */
#define WT_TLS_VERSION_1_3 0x0304U
#define WT_TLS_VERSION_1_2 0x0303U
#define WT_TLS_CIPHER_AES_128_GCM_SHA256 0x1301U
#define WT_TLS_GROUP_X25519 0x001dU
#define WT_TLS_GROUP_SECP256R1 0x0017U
#define WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403U
#define WT_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 0x0503U
#define WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 0x0804U
#define WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 0x0805U
#define WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 0x0806U
#define WT_TLS_SIGNATURE_ED25519 0x0807U
#define WT_TLS_PSK_MODE_PSK_DHE_KE 0x0001U

/* One extension, as a view into the message it was parsed from. */
typedef struct wt_tls_extension {
  uint16_t type;
  const uint8_t *data;
  size_t len;
} wt_tls_extension_t;

typedef struct wt_tls_extension_list {
  wt_tls_extension_t entries[WT_TLS_MAX_EXTENSIONS];
  size_t count;
} wt_tls_extension_list_t;

/* Parse the extension list at the cursor: a two-byte length and then that many
 * bytes, which must contain whole extensions and nothing else.
 *
 * WT_ERR_LIMIT if there are more extensions than the list can hold;
 * WT_ERR_PROTOCOL for a duplicate type (RFC 8446 section 4.2 forbids one), a
 * length that does not fill the block exactly, or a length field larger than the
 * cursor has. On success the cursor is past the whole block. */
wt_status_t wt_tls_extensions_parse(wt_cursor_t *cursor,
                                    wt_tls_extension_list_t *out);

/* Write a list as one block: the two-byte length, then each extension. */
wt_status_t wt_tls_extensions_encode(wt_writer_t *w,
                                     const wt_tls_extension_list_t *list);

/* The first extension of a type, or NULL. A list cannot hold two of one type, so
 * "first" and "the" are the same thing. */
const wt_tls_extension_t *wt_tls_extensions_find(
    const wt_tls_extension_list_t *list, uint16_t type);

/* Whether a list contains a type. */
int wt_tls_extensions_contains(const wt_tls_extension_list_t *list, uint16_t type);

/* ------------------------------------------------------------ typed readers */

/* supported_versions in a ClientHello: a one-byte length and then that many
 * two-byte versions (RFC 8446 section 4.2.1). */
wt_status_t wt_tls_supported_versions_client(const wt_tls_extension_t *extension,
                                             uint16_t *versions, size_t capacity,
                                             size_t *count);

/* supported_versions in a ServerHello: a single two-byte version. */
wt_status_t wt_tls_supported_versions_server(const wt_tls_extension_t *extension,
                                             uint16_t *version);

/* A list of two-byte values behind a two-byte length: `supported_groups` and
 * `signature_algorithms` are the same shape, and one reader serves both. */
wt_status_t wt_tls_u16_list_parse(const wt_tls_extension_t *extension,
                                  uint16_t *values, size_t capacity,
                                  size_t *count);

/* One key share: a group and a public key. */
typedef struct wt_tls_key_share {
  uint16_t group;
  const uint8_t *key;
  size_t key_len;
} wt_tls_key_share_t;

/* key_share in a ClientHello: a list of shares. */
wt_status_t wt_tls_key_share_client(const wt_tls_extension_t *extension,
                                    wt_tls_key_share_t *shares, size_t capacity,
                                    size_t *count);

/* key_share in a ServerHello: exactly one share. */
wt_status_t wt_tls_key_share_server(const wt_tls_extension_t *extension,
                                    wt_tls_key_share_t *share);

/* application_layer_protocol_negotiation (RFC 7301): a list of one-byte-length
 * names behind a two-byte length. The names are views, and they are not
 * NUL-terminated: a protocol name is a length and bytes, not a C string. */
typedef struct wt_tls_alpn {
  const uint8_t *names[WT_TLS_MAX_PROTOCOLS];
  uint8_t lengths[WT_TLS_MAX_PROTOCOLS];
  size_t count;
} wt_tls_alpn_t;

wt_status_t wt_tls_alpn_parse(const wt_tls_extension_t *extension,
                              wt_tls_alpn_t *out);

/* quic_transport_parameters (RFC 9001 section 8.2): the QUIC parameters as opaque
 * bytes. Opaque here is deliberate -- the codec for them belongs to the QUIC
 * layer, which is what refuses a malformed set. */
wt_status_t wt_tls_transport_parameters(const wt_tls_extension_t *extension,
                                        const uint8_t **data, size_t *len);

/* ------------------------------------------------------------ typed writers */

/* Each writes a complete extension: type, length, body. The length is computed
 * from the values rather than remembered, which is why these take the values. */

void wt_tls_extension_supported_versions_client(wt_writer_t *w,
                                                const uint16_t *versions,
                                                size_t count);
void wt_tls_extension_supported_versions_server(wt_writer_t *w, uint16_t version);
void wt_tls_extension_u16_list(wt_writer_t *w, uint16_t type,
                               const uint16_t *values, size_t count);
void wt_tls_extension_key_share_client(wt_writer_t *w,
                                       const wt_tls_key_share_t *shares,
                                       size_t count);
void wt_tls_extension_key_share_server(wt_writer_t *w,
                                       const wt_tls_key_share_t *share);
/* `names` are C strings; a name that is empty or longer than 255 bytes is written
 * as nothing rather than as a wrong length, and the caller checks the result. */
void wt_tls_extension_alpn(wt_writer_t *w, const char *const *names, size_t count);
void wt_tls_extension_transport_parameters(wt_writer_t *w, const uint8_t *data,
                                           size_t len);
/* psk_key_exchange_modes with a single psk_dhe_ke, which is the only mode a QUIC
 * client may offer (RFC 9001 section 8.3 makes 0-RTT's psk_ke unusable). */
void wt_tls_extension_psk_key_exchange_modes(wt_writer_t *w);
/* server_name with one host name (RFC 6066 section 3). */
void wt_tls_extension_server_name(wt_writer_t *w, const char *host_name);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_EXTENSION_H */
