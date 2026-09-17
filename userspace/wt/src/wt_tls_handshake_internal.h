/* The cursor and version constants shared by the TLS 1.3 handshake's modules.
 *
 * `wt_tls_handshake.c` keeps the framing, the transcript hash, the ServerHello
 * parser and the Finished MAC; `wt_tls_handshake_ee.c` holds the
 * EncryptedExtensions parser and the ClientHello-offered check, and
 * `wt_tls_handshake_clienthello.c` builds a ClientHello. All three include this
 * header.
 *
 * What crosses the cut is one cursor and two version constants. The cursor
 * reads a peer-controlled handshake body and bounds-checks every read, so it is
 * defined once, in `wt_tls_handshake.c`, and shared rather than copied: a second
 * copy that drifted would be a second bounds policy. Its symbols carry the
 * module prefix because they now cross a translation unit.
 */

#ifndef WT_TLS_HANDSHAKE_INTERNAL_H
#define WT_TLS_HANDSHAKE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* TLS 1.3's wire version. The legacy_version field is always 0x0303 -- "TLS
 * 1.2" -- and the real version is negotiated in supported_versions. A reader
 * that trusted legacy_version would accept a downgrade. */
#define WT_TLS_LEGACY_VERSION 0x0303U
#define WT_TLS_VERSION_13 0x0304U

/* A cursor over the body of a handshake message. Every read is bounds-checked,
 * because the whole body is peer-controlled. */
typedef struct wt_tls_reader {
  const uint8_t *data;
  size_t len;
  size_t offset;
  int failed;
} wt_tls_reader_t;

void wt_tls_reader_init(wt_tls_reader_t *r, const uint8_t *data, size_t len);
const uint8_t *wt_tls_reader_take(wt_tls_reader_t *r, size_t n);
uint8_t wt_tls_reader_u8(wt_tls_reader_t *r);
uint16_t wt_tls_reader_u16(wt_tls_reader_t *r);

#endif /* WT_TLS_HANDSHAKE_INTERNAL_H */
