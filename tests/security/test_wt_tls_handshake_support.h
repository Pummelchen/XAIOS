/* Fixtures and assertion helpers shared by the split TLS handshake tests.
 *
 * test_wt_tls_handshake.c, test_wt_tls_handshake_clienthello.c and
 * test_wt_tls_handshake_servermsgs.c are one test program compiled as three
 * translation units. The byte reader and the EncryptedExtensions builders are
 * the fixtures two of them use, the two check helpers are used by all three,
 * and their counters are declared here and defined exactly once, in
 * test_wt_tls_handshake_servermsgs.c.
 *
 * The helpers are `static inline` because each translation unit includes this
 * header and not every unit uses every helper.
 */

#ifndef XAIOS_TEST_WT_TLS_HANDSHAKE_SUPPORT_H
#define XAIOS_TEST_WT_TLS_HANDSHAKE_SUPPORT_H

#include "wt_tls_handshake.h"
#include "wt_quic_pkt.h"
#include "wt_rfc8448_vectors.h"
#include "wt_rfc9001_vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The check counters, defined in test_wt_tls_handshake_servermsgs.c. */
extern int twth_failures;
extern int twth_checks;

static inline void twth_expect_bytes(const char *name, const uint8_t *want,
                         const uint8_t *got, size_t len) {
  twth_checks++;
  if (memcmp(want, got, len) == 0) return;
  twth_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static inline void twth_expect_int(const char *name, long want, long got) {
  twth_checks++;
  if (want == got) return;
  twth_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* A minimal reader over the built message, written here rather than shared with
 * the parser: a verifier that used the code under test would agree with it.
 *
 * Every function takes the cursor by pointer and moves it explicitly, and there
 * is no arithmetic that mixes a cursor update with a read in one expression.
 * The first three versions of this used `r->offset += n + chr_u16(r)`, which
 * modifies the cursor twice with no sequence point between them -- undefined
 * behaviour that ASan reported as a stack overflow and then as a wild read, and
 * that read like a builder emitting the wrong bytes. */

typedef struct ch_reader {
  const uint8_t *data;
  size_t len;
  size_t offset;
  int failed;
} ch_reader_t;

static inline void chr_init(ch_reader_t *r, const uint8_t *data, size_t len) {
  r->data = data;
  r->len = len;
  r->offset = 0U;
  r->failed = 0;
}

static inline const uint8_t *chr_take(ch_reader_t *r, size_t n) {
  const uint8_t *p;
  if (r->failed || n > r->len - r->offset) {
    r->failed = 1;
    return NULL;
  }
  p = r->data + r->offset;
  r->offset += n;
  return p;
}

static inline uint8_t chr_u8(ch_reader_t *r) {
  const uint8_t *p = chr_take(r, 1U);
  return p == NULL ? 0U : p[0];
}

static inline uint16_t chr_u16(ch_reader_t *r) {
  const uint8_t *p = chr_take(r, 2U);
  return p == NULL ? 0U : (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Skip precisely one field and return its length, so the walk reads the same
 * number of bytes in both passes. `chr_skip` is the only place the cursor moves
 * without producing a value, and every caller uses the value it returns. */
static inline void chr_skip(ch_reader_t *r, size_t n) { (void)chr_take(r, n); }

/* The ClientHello's fixed prefix, leaving the cursor at the extensions block.
 * `out_ext_len` receives that block's length and the cursor is left just past
 * its two-byte length, so the caller can walk the extensions itself. */
static inline void chr_enter_extensions(ch_reader_t *r, uint16_t *out_ext_len) {
  uint8_t session_id_len;
  uint16_t suites_len;
  uint8_t compression_len;

  chr_skip(r, 2U);                 /* legacy_version */
  chr_skip(r, 32U);                /* random */
  session_id_len = chr_u8(r);
  chr_skip(r, session_id_len);     /* legacy_session_id */
  suites_len = chr_u16(r);
  chr_skip(r, suites_len);         /* cipher_suites */
  compression_len = chr_u8(r);
  chr_skip(r, compression_len);    /* legacy_compression_methods */
  *out_ext_len = chr_u16(r);       /* the extensions block's length */
}

/* Find one extension by walking the block from its start. */
static inline const uint8_t *chr_find_extension(const uint8_t *extensions,
                                         size_t extensions_len, uint16_t want,
                                         size_t *out_len) {
  ch_reader_t ext;
  chr_init(&ext, extensions, extensions_len);
  while (ext.offset < ext.len) {
    uint16_t type = chr_u16(&ext);
    uint16_t len = chr_u16(&ext);
    const uint8_t *data = chr_take(&ext, len);
    if (ext.failed) return NULL;
    if (type == want) {
      *out_len = len;
      return data;
    }
  }
  return NULL;
}

/* -------------------------------------------------- EncryptedExtensions */

/* A minimal EncryptedExtensions around a raw extension block. The header says
 * `08 || uint24 body length` and the body is the two-byte list length followed
 * by the list, per RFC 8446 section 4.3.1. Small enough for the tests, which
 * stay under 256 bytes so the length bytes can be written directly; the size is
 * asserted rather than assumed. */
static inline size_t ee_wrap(uint8_t *out, size_t capacity, const uint8_t *extensions,
                      size_t extensions_len) {
  size_t body_len = 2U + extensions_len;
  if (capacity < 4U + body_len || body_len > 0xFFFFFFU) return 0U;
  out[0] = WT_TLS_HS_ENCRYPTED_EXTENSIONS;
  out[1] = (uint8_t)((body_len >> 16) & 0xFFU);
  out[2] = (uint8_t)((body_len >> 8) & 0xFFU);
  out[3] = (uint8_t)(body_len & 0xFFU);
  out[4] = (uint8_t)((extensions_len >> 8) & 0xFFU);
  out[5] = (uint8_t)(extensions_len & 0xFFU);
  if (extensions_len != 0U) memcpy(out + 6U, extensions, extensions_len);
  return 4U + body_len;
}

/* One `type || length || data` extension appended to a block. Returns the new
 * block length. */
static inline size_t ee_ext(uint8_t *out, size_t len, uint16_t type,
                     const uint8_t *data, size_t data_len) {
  out[len + 0U] = (uint8_t)(type >> 8);
  out[len + 1U] = (uint8_t)(type & 0xFFU);
  out[len + 2U] = (uint8_t)(data_len >> 8);
  out[len + 3U] = (uint8_t)(data_len & 0xFFU);
  if (data_len != 0U) memcpy(out + len + 4U, data, data_len);
  return len + 4U + data_len;
}

/* The ClientHello parameters the parser's acceptance rules are checked
 * against: the seven extensions this module's builder emits, and nothing
 * else. `alpn` and the transport parameters are only read for their lengths. */
static inline void ee_offered_params(wt_tls_client_hello_params_t *p,
                              const uint8_t *alpn, size_t alpn_len,
                              const uint8_t *transport, size_t transport_len) {
  static const uint16_t groups[1] = {0x001DU};
  static const uint16_t sigalgs[1] = {0x0804U};
  static const uint16_t suites[1] = {0x1301U};
  static const uint8_t pub[32] = {0};
  static const wt_tls_key_share_t share = {0x001DU, pub, sizeof(pub)};

  memset(p, 0, sizeof(*p));
  p->random = (const uint8_t *)"0123456789abcdef0123456789abcdef";
  p->cipher_suites = suites;
  p->cipher_suite_count = 1U;
  p->key_shares = &share;
  p->key_share_count = 1U;
  p->supported_groups = groups;
  p->supported_group_count = 1U;
  p->signature_algorithms = sigalgs;
  p->signature_algorithm_count = 1U;
  p->server_name = "server";
  p->alpn_protocols = alpn;
  p->alpn_protocols_len = alpn_len;
  p->quic_transport_parameters = transport;
  p->quic_transport_parameters_len = transport_len;
}

/* The test entry points the other two translation units define, called by
 * main in test_wt_tls_handshake.c. */
void twth_test_handshake_framing(void);
void twth_test_client_hello_build(void);
void twth_test_encrypted_extensions(void);
void twth_test_server_hello_parse(void);

#endif /* XAIOS_TEST_WT_TLS_HANDSHAKE_SUPPORT_H */
