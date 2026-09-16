/* The OpenSSL 3.x backend for webtransport/crypto/crypto.h.
 *
 * One file, and it is the only file in this project that includes an OpenSSL
 * header. Everything above it -- QUIC packet protection, the TLS key schedule,
 * QPACK -- calls the functions declared in crypto.h, so replacing this file is
 * the whole of a backend change.
 *
 * THE PROVIDER IS NAMED EXPLICITLY IN ONE PLACE. OpenSSL 3 fetches algorithms
 * from a provider, and a build with the default provider missing would fail at
 * the first use rather than at the call that needed it; `wt_crypto_init` fetches
 * what this file uses so that a machine without the default provider says so
 * once, at start-up, instead of in the middle of a handshake.
 *
 * THE CONTEXT SIZE IS ASSERTED, not assumed. `wt_sha256_ctx_t` is a caller-owned
 * byte array, so a backend structure that outgrew it would corrupt a caller's
 * stack; the assertion below turns that into a build failure in this file, where
 * the size and the structure are both visible.
 */

#include "webtransport/crypto/crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <string.h>

/* The EVP context is the largest thing a caller-owned hash context has to hold,
 * and this is where that is checked. */
typedef struct wt_openssl_sha256_ctx {
  /* A marker written last by init and cleared by final, so that a context that
   * was never initialised -- which is a caller's uninitialised stack array -- can
   * be recognised without reading the pointer beside it. Without the marker the
   * only test is on `ctx`, and an uninitialised pointer is not NULL often enough
   * to be worth the crash inside libcrypto when it is not. */
  uint64_t live;
  EVP_MD_CTX *ctx;
} wt_openssl_sha256_ctx_t;

/* An arbitrary constant. Its value is not a checksum of anything; it only has to
 * be a value that a zeroed or garbage context is unlikely to hold. */
#define WT_OPENSSL_SHA256_LIVE UINT64_C(0x9e3779b97f4a7c15)

/* A context pointer fits the caller's array by construction: the array is
 * aligned to uint64_t and is at least as large as a pointer. The assertion is
 * about the assumption, so that a future backend that stores the EVP_MD_CTX by
 * value fails here rather than in a caller. */
typedef char wt_sha256_ctx_fits
    [sizeof(wt_openssl_sha256_ctx_t) <= sizeof(wt_sha256_ctx_t) ? 1 : -1];

/* OpenSSL's OSSL_PARAM_construct_octet_string takes a `void *` although it only
 * reads the bytes it is given, and its digest name parameter takes a `char *`
 * although it only reads that too. The cast is therefore required and is the
 * library's shape rather than a permission this code takes: nothing here writes
 * through the result. Casting through uintptr_t is what `-Wcast-qual` accepts,
 * which is why the compiler is told the intent rather than silenced. */
static void *wt_openssl_param_bytes(const void *bytes) {
  return (void *)(uintptr_t)bytes;
}

static char *wt_openssl_param_name(const char *name) {
  return (char *)(uintptr_t)name;
}

const char *wt_aead_name(wt_aead_t aead) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
      return "aes-128-gcm";
    case WT_AEAD_CHACHA20_POLY1305:
      return "chacha20-poly1305";
    default:
      return "unknown";
  }
}

size_t wt_aead_key_len(wt_aead_t aead) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
      return 16U;
    case WT_AEAD_CHACHA20_POLY1305:
      return 32U;
    default:
      return 0U;
  }
}

size_t wt_aead_iv_len(wt_aead_t aead) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
    case WT_AEAD_CHACHA20_POLY1305:
      return WT_AEAD_IV_LEN;
    default:
      return 0U;
  }
}

size_t wt_aead_tag_len(wt_aead_t aead) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
    case WT_AEAD_CHACHA20_POLY1305:
      return WT_AEAD_TAG_LEN;
    default:
      return 0U;
  }
}

static const EVP_CIPHER *wt_aead_cipher(wt_aead_t aead) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
      return EVP_aes_128_gcm();
    case WT_AEAD_CHACHA20_POLY1305:
      return EVP_chacha20_poly1305();
    default:
      return NULL;
  }
}

wt_status_t wt_crypto_init(void) {
  /* OpenSSL 3 fetches algorithms lazily from the default provider. Touching one
   * here means a machine whose provider is missing fails at start-up with a
   * message about the provider, rather than inside a handshake with a message
   * about a digest. */
  if (EVP_sha256() == NULL) return WT_ERR_UNSUPPORTED;
  if (EVP_aes_128_gcm() == NULL) return WT_ERR_UNSUPPORTED;
  return WT_OK;
}

/* --------------------------------------------------------------- SHA-256 */

wt_status_t wt_sha256_init(wt_sha256_ctx_t *ctx) {
  wt_openssl_sha256_ctx_t *impl;
  if (ctx == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A context that was already initialised and not finalised would leak its
   * EVP_MD_CTX: the pointer to it is in the caller's array and there is no way to
   * know whether it is still a pointer. The marker is therefore cleared first, so
   * that re-initialising a live context leaks predictably rather than freeing a
   * pointer twice, and it is set last, so that a failure below leaves the context
   * unmistakably dead.
   *
   * The view is taken AFTER the clear, which is the only place it can be taken: the
   * memset wipes the storage the pointer points into. This was written as an
   * assignment before the clear as well, which the Clang Static Analyzer reported as
   * a dead store -- the value was overwritten without ever being read (WT-176). */
  memset(ctx, 0, sizeof(*ctx));
  impl = (wt_openssl_sha256_ctx_t *)(void *)ctx->storage;
  impl->ctx = EVP_MD_CTX_new();
  if (impl->ctx == NULL) return WT_ERR_OUT_OF_MEMORY;
  if (EVP_DigestInit_ex(impl->ctx, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(impl->ctx);
    impl->ctx = NULL;
    return WT_ERR_UNSUPPORTED;
  }
  impl->live = WT_OPENSSL_SHA256_LIVE;
  return WT_OK;
}

wt_status_t wt_sha256_update(wt_sha256_ctx_t *ctx, const void *data,
                             size_t len) {
  wt_openssl_sha256_ctx_t *impl;
  if (ctx == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len != 0U && data == NULL) return WT_ERR_INVALID_ARGUMENT;
  impl = (wt_openssl_sha256_ctx_t *)(void *)ctx->storage;
  /* Checked before the pointer is read: an uninitialised context holds neither. */
  if (impl->live != WT_OPENSSL_SHA256_LIVE || impl->ctx == NULL) {
    return WT_ERR_STATE;
  }
  if (len == 0U) return WT_OK;
  if (EVP_DigestUpdate(impl->ctx, data, len) != 1) return WT_ERR_UNSUPPORTED;
  return WT_OK;
}

wt_status_t wt_sha256_final(wt_sha256_ctx_t *ctx, uint8_t out[WT_SHA256_LEN]) {
  wt_openssl_sha256_ctx_t *impl;
  unsigned int written = 0U;
  if (ctx == NULL) return WT_ERR_INVALID_ARGUMENT;
  impl = (wt_openssl_sha256_ctx_t *)(void *)ctx->storage;
  if (impl->live != WT_OPENSSL_SHA256_LIVE || impl->ctx == NULL) {
    return WT_ERR_STATE;
  }
  if (EVP_DigestFinal_ex(impl->ctx, out, &written) != 1) {
    EVP_MD_CTX_free(impl->ctx);
    impl->ctx = NULL;
    memset(ctx, 0, sizeof(*ctx));
    return WT_ERR_UNSUPPORTED;
  }
  EVP_MD_CTX_free(impl->ctx);
  impl->ctx = NULL;
  /* The context held the message so far, which for a transcript is the
   * handshake. It is cleared rather than left for the next user of the frame. */
  memset(ctx, 0, sizeof(*ctx));
  return (written == WT_SHA256_LEN) ? WT_OK : WT_ERR_UNSUPPORTED;
}

wt_status_t wt_sha256(const void *data, size_t len,
                      uint8_t out[WT_SHA256_LEN]) {
  unsigned int written = 0U;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len != 0U && data == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (EVP_Digest(data, len, out, &written, EVP_sha256(), NULL) != 1) {
    return WT_ERR_UNSUPPORTED;
  }
  return (written == WT_SHA256_LEN) ? WT_OK : WT_ERR_UNSUPPORTED;
}

wt_status_t wt_sha256_snapshot(const wt_sha256_ctx_t *ctx,
                               uint8_t out[WT_SHA256_LEN]) {
  const wt_openssl_sha256_ctx_t *impl;
  EVP_MD_CTX *copy;
  unsigned int written = 0U;
  int ok;

  if (ctx == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  impl = (const wt_openssl_sha256_ctx_t *)(const void *)ctx->storage;
  if (impl->live != WT_OPENSSL_SHA256_LIVE || impl->ctx == NULL) {
    return WT_ERR_STATE;
  }
  /* EVP_MD_CTX_copy_ex is the backend's own way of saying "the same hash over the
   * same bytes so far, without disturbing it", which is exactly the operation the
   * transcript needs and the reason the context is a backend structure rather than
   * a caller-visible one. */
  copy = EVP_MD_CTX_new();
  if (copy == NULL) return WT_ERR_OUT_OF_MEMORY;
  ok = EVP_MD_CTX_copy_ex(copy, impl->ctx) == 1 &&
       EVP_DigestFinal_ex(copy, out, &written) == 1 &&
       written == WT_SHA256_LEN;
  EVP_MD_CTX_free(copy);
  if (!ok) {
    memset(out, 0, WT_SHA256_LEN);
    return WT_ERR_UNSUPPORTED;
  }
  return WT_OK;
}

/* ------------------------------------------------------------ HMAC, HKDF */

/* HMAC-SHA256 over up to three pieces. The HKDF expansion needs it because its
 * message is T(n-1) | info | n and `info` is the caller's length; writing it with
 * the streaming MAC means no buffer has to be allocated for it, and no caller's
 * length has to be bounded. */
static wt_status_t wt_hmac_sha256_parts(const uint8_t *key, size_t key_len,
                                       const uint8_t *first, size_t first_len,
                                       const uint8_t *second, size_t second_len,
                                       const uint8_t *third, size_t third_len,
                                       uint8_t out[WT_SHA256_LEN]) {
  EVP_MAC *mac;
  EVP_MAC_CTX *ctx;
  OSSL_PARAM params[2];
  size_t written = 0U;
  int ok;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (key == NULL && key_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (first == NULL && first_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (second == NULL && second_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (third == NULL && third_len != 0U) return WT_ERR_INVALID_ARGUMENT;

  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (mac == NULL) return WT_ERR_UNSUPPORTED;
  ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  if (ctx == NULL) return WT_ERR_OUT_OF_MEMORY;

  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                               wt_openssl_param_name("SHA256"),
                                               0);
  params[1] = OSSL_PARAM_construct_end();
  ok = EVP_MAC_init(ctx, key, key_len, params) == 1 &&
       (first_len == 0U || EVP_MAC_update(ctx, first, first_len) == 1) &&
       (second_len == 0U || EVP_MAC_update(ctx, second, second_len) == 1) &&
       (third_len == 0U || EVP_MAC_update(ctx, third, third_len) == 1) &&
       EVP_MAC_final(ctx, out, &written, WT_SHA256_LEN) == 1;
  EVP_MAC_CTX_free(ctx);
  if (!ok || written != WT_SHA256_LEN) {
    memset(out, 0, WT_SHA256_LEN);
    return WT_ERR_UNSUPPORTED;
  }
  return WT_OK;
}

wt_status_t wt_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[WT_SHA256_LEN]) {
  /* The one-shot OpenSSL HMAC, which handles a key longer than the block size
   * the way RFC 2104 requires. RFC 4231's vectors, including the 131-byte key,
   * are what check it. */
  unsigned int written = 0U;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (key == NULL && key_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && data_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &written) ==
      NULL) {
    return WT_ERR_UNSUPPORTED;
  }
  return (written == WT_SHA256_LEN) ? WT_OK : WT_ERR_UNSUPPORTED;
}

wt_status_t wt_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *ikm, size_t ikm_len,
                                   uint8_t out[WT_SHA256_LEN]) {
  /* RFC 5869 section 2.2 defines extract as HMAC with the salt as the key, and
   * an absent salt as HashLen zero bytes. Writing it as the HMAC it is avoids
   * two things at once: a dependency on OpenSSL's HKDF interface, which has
   * changed shape across versions, and any chance of the "no salt" and
   * "zero salt" cases being confused -- an all-zero key of the right length is
   * exactly what HMAC does with a zero-length key anyway, and saying so here
   * makes it checkable. */
  uint8_t zero_salt[WT_SHA256_LEN];
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (salt == NULL) {
    if (salt_len != 0U) return WT_ERR_INVALID_ARGUMENT;
    memset(zero_salt, 0, sizeof(zero_salt));
    return wt_hmac_sha256(zero_salt, sizeof(zero_salt), ikm, ikm_len, out);
  }
  return wt_hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

wt_status_t wt_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *out, size_t out_len) {
  /* RFC 5869 section 2.3, written as the HMAC chain it is:
   *
   *   T(0) = empty
   *   T(n) = HMAC-Hash(PRK, T(n-1) | info | n)
   *   OKM  = first L bytes of T(1) | T(2) | ...
   *
   * The alternative is OpenSSL's HKDF through EVP_KDF, and it was tried and
   * removed: its "mode" parameter is an integer whose encoding is not the one the
   * TLS 1.3 code in the same library uses for the same word, and getting it wrong
   * produces a KDF that fails rather than one that derives the wrong bytes. The
   * chain above is four lines of arithmetic that RFC 5869's own test vectors
   * check directly, and it shares the HMAC with the extract step so that both
   * halves of HKDF cannot disagree about what the hash is. */
  uint8_t block[WT_SHA256_LEN];
  size_t done = 0U;
  unsigned int counter = 1U;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (prk == NULL || prk_len == 0U) return WT_ERR_INVALID_ARGUMENT;
  if (info == NULL && info_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 5869 section 2.3: the counter is one byte, so the output cannot exceed
   * 255 blocks. A longer request would wrap the counter and produce a stream
   * that is not HKDF's; refusing is the only answer that is not a silent lie. */
  if (out_len > 255U * WT_SHA256_LEN) return WT_ERR_INVALID_ARGUMENT;
  if (out_len == 0U) return WT_OK;

  memset(block, 0, sizeof(block));
  while (done < out_len) {
    uint8_t counter_byte = (uint8_t)counter;
    size_t take;
    wt_status_t status = wt_hmac_sha256_parts(
        prk, prk_len, block, (counter == 1U) ? 0U : sizeof(block), info,
        info_len, &counter_byte, 1U, block);
    if (status != WT_OK) {
      wt_secure_zero(block, sizeof(block));
      return status;
    }
    take = out_len - done;
    if (take > sizeof(block)) take = sizeof(block);
    memcpy(out + done, block, take);
    done += take;
    counter++;
  }
  wt_secure_zero(block, sizeof(block));
  return WT_OK;
}

wt_status_t wt_hkdf_expand_label_sha256(const uint8_t *secret,
                                        size_t secret_len, const char *label,
                                        const uint8_t *context,
                                        size_t context_len, uint8_t *out,
                                        size_t out_len) {
  /* RFC 8446 section 7.1:
   *
   *   struct {
   *       uint16 length = Length;
   *       opaque label<7..255> = "tls13 " + Label;
   *       opaque context<0..255> = Context;
   *   } HkdfLabel;
   *
   * The structure is built here rather than delegated, because it is three
   * length prefixes and it is the part of the schedule a caller gets wrong: the
   * "tls13 " prefix is required, the context is length-prefixed even when it is
   * empty, and the length is the OUTPUT length rather than the secret's. */
  uint8_t info[2U + 1U + 255U + 1U + 255U];
  size_t offset = 0U;
  size_t label_len;
  static const char prefix[] = "tls13 ";

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (secret == NULL || label == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (context == NULL && context_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (out_len > 65535U) return WT_ERR_INVALID_ARGUMENT;
  label_len = strlen(label);
  /* "tls13 " is six bytes and the length prefix requires at least seven, so a
   * label longer than 249 bytes does not fit its own field. */
  if (label_len > 249U) return WT_ERR_INVALID_ARGUMENT;
  if (context_len > 255U) return WT_ERR_INVALID_ARGUMENT;

  info[offset++] = (uint8_t)((out_len >> 8) & 0xFFU);
  info[offset++] = (uint8_t)(out_len & 0xFFU);
  info[offset++] = (uint8_t)(sizeof(prefix) - 1U + label_len);
  memcpy(info + offset, prefix, sizeof(prefix) - 1U);
  offset += sizeof(prefix) - 1U;
  memcpy(info + offset, label, label_len);
  offset += label_len;
  info[offset++] = (uint8_t)context_len;
  if (context_len != 0U) {
    memcpy(info + offset, context, context_len);
    offset += context_len;
  }
  return wt_hkdf_expand_sha256(secret, secret_len, info, offset, out, out_len);
}

/* ------------------------------------------------------------------ AEAD */

static wt_status_t wt_aead_run(wt_aead_t aead, int encrypt, const uint8_t *key,
                               const uint8_t *iv, const uint8_t *aad,
                               size_t aad_len, const uint8_t *in, size_t len,
                               const uint8_t *tag, uint8_t *out,
                               uint8_t out_tag[WT_AEAD_TAG_LEN]) {
  const EVP_CIPHER *cipher = wt_aead_cipher(aead);
  EVP_CIPHER_CTX *ctx;
  /* Finalisation writes nothing for either of these AEADs -- neither has padding
   * -- but OpenSSL is given a real buffer to write it into rather than
   * `out + len`, which would be pointer arithmetic on NULL for a zero-length
   * message. */
  uint8_t tail[WT_AEAD_TAG_LEN];
  int written = 0;
  wt_status_t status = WT_ERR_UNSUPPORTED;

  if (cipher == NULL || key == NULL || iv == NULL || tag == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (aad == NULL && aad_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (in == NULL && len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (out == NULL && len != 0U) return WT_ERR_INVALID_ARGUMENT;

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return WT_ERR_OUT_OF_MEMORY;

  if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, WT_AEAD_IV_LEN, NULL) !=
      1) {
    goto done;
  }
  if (EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt) != 1) goto done;
  if (aad_len != 0U) {
    if (EVP_CipherUpdate(ctx, NULL, &written, aad, (int)aad_len) != 1) goto done;
  }
  if (len != 0U) {
    if (EVP_CipherUpdate(ctx, out, &written, in, (int)len) != 1) goto done;
  }
  if (encrypt) {
    /* Finalisation authenticates nothing on this path: it flushes the last
     * partial block and the tag is read out afterwards. */
    if (EVP_CipherFinal_ex(ctx, tail, &written) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, WT_AEAD_TAG_LEN,
                            out_tag) != 1) {
      goto done;
    }
    status = WT_OK;
  } else {
    /* The peer's tag is handed to OpenSSL before finalisation, which is the only
     * order in which it verifies one: finalisation then either succeeds, meaning
     * the tag was right, or fails, meaning it was not. OpenSSL's own comparison
     * is constant time and is not re-implemented here.
     *
     * The tag pointer is const and OpenSSL's ctrl takes a `void *` it only reads;
     * the cast goes through uintptr_t for the reason given at
     * wt_openssl_param_bytes above. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, WT_AEAD_TAG_LEN,
                            wt_openssl_param_bytes(tag)) != 1) {
      goto done;
    }
    if (EVP_CipherFinal_ex(ctx, tail, &written) != 1) {
      /* Final failing here is the tag not verifying. Any other failure would
       * have been reported by the calls above, so this is not a catch-all. */
      status = WT_ERR_AUTHENTICATION;
      goto done;
    }
    status = WT_OK;
  }

done:
  EVP_CIPHER_CTX_free(ctx);
  return status;
}

wt_status_t wt_aead_seal(wt_aead_t aead, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plain, size_t len, uint8_t *out,
                         uint8_t tag[WT_AEAD_TAG_LEN]) {
  /* `tag` is an output only on this path; it fills the input slot as well so
   * that there is one NULL check for both directions, in wt_aead_run. */
  return wt_aead_run(aead, 1, key, iv, aad, aad_len, plain, len, tag, out, tag);
}

wt_status_t wt_aead_open(wt_aead_t aead, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *cipher, size_t len,
                         const uint8_t tag[WT_AEAD_TAG_LEN], uint8_t *out) {
  uint8_t unused[WT_AEAD_TAG_LEN];
  wt_status_t status = wt_aead_run(aead, 0, key, iv, aad, aad_len, cipher, len,
                                   tag, out, unused);
  wt_secure_zero(unused, sizeof(unused));
  /* A failed open leaves whatever the cipher produced in `out` before it
   * discovered the tag was wrong. Clearing it here is what makes the return
   * value the only usable output, which the header promises. */
  if (status == WT_ERR_AUTHENTICATION && len != 0U) wt_secure_zero(out, len);
  return status;
}

/* ------------------------------------------------- header protection parts */

wt_status_t wt_aes128_ecb_encrypt_block(const uint8_t key[16],
                                        const uint8_t in[16], uint8_t out[16]) {
  EVP_CIPHER_CTX *ctx;
  int written = 0;
  int ok;

  if (key == NULL || in == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return WT_ERR_OUT_OF_MEMORY;
  /* Padding is disabled because QUIC's header protection encrypts exactly one
   * 16-byte block. A backend left to pad would append a block; a caller that
   * read the first sixteen bytes would then be reading the right answer by
   * accident, which is worse than being wrong. */
  ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
       EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
       EVP_EncryptUpdate(ctx, out, &written, in, 16) == 1 &&
       EVP_EncryptFinal_ex(ctx, out + written, &written) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok ? WT_OK : WT_ERR_UNSUPPORTED;
}

wt_status_t wt_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t *in, size_t len,
                            uint8_t *out) {
  EVP_CIPHER_CTX *ctx;
  uint8_t counter_bytes[16];
  int written = 0;
  int ok;

  if (key == NULL || nonce == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (in == NULL && len != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* OpenSSL's ChaCha20 takes the counter as the first four bytes of a 16-byte
   * IV, little-endian, followed by the 12-byte nonce. Getting that layout wrong
   * produces a keystream that is right for the first block and wrong after it,
   * which is why the ChaCha20 header protection in RFC 9001 section 5.4.4 is
   * tested against the RFC's own sample. */
  counter_bytes[0] = (uint8_t)(counter & 0xFFU);
  counter_bytes[1] = (uint8_t)((counter >> 8) & 0xFFU);
  counter_bytes[2] = (uint8_t)((counter >> 16) & 0xFFU);
  counter_bytes[3] = (uint8_t)((counter >> 24) & 0xFFU);
  memcpy(counter_bytes + 4U, nonce, 12U);

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return WT_ERR_OUT_OF_MEMORY;
  ok = EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, counter_bytes) == 1 &&
       (len == 0U || EVP_EncryptUpdate(ctx, out, &written, in, (int)len) == 1);
  EVP_CIPHER_CTX_free(ctx);
  return ok ? WT_OK : WT_ERR_UNSUPPORTED;
}

/* ------------------------------------------------------ comparison, zeros */

int wt_ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t difference = 0U;
  size_t i;
  if (a == NULL || b == NULL) return 0;
  /* The whole buffer is always read. A loop that returned early would tell an
   * attacker how many leading bytes it had guessed correctly, which is a forgery
   * oracle for a tag and a key-recovery aid for a shared secret. */
  for (i = 0U; i < len; i++) {
    difference = (uint8_t)(difference | (a[i] ^ b[i]));
  }
  return difference == 0U;
}

void wt_secure_zero(void *buffer, size_t len) {
  if (buffer == NULL || len == 0U) return;
  /* OPENSSL_cleanse is the backend's guaranteed-not-optimised zero. Writing a
   * volatile loop here would be a second implementation of the same thing and
   * would not be better. */
  OPENSSL_cleanse(buffer, len);
}

wt_status_t wt_random_bytes(uint8_t *out, size_t len) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len == 0U) return WT_OK;
  /* RAND_bytes taking an int is the backend's shape; a length that does not fit
   * is refused rather than truncated to one that does. */
  if (len > (size_t)INT32_MAX) return WT_ERR_INVALID_ARGUMENT;
  if (RAND_bytes(out, (int)len) != 1) return WT_ERR_UNSUPPORTED;
  return WT_OK;
}
