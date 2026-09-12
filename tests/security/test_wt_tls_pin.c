/* The pinned-operator-key trust policy.
 *
 * Almost every check here is a refusal, and that is the right proportion: the
 * only way a pinning policy fails dangerously is by accepting something, so the
 * cases worth testing are the ones where the answer must be no -- an unset pin,
 * a cleared pin, a key of the other type, a key with one bit different, a
 * certificate that is not a certificate.
 *
 * The positive case uses RFC 8448's real certificate, and the pin is built from
 * that certificate's own key read back out of it. That is deliberate: a
 * hardcoded modulus in a test can be wrong in the same way the code is wrong, so
 * the key is taken from the DER and then required to match the DER.
 */

#include "wt_tls_pin.h"
#include "wt_rfc8448_vectors.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect_int(const char *name, long want, long got) {
  g_checks++;
  if (want == got) return;
  g_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

static void expect_bytes(const char *name, const uint8_t *want,
                         const uint8_t *got, size_t len) {
  g_checks++;
  if (memcmp(want, got, len) == 0) return;
  g_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

/* RFC 8448's certificate, and its leaf as DER. */
static wt_tls_certificate_chain_t g_chain;

static void test_pin_from_the_certificate(void) {
  wt_tls_public_key_t key;
  wt_tls_pinned_key_t pin;

  expect_int("the RFC's Certificate parses", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE),
                                      &g_chain));
  expect_int("with one entry", 1, (long)g_chain.count);
  expect_int("the entry's key is readable", 0,
             wt_tls_certificate_public_key(g_chain.entries[0],
                                           g_chain.lengths[0], &key));
  expect_int("it is RSA", 1, key.is_rsa);
  expect_int("with a 128-byte modulus", 128, (long)key.rsa.nlen);
  expect_int("and a 3-byte exponent", 3, (long)key.rsa.elen);

  /* --- an unset pin refuses, and says so --- */
  memset(&pin, 0, sizeof(pin));
  expect_int("an unset pin is not set", 0, wt_tls_pinned_key_is_set(&pin));
  expect_int("an unset pin refuses a certificate",
             (long)WT_TLS_PIN_NO_PIN,
             (long)wt_tls_pinned_key_accepts_certificate(
                 &pin, g_chain.entries[0], g_chain.lengths[0]));
  expect_int("an unset pin refuses a key", (long)WT_TLS_PIN_NO_PIN,
             (long)wt_tls_pinned_key_accepts_public_key(&pin, &key));
  expect_int("a NULL pin refuses a certificate",
             (long)WT_TLS_PIN_NO_PIN,
             (long)wt_tls_pinned_key_accepts_certificate(
                 NULL, g_chain.entries[0], g_chain.lengths[0]));
  expect_int("a NULL pin refuses a key", (long)WT_TLS_PIN_NO_PIN,
             (long)wt_tls_pinned_key_accepts_public_key(NULL, &key));
  expect_int("a NULL pin is not set", 0, wt_tls_pinned_key_is_set(NULL));

  /* --- the pinned key itself --- */
  expect_int("pinning the certificate's own key succeeds", 0,
             wt_tls_pinned_key_set_rsa(&pin, key.rsa.n, key.rsa.nlen,
                                       key.rsa.e, key.rsa.elen));
  expect_int("the pin is set", 1, wt_tls_pinned_key_is_set(&pin));
  expect_int("the certificate is accepted", (long)WT_TLS_PIN_ACCEPTED,
             (long)wt_tls_pinned_key_accepts_certificate(
                 &pin, g_chain.entries[0], g_chain.lengths[0]));
  expect_int("and so is the key on its own",
             (long)WT_TLS_PIN_ACCEPTED,
             (long)wt_tls_pinned_key_accepts_public_key(&pin, &key));

  /* --- the same key expressed as hex, which is how an operator supplies it --- */
  {
    wt_tls_pinned_key_t hex_pin;
    char hex[2U * 128U + 1U];
    size_t i;
    static const char digits[] = "0123456789abcdef";
    for (i = 0U; i < 128U; i++) {
      hex[2U * i] = digits[(key.rsa.n[i] >> 4) & 0x0FU];
      hex[2U * i + 1U] = digits[key.rsa.n[i] & 0x0FU];
    }
    hex[256] = '\0';
    expect_int("pinning from hex succeeds", 0,
               wt_tls_pinned_key_set_rsa_hex(&hex_pin, hex, 65537U));
    expect_int("the hex pin accepts the certificate",
               (long)WT_TLS_PIN_ACCEPTED,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &hex_pin, g_chain.entries[0], g_chain.lengths[0]));
    expect_int("and the two pins are the same key", 1,
               wt_tls_public_key_equal(&pin.key, &hex_pin.key));
    expect_int("an uppercase hex string is the same key too", 0,
               wt_tls_pinned_key_set_rsa_hex(&hex_pin, hex, 65537U));
    {
      /* Upper case: the same digits, and the same key. */
      char upper[257];
      memcpy(upper, hex, sizeof(upper));
      for (i = 0U; i < 256U; i++) {
        if (upper[i] >= 'a' && upper[i] <= 'f') {
          upper[i] = (char)(upper[i] - 'a' + 'A');
        }
      }
      expect_int("uppercase hex is accepted", 0,
                 wt_tls_pinned_key_set_rsa_hex(&hex_pin, upper, 65537U));
      expect_int("and names the same key", (long)WT_TLS_PIN_ACCEPTED,
                 (long)wt_tls_pinned_key_accepts_certificate(
                     &hex_pin, g_chain.entries[0], g_chain.lengths[0]));
    }
  }

  /* --- a key with one bit different --- */
  {
    wt_tls_pinned_key_t other;
    uint8_t modulus[WT_TLS_PUBLIC_KEY_MAX];
    memcpy(modulus, key.rsa.n, key.rsa.nlen);
    modulus[64] ^= 0x01U;
    expect_int("pinning a different modulus succeeds", 0,
               wt_tls_pinned_key_set_rsa(&other, modulus, key.rsa.nlen, key.rsa.e,
                                         key.rsa.elen));
    expect_int("a certificate with a different key is refused",
               (long)WT_TLS_PIN_KEY_MISMATCH,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &other, g_chain.entries[0], g_chain.lengths[0]));
  }

  /* --- the same modulus, a different exponent --- */
  {
    wt_tls_pinned_key_t other;
    static uint8_t exponent[3] = {0x01U, 0x00U, 0x03U};
    expect_int("pinning a different exponent succeeds", 0,
               wt_tls_pinned_key_set_rsa(&other, key.rsa.n, key.rsa.nlen,
                                         exponent, sizeof(exponent)));
    expect_int("a different exponent is a different key",
               (long)WT_TLS_PIN_KEY_MISMATCH,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &other, g_chain.entries[0], g_chain.lengths[0]));
  }

  /* --- an EC pin cannot be satisfied by an RSA certificate --- */
  {
    wt_tls_pinned_key_t ec_pin;
    static uint8_t point[65];
    memset(point, 0x01, sizeof(point));
    point[0] = 0x04U;
    expect_int("pinning an EC key succeeds", 0,
               wt_tls_pinned_key_set_ec(&ec_pin, BR_EC_secp256r1, point,
                                        sizeof(point)));
    expect_int("an RSA certificate cannot satisfy an EC pin",
               (long)WT_TLS_PIN_WRONG_KEY_TYPE,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &ec_pin, g_chain.entries[0], g_chain.lengths[0]));
    expect_int("and neither can an RSA key",
               (long)WT_TLS_PIN_WRONG_KEY_TYPE,
               (long)wt_tls_pinned_key_accepts_public_key(&ec_pin, &key));
  }

  /* --- clearing a pin unsets it --- */
  wt_tls_pinned_key_clear(&pin);
  expect_int("a cleared pin is not set", 0, wt_tls_pinned_key_is_set(&pin));
  expect_int("a cleared pin refuses everything",
             (long)WT_TLS_PIN_NO_PIN,
             (long)wt_tls_pinned_key_accepts_certificate(
                 &pin, g_chain.entries[0], g_chain.lengths[0]));
}

static void test_certificate_refusals(void) {
  wt_tls_public_key_t key;
  wt_tls_pinned_key_t pin;

  wt_tls_certificate_public_key(g_chain.entries[0], g_chain.lengths[0], &key);
  expect_int("pin the RFC's key", 0,
             wt_tls_pinned_key_set_rsa(&pin, key.rsa.n, key.rsa.nlen, key.rsa.e,
                                       key.rsa.elen));

  expect_int("a NULL certificate is a bad certificate",
             (long)WT_TLS_PIN_BAD_CERTIFICATE,
             (long)wt_tls_pinned_key_accepts_certificate(&pin, NULL, 100U));
  {
    static const uint8_t not_a_certificate[16] = "not a certifica";
    expect_int("an empty certificate is a bad certificate",
               (long)WT_TLS_PIN_BAD_CERTIFICATE,
               (long)wt_tls_pinned_key_accepts_certificate(&pin,
                                                           not_a_certificate,
                                                           0U));
    expect_int("a non-certificate is a bad certificate",
               (long)WT_TLS_PIN_BAD_CERTIFICATE,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &pin, not_a_certificate, sizeof(not_a_certificate)));
    /* A truncated certificate, which is the shape a peer would send if it were
       trying to make the parser read past the end. */
    expect_int("a truncated certificate is a bad certificate",
               (long)WT_TLS_PIN_BAD_CERTIFICATE,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &pin, g_chain.entries[0], g_chain.lengths[0] / 2U));
  }
  expect_int("a NULL peer key is a bad certificate",
             (long)WT_TLS_PIN_BAD_CERTIFICATE,
             (long)wt_tls_pinned_key_accepts_public_key(&pin, NULL));

  /* --- the setter's refusals leave the pin unset, never half configured --- */
  {
    uint8_t modulus[WT_TLS_PUBLIC_KEY_MAX];
    memcpy(modulus, key.rsa.n, key.rsa.nlen);
    expect_int("a NULL modulus is refused", -1,
               wt_tls_pinned_key_set_rsa(&pin, NULL, 128U, key.rsa.e, 3U));
    expect_int("  and leaves the pin unset", 0, wt_tls_pinned_key_is_set(&pin));
    expect_int("an empty modulus is refused", -1,
               wt_tls_pinned_key_set_rsa(&pin, modulus, 0U, key.rsa.e, 3U));
    expect_int("  and leaves the pin unset", 0, wt_tls_pinned_key_is_set(&pin));
    expect_int("a NULL exponent is refused", -1,
               wt_tls_pinned_key_set_rsa(&pin, modulus, 128U, NULL, 3U));
    expect_int("  and leaves the pin unset", 0, wt_tls_pinned_key_is_set(&pin));
    expect_int("an empty exponent is refused", -1,
               wt_tls_pinned_key_set_rsa(&pin, modulus, 128U, key.rsa.e, 0U));
    expect_int("  and leaves the pin unset", 0, wt_tls_pinned_key_is_set(&pin));
    {
      /* A leading zero byte: the padded form of the same number. Refused so
         that one key has one byte string, which is what makes a byte
         comparison a key comparison. */
      uint8_t padded[129];
      padded[0] = 0x00U;
      memcpy(padded + 1U, key.rsa.n, 128U);
      expect_int("a leading zero byte is refused", -1,
                 wt_tls_pinned_key_set_rsa(&pin, padded, sizeof(padded),
                                           key.rsa.e, 3U));
      expect_int("  and leaves the pin unset", 0,
                 wt_tls_pinned_key_is_set(&pin));
    }
    {
      uint8_t too_big[WT_TLS_PUBLIC_KEY_MAX + 1U];
      memset(too_big, 0x80, sizeof(too_big));
      expect_int("a modulus that does not fit is refused", -1,
                 wt_tls_pinned_key_set_rsa(&pin, too_big, sizeof(too_big),
                                           key.rsa.e, 3U));
      expect_int("  and leaves the pin unset", 0,
                 wt_tls_pinned_key_is_set(&pin));
    }
    expect_int("a NULL hex string is refused", -1,
               wt_tls_pinned_key_set_rsa_hex(&pin, NULL, 65537U));
    expect_int("an empty hex string is refused", -1,
               wt_tls_pinned_key_set_rsa_hex(&pin, "", 65537U));
    expect_int("an odd-length hex string is refused", -1,
               wt_tls_pinned_key_set_rsa_hex(&pin, "abc", 65537U));
    expect_int("a non-hex character is refused", -1,
               wt_tls_pinned_key_set_rsa_hex(&pin, "zz", 65537U));
    expect_int("a zero exponent is refused", -1,
               wt_tls_pinned_key_set_rsa_hex(&pin, "abcd", 0U));
    expect_int("  and leaves the pin unset", 0, wt_tls_pinned_key_is_set(&pin));
    /* A hex string longer than the key buffer. */
    {
      char huge[2U * (WT_TLS_PUBLIC_KEY_MAX + 4U) + 1U];
      memset(huge, 'a', sizeof(huge) - 1U);
      huge[sizeof(huge) - 1U] = '\0';
      expect_int("a hex string that does not fit is refused", -1,
                 wt_tls_pinned_key_set_rsa_hex(&pin, huge, 65537U));
    }
  }

  /* --- a NULL pin argument to a setter --- */
  expect_int("a NULL pin cannot be set", -1,
             wt_tls_pinned_key_set_rsa(NULL, key.rsa.n, key.rsa.nlen, key.rsa.e,
                                       3U));
  expect_int("a NULL pin cannot be set from hex", -1,
             wt_tls_pinned_key_set_rsa_hex(NULL, "abcd", 65537U));
  expect_int("a NULL pin cannot be set to EC", -1,
             wt_tls_pinned_key_set_ec(NULL, BR_EC_secp256r1, NULL, 0U));
}

static void test_ec_keys(void) {
  wt_tls_pinned_key_t pin;
  wt_tls_public_key_t a;
  wt_tls_public_key_t b;
  uint8_t point_a[65];
  uint8_t point_b[65];
  size_t i;

  for (i = 0U; i < 65U; i++) {
    point_a[i] = (uint8_t)i;
    point_b[i] = (uint8_t)i;
  }
  point_a[0] = 0x04U;
  point_b[0] = 0x04U;

  expect_int("build an EC key", 0,
             wt_tls_public_key_set_ec(&a, BR_EC_secp256r1, point_a,
                                      sizeof(point_a)));
  expect_int("it is not RSA", 0, a.is_rsa);
  expect_int("with the curve recorded", BR_EC_secp256r1, a.ec.curve);
  expect_int("and the point readable", 1, a.ec.qlen == sizeof(point_a) ? 1 : 0);
  expect_bytes("the point bytes are the ones supplied", point_a, a.ec.q,
               sizeof(point_a));

  point_b[64] ^= 0x01U;
  expect_int("build a different EC key", 0,
             wt_tls_public_key_set_ec(&b, BR_EC_secp256r1, point_b,
                                      sizeof(point_b)));
  expect_int("two different points are different keys", 0,
             wt_tls_public_key_equal(&a, &b));
  expect_int("a key equals itself", 1, wt_tls_public_key_equal(&a, &a));

  /* The same point on a different curve is a different key. */
  {
    wt_tls_public_key_t c;
    expect_int("build the same point on another curve", 0,
               wt_tls_public_key_set_ec(&c, BR_EC_secp384r1, point_a,
                                        sizeof(point_a)));
    expect_int("the same point on another curve is a different key", 0,
               wt_tls_public_key_equal(&a, &c));
  }

  /* An EC key and an RSA key are never equal. */
  {
    wt_tls_public_key_t rsa;
    expect_int("build an RSA key with the same bytes", 0,
               wt_tls_public_key_set_rsa(&rsa, point_a, 32U, point_a + 32U,
                                         32U));
    expect_int("an EC key and an RSA key are different", 0,
               wt_tls_public_key_equal(&a, &rsa));
  }

  /* --- the pin, on the EC path --- */
  expect_int("pin the EC key", 0,
             wt_tls_pinned_key_set_ec(&pin, BR_EC_secp256r1, point_a,
                                      sizeof(point_a)));
  expect_int("the EC key is accepted", (long)WT_TLS_PIN_ACCEPTED,
             (long)wt_tls_pinned_key_accepts_public_key(&pin, &a));
  expect_int("a different point is a mismatch",
             (long)WT_TLS_PIN_KEY_MISMATCH,
             (long)wt_tls_pinned_key_accepts_public_key(&pin, &b));
  expect_int("a NULL point is refused", -1,
             wt_tls_pinned_key_set_ec(&pin, BR_EC_secp256r1, NULL, 65U));
  expect_int("an empty point is refused", -1,
             wt_tls_pinned_key_set_ec(&pin, BR_EC_secp256r1, point_a, 0U));
  expect_int("a negative curve is refused", -1,
             wt_tls_pinned_key_set_ec(&pin, -1, point_a, sizeof(point_a)));

  /* --- and the unset-key rules still hold on this path --- */
  expect_int("an all-zero key is not equal to a real one", 0,
             wt_tls_public_key_equal(&a, NULL));
  {
    wt_tls_public_key_t empty;
    memset(&empty, 0, sizeof(empty));
    expect_int("an unset key equals nothing", 0,
               wt_tls_public_key_equal(&a, &empty));
    expect_int("and nothing equals an unset key", 0,
               wt_tls_public_key_equal(&empty, &a));
  }
}

int main(void) {
  memset(&g_chain, 0, sizeof(g_chain));

  test_pin_from_the_certificate();
  test_certificate_refusals();
  test_ec_keys();

  if (g_failures != 0) {
    printf("wt_tls_pin: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls_pin: all %d checks held the pinned-key policy\n", g_checks);
  return 0;
}
