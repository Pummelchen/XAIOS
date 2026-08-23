#include <bearssl.h>
#include <xaios_user.h>

#include "xapt_tls.h"
#include "xapt_trust_anchors.h"

#define XAPT_TLS_RSA_BYTES 256U

/* br_x509_minimal_set_time counts days from year 0; the realtime clock counts
   from 1970. This is the offset between the two in the Gregorian calendar. */
#define XAPT_TLS_EPOCH_DAYS UINT32_C(719528)
#define XAPT_TLS_SECONDS_PER_DAY UINT64_C(86400)

/* An unset clock reads as 1970, which would make every certificate look
   not-yet-valid. Refuse instead of reporting a confusing expiry failure;
   2025-01-01 is comfortably before any certificate this client will meet. */
#define XAPT_TLS_MIN_EPOCH_SECONDS UINT64_C(1735689600)

static br_ssl_client_context g_client;
static br_x509_minimal_context g_minimal;
static br_x509_knownkey_context g_knownkey;
static br_sslio_context g_io;
static unsigned char g_io_buffer[BR_SSL_BUFSIZE_BIDI];
static unsigned char g_modulus[XAPT_TLS_RSA_BYTES];
static unsigned char g_exponent[3] = {1U, 0U, 1U};
static u64 g_socket;
static u64 g_deadline;
static int g_error;

static int hex_digit(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_modulus(const char *text) {
  for (u32 i = 0U; i < XAPT_TLS_RSA_BYTES; ++i) {
    int high = hex_digit(text[i * 2U]);
    int low = hex_digit(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return -1;
    g_modulus[i] = (unsigned char)((high << 4) | low);
  }
  return text[XAPT_TLS_RSA_BYTES * 2U] == '\0' ? 0 : -1;
}

static int socket_read(void *context, unsigned char *data, size_t size) {
  (void)context;
  if (size > 4096U) size = 4096U;
  while (xaios_clock_nanos() < g_deadline) {
    u64 received = 0U;
    int status = xaios_net_recv(g_socket, data, size, &received);
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0) return -1;
    if (received != 0U) return (int)received;
  }
  return -1;
}

static int socket_write(void *context, const unsigned char *data,
                        size_t size) {
  u64 offset = 0U;
  (void)context;
  while (offset < size && xaios_clock_nanos() < g_deadline) {
    u64 sent = 0U;
    int status = xaios_net_send(g_socket, data + offset, size - offset, &sent);
    if (status == XAIOS_ERR_BUSY) continue;
    if (status != 0 || sent == 0U) return -1;
    offset += sent;
  }
  return offset == size ? (int)size : -1;
}

/* Validate the presented chain against the compiled-in roots, including the
   server name and the validity window. Used for publicly issued certificates,
   which are reissued with a fresh key long before an image is rebuilt. */
static int use_chain_validation(void) {
  u64 epoch_seconds =
      xaios_clock_nanos_kind(XAIOS_CLOCK_REALTIME) / UINT64_C(1000000000);
  if (epoch_seconds < XAPT_TLS_MIN_EPOCH_SECONDS) {
    g_error = 83;
    return -1;
  }
  br_x509_minimal_init(&g_minimal, &br_sha256_vtable, XAPT_TRUST_ANCHORS,
                       XAPT_TRUST_ANCHORS_COUNT);
  br_x509_minimal_set_hash(&g_minimal, br_sha256_ID, &br_sha256_vtable);
  br_x509_minimal_set_hash(&g_minimal, br_sha384_ID, &br_sha384_vtable);
  br_x509_minimal_set_hash(&g_minimal, br_sha512_ID, &br_sha512_vtable);
  br_x509_minimal_set_rsa(&g_minimal, br_rsa_pkcs1_vrfy_get_default());
  br_x509_minimal_set_ecdsa(&g_minimal, br_ec_get_default(),
                            br_ecdsa_vrfy_asn1_get_default());
  br_x509_minimal_set_time(
      &g_minimal,
      (uint32_t)(epoch_seconds / XAPT_TLS_SECONDS_PER_DAY) + XAPT_TLS_EPOCH_DAYS,
      (uint32_t)(epoch_seconds % XAPT_TLS_SECONDS_PER_DAY));
  br_ssl_engine_set_x509(&g_client.eng, &g_minimal.vtable);
  return 0;
}

/* Accept exactly one leaf public key and ignore the rest of the certificate.
   Used for private deployments whose key is long-lived and whose certificate
   is reachable only by address, where no public chain exists to validate. */
static int use_pinned_key(const char *rsa_modulus_hex) {
  br_rsa_public_key key;
  if (parse_modulus(rsa_modulus_hex) != 0) {
    g_error = 80;
    return -1;
  }
  key.n = g_modulus;
  key.nlen = sizeof(g_modulus);
  key.e = g_exponent;
  key.elen = sizeof(g_exponent);
  br_x509_knownkey_init_rsa(&g_knownkey, &key, BR_KEYTYPE_SIGN);
  br_ssl_engine_set_x509(&g_client.eng, &g_knownkey.vtable);
  return 0;
}

int xapt_tls_open(u64 socket, const char *server_name,
                  const char *rsa_modulus_hex) {
  static const uint16_t suites[] = {
      BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
  int pinned = rsa_modulus_hex != 0 && rsa_modulus_hex[0] != '\0';
  unsigned char entropy[32];
  g_error = 0;
  if (server_name == 0) {
    g_error = 80;
    return -1;
  }
  if (xaios_random(entropy, sizeof(entropy)) != 0) {
    g_error = 81;
    return -1;
  }
  g_socket = socket;
  g_deadline = xaios_clock_nanos() + UINT64_C(600000000000);
  br_ssl_client_zero(&g_client);
  br_ssl_engine_set_versions(&g_client.eng, BR_TLS12, BR_TLS12);
  br_ssl_engine_set_suites(&g_client.eng, suites,
                           sizeof(suites) / sizeof(suites[0]));
  br_ssl_client_set_default_rsapub(&g_client);
  br_ssl_engine_set_default_rsavrfy(&g_client.eng);
  br_ssl_engine_set_default_ecdsa(&g_client.eng);
  br_ssl_engine_set_default_ec(&g_client.eng);
  br_ssl_engine_set_hash(&g_client.eng, br_sha256_ID, &br_sha256_vtable);
  br_ssl_engine_set_hash(&g_client.eng, br_sha384_ID, &br_sha384_vtable);
  br_ssl_engine_set_hash(&g_client.eng, br_sha512_ID, &br_sha512_vtable);
  br_ssl_engine_set_prf_sha256(&g_client.eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_prf_sha384(&g_client.eng, &br_tls12_sha384_prf);
  br_ssl_engine_set_default_aes_gcm(&g_client.eng);
  if (pinned ? use_pinned_key(rsa_modulus_hex) : use_chain_validation()) {
    return -1;
  }
  br_ssl_engine_set_buffer(&g_client.eng, g_io_buffer, sizeof(g_io_buffer), 1);
  br_ssl_engine_inject_entropy(&g_client.eng, entropy, sizeof(entropy));
  if (!br_ssl_client_reset(&g_client, server_name, 0)) {
    g_error = br_ssl_engine_last_error(&g_client.eng);
    if (g_error == 0) g_error = 82;
    return -1;
  }
  br_sslio_init(&g_io, &g_client.eng, socket_read, 0, socket_write, 0);
  return 0;
}

int xapt_tls_write(const void *data, u64 size) {
  return br_sslio_write_all(&g_io, data, size) == 0 &&
                 br_sslio_flush(&g_io) == 0
             ? 0
             : -1;
}

int xapt_tls_read(void *data, u64 size) {
  return br_sslio_read(&g_io, data, size);
}

int xapt_tls_close(void) { return br_sslio_close(&g_io); }

int xapt_tls_last_error(void) {
  int engine = br_ssl_engine_last_error(&g_client.eng);
  return engine != 0 ? engine : g_error;
}
