#include "ssh_host_key.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

#define HOST_KEY_PATH "/state/xaios_host_key"

static uint8_t g_host_private_key[32];
static uint8_t g_host_public_key[32];
static uint32_t g_key_initialized = 0;

/* Convert hex char to nibble */
static int hex_to_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

/* Convert binary to hex string */
static void bin_to_hex(const uint8_t *bin, uint32_t bin_len, char *hex) {
  static const char hex_chars[] = "0123456789abcdef";
  for (uint32_t i = 0; i < bin_len; ++i) {
    hex[i * 2] = hex_chars[(bin[i] >> 4) & 0xF];
    hex[i * 2 + 1] = hex_chars[bin[i] & 0xF];
  }
  hex[bin_len * 2] = '\0';
}

/* Convert hex string to binary */
static int hex_to_bin(const char *hex, uint8_t *bin, uint32_t bin_len) {
  uint32_t hex_len = 0;
  while (hex[hex_len]) ++hex_len;
  if (hex_len != bin_len * 2) return -1;
  for (uint32_t i = 0; i < bin_len; ++i) {
    int hi = hex_to_nibble(hex[i * 2]);
    int lo = hex_to_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return -1;
    bin[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static void ensure_key(void) {
  if (!g_key_initialized) {
    /* Try to load the persistent host key from mutable state storage. */
    char key_buf[128];
    int ret = xaios_read_file(HOST_KEY_PATH, key_buf, sizeof(key_buf));

    if (ret == 0 && hex_to_bin(key_buf, g_host_private_key, 32) == 0) {
      /* Successfully loaded private key, compute public key */
      xaios_ed25519_public_key(g_host_public_key, g_host_private_key);
      g_key_initialized = 1;
      return;
    }

    /* Generate new key pair */
    crypto_random_bytes(g_host_private_key, 32);
    xaios_ed25519_public_key(g_host_public_key, g_host_private_key);

    /* Save private key to persistent storage */
    char hex_buf[65];
    bin_to_hex(g_host_private_key, 32, hex_buf);
    int save_ret = xaios_write_file(HOST_KEY_PATH, hex_buf);
    (void)save_ret;

    g_key_initialized = 1;
  }
}

void ssh_host_key_get_private(uint8_t priv[32]) {
  ensure_key();
  for (uint32_t i = 0; i < 32; ++i) priv[i] = g_host_private_key[i];
}

void ssh_host_key_get_public(uint8_t pub[32]) {
  ensure_key();
  for (uint32_t i = 0; i < 32; ++i) pub[i] = g_host_public_key[i];
}
