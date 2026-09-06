#include "ssh_host_key.h"
#include "sshd.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

#define HOST_KEY_PATH "/state/xaios_host_key"

static uint8_t g_host_private_key[32];
static uint8_t g_host_public_key[32];
static uint32_t g_key_initialized = 0;
/* Set when the key in use could not be written to persistent storage, so the
   condition can be reported rather than silently tolerated. */
static uint32_t g_host_key_ephemeral = 0;

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
static int hex_to_bin(const char *hex, uint32_t hex_len, uint8_t *bin,
                      uint32_t bin_len) {
  if (hex_len != bin_len * 2) return -1;
  for (uint32_t i = 0; i < bin_len; ++i) {
    int hi = hex_to_nibble(hex[i * 2]);
    int lo = hex_to_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return -1;
    bin[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static int ensure_key(void) {
  if (!g_key_initialized) {
    /* Try to load the persistent host key from mutable state storage. */
    char key_buf[128];
    int ret = xaios_read_file(HOST_KEY_PATH, key_buf, sizeof(key_buf));

    if (ret == 64 &&
        hex_to_bin(key_buf, (uint32_t)ret, g_host_private_key, 32) == 0) {
      /* Successfully loaded private key, compute public key */
      xaios_ed25519_public_key(g_host_public_key, g_host_private_key);
      g_key_initialized = 1;
      return 0;
    }

    /* Generate new key pair */
    if (crypto_random_bytes(g_host_private_key, 32) != 0) {
      ssh_mem_zero(g_host_private_key, sizeof(g_host_private_key));
      return -1;
    }
    xaios_ed25519_public_key(g_host_public_key, g_host_private_key);

    /* Save private key to persistent storage.

       A failure here used to abort SSH startup, which made an unwritable
       persistent filesystem mean no remote access at all. The key pair in
       hand is perfectly good; only its durability is in question, so the
       service continues with it rather than leaving the machine unreachable
       at exactly the moment an operator needs to get in and repair storage.

       The cost is a host key that does not survive this boot, which clients
       see as a changed key and warn about. That warning is the point: it is
       visible, whereas an unreachable machine offers nothing to act on. */
    char hex_buf[65];
    bin_to_hex(g_host_private_key, 32, hex_buf);
    int save_ret = xaios_write_file(HOST_KEY_PATH, hex_buf);
    ssh_mem_zero(hex_buf, sizeof(hex_buf));
    if (save_ret != 64) {
      g_host_key_ephemeral = 1U;
      ssh_log(SSH_LOG_ERROR,
              "Host key could not be persisted; continuing with an ephemeral "
              "key. Clients will report a changed host key until persistent "
              "storage is repaired.\n");
    }

    /* Said at the one moment the machine's identity is decided.
       This is the first-boot mint, and unlike an operator-requested rotation
       -- which the kernel now refuses outright on development-grade entropy
       -- it cannot refuse: a machine with no host key has no SSH, and the
       operator who would fix that is the one who cannot get in. So it says
       what it did instead, next to the kernel's own `entropy: source=` line
       from earlier in the same console. On a machine whose only randomness
       is a seed file baked into its image, this key is reproducible by
       anyone holding that image, and this line is where to notice it. */
    ssh_log(SSH_LOG_WARN,
            "Generated a new host key. Its strength is this machine's "
            "entropy: see the kernel's `entropy: source=` line above. A key "
            "minted on a development seed file is reproducible from the "
            "image it was built into.\n");

    g_key_initialized = 1;
  }
  return 0;
}

int ssh_host_key_init(void) {
  return ensure_key();
}

int ssh_host_key_is_ephemeral(void) {
  return g_host_key_ephemeral != 0U;
}

int ssh_host_key_reload(void) {
  ssh_mem_zero(g_host_private_key, sizeof(g_host_private_key));
  ssh_mem_zero(g_host_public_key, sizeof(g_host_public_key));
  g_key_initialized = 0U;
  return ensure_key();
}

int ssh_host_key_get_private(uint8_t priv[32]) {
  if (ensure_key() != 0) return -1;
  for (uint32_t i = 0; i < 32; ++i) priv[i] = g_host_private_key[i];
  return 0;
}

int ssh_host_key_get_public(uint8_t pub[32]) {
  if (ensure_key() != 0) return -1;
  for (uint32_t i = 0; i < 32; ++i) pub[i] = g_host_public_key[i];
  return 0;
}
