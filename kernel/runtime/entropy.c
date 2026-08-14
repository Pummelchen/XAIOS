#include <xaios/assert.h>
#include <xaios/arch_random.h>
#include <xaios/entropy.h>
#include <xaios/klog.h>
#include <xaios/sha256.h>
#include <xaios/spinlock.h>
#include <xaios/virtio_rng.h>

#define XAIOS_ENTROPY_STATE_BYTES UINT32_C(32)
#define XAIOS_ENTROPY_BLOCK_BYTES UINT32_C(32)

typedef struct entropy_provider {
  uint8_t state[XAIOS_ENTROPY_STATE_BYTES];
  uint64_t counter;
  uint32_t seeded;
  xaios_spinlock_t lock;
} entropy_provider_t;

static entropy_provider_t g_entropy;

static void bytes_copy(void *destination, const void *source, uint64_t size) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < size; ++index) out[index] = in[index];
}

static void bytes_zero(void *destination, uint64_t size) {
  volatile uint8_t *out = (volatile uint8_t *)destination;
  for (uint64_t index = 0U; index < size; ++index) out[index] = 0U;
}

static uint64_t string_length(const char *text) {
  uint64_t length = 0U;
  while (text[length] != '\0') ++length;
  return length;
}

static void hash_parts(const char *label, const void *first,
                       uint64_t first_size, const void *second,
                       uint64_t second_size, uint64_t counter,
                       uint8_t out[32]) {
  xaios_sha256_ctx_t context;
  uint8_t encoded_counter[8];
  for (uint32_t index = 0U; index < sizeof(encoded_counter); ++index) {
    encoded_counter[index] =
        (uint8_t)(counter >> (8U * (sizeof(encoded_counter) - 1U - index)));
  }
  xaios_sha256_init(&context);
  xaios_sha256_update(&context, label, string_length(label));
  xaios_sha256_update(&context, first, first_size);
  xaios_sha256_update(&context, second, second_size);
  xaios_sha256_update(&context, encoded_counter, sizeof(encoded_counter));
  xaios_sha256_final(&context, out);
  bytes_zero(encoded_counter, sizeof(encoded_counter));
}

static void seed_from_material(const char *label, const void *material,
                               uint64_t material_size) {
  hash_parts(label, material, material_size, g_entropy.state,
             sizeof(g_entropy.state), g_entropy.counter, g_entropy.state);
  g_entropy.seeded = 1U;
}

void entropy_init(const xaios_boot_info_t *boot) {
  uint8_t hardware_seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES];
  bytes_zero(&g_entropy, sizeof(g_entropy));
  xaios_spin_init(&g_entropy.lock);
  if (boot != 0 &&
      boot->entropy_seed_size == XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES) {
    seed_from_material("xaios.entropy.efi.v1", boot->entropy_seed,
                       XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES);
    klog("entropy: EFI RNG seed accepted\n");
  }
  if (arch_random_read(hardware_seed, sizeof(hardware_seed)) == XAIOS_OK) {
    seed_from_material("xaios.entropy.arch.v1", hardware_seed,
                       sizeof(hardware_seed));
    klog("entropy: architectural RNG seed accepted\n");
  }
  bytes_zero(hardware_seed, sizeof(hardware_seed));
}

static xaios_status_t firmware_random(void *buffer, uint64_t size) {
  uint8_t *output = (uint8_t *)buffer;
  xaios_spin_lock(&g_entropy.lock);
  while (size != 0U) {
    uint8_t block[XAIOS_ENTROPY_BLOCK_BYTES];
    uint8_t next_state[XAIOS_ENTROPY_STATE_BYTES];
    const uint64_t counter = ++g_entropy.counter;
    hash_parts("xaios.entropy.output.v1", g_entropy.state,
               sizeof(g_entropy.state), 0, 0U, counter, block);
    hash_parts("xaios.entropy.ratchet", g_entropy.state,
               sizeof(g_entropy.state), block, sizeof(block), counter,
               next_state);
    const uint32_t take =
        size > sizeof(block) ? sizeof(block) : (uint32_t)size;
    bytes_copy(output, block, take);
    bytes_copy(g_entropy.state, next_state, sizeof(next_state));
    bytes_zero(block, sizeof(block));
    bytes_zero(next_state, sizeof(next_state));
    output += take;
    size -= take;
  }
  xaios_spin_unlock(&g_entropy.lock);
  return XAIOS_OK;
}

xaios_status_t entropy_read(void *buffer, uint64_t size) {
  if (buffer == 0 || size == 0U || size > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  if (virtio_rng_read(buffer, size) == XAIOS_OK) return XAIOS_OK;
  if (g_entropy.seeded == 0U) return XAIOS_ERR_UNSUPPORTED;
  return firmware_random(buffer, size);
}

void entropy_self_test(void) {
  uint8_t first[32];
  uint8_t second[32];
  if (entropy_read(first, sizeof(first)) != XAIOS_OK ||
      entropy_read(second, sizeof(second)) != XAIOS_OK) {
    klog("entropy: secure entropy unavailable\n");
    return;
  }
  uint8_t difference = 0U;
  uint8_t nonzero = 0U;
  for (uint32_t index = 0U; index < sizeof(first); ++index) {
    difference |= first[index] ^ second[index];
    nonzero |= first[index];
  }
  kassert(difference != 0U);
  kassert(nonzero != 0U);
  bytes_zero(first, sizeof(first));
  bytes_zero(second, sizeof(second));
  klog("entropy: provider self-test passed\n");
}
