#include <xaios/boot_info.h>
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
  /* Where the seed came from, kept so anything about to mint a long-lived
     secret can ask rather than assume. */
  uint32_t source;
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
    g_entropy.source = boot->entropy_seed_source;
    /* Say which. This used to report "EFI RNG seed accepted" for a seed the
       loader had read out of a file on the EFI System Partition, because the
       size is the same either way and nothing carried the difference. A
       development seed that logs as a hardware one is worse than no log. */
    if (boot->entropy_seed_source == XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG) {
      klog("entropy: firmware RNG seed accepted\n");
    } else {
      klog("entropy: DEVELOPMENT seed file accepted -- reproducible by "
           "construction, not fit for secrets that must survive contact with "
           "anyone else\n");
    }
  }
  if (arch_random_read(hardware_seed, sizeof(hardware_seed)) == XAIOS_OK) {
    seed_from_material("xaios.entropy.arch.v1", hardware_seed,
                       sizeof(hardware_seed));
    /* An architectural source upgrades the answer whatever came before it:
       mixing it in means the state no longer depends only on a file. */
    g_entropy.source = XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG;
    klog("entropy: architectural RNG seed accepted\n");
  }
  /* A random device on the bus, mixed in after the firmware's own sources.
     Always mixed when present -- more real entropy is never worse -- but it
     only names itself as the source when nothing better already did, so a
     machine with a firmware RNG keeps saying so. */
  uint8_t device_seed[32];
  if (virtio_rng_read(device_seed, sizeof(device_seed)) == XAIOS_OK) {
    seed_from_material("xaios.entropy.device.v1", device_seed,
                       sizeof(device_seed));
    if (g_entropy.source != XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG) {
      g_entropy.source = XAIOS_ENTROPY_SOURCE_DEVICE_RNG;
    }
    klog("entropy: device RNG seed accepted\n");
    bytes_zero(device_seed, sizeof(device_seed));
  }
  klog("entropy: source=%s\n",
       g_entropy.source == XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG ? "hardware"
       : g_entropy.source == XAIOS_ENTROPY_SOURCE_DEVICE_RNG ? "device-rng"
       : g_entropy.source == XAIOS_ENTROPY_SOURCE_SEED_FILE  ? "development-seed-file"
                                                             : "none");
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

uint32_t entropy_source(void) { return g_entropy.source; }

/* Swap the recorded provenance and hand back what was there.
   Only the self-tests use this, and only in matched pairs. It exists because
   the one behaviour F-05 turns on -- refusing to mint a host key when the
   randomness is a file baked into the image -- is unreachable on every
   machine this project can boot in a test: QEMU's firmware has an RNG, its
   bus has a virtio-rng, and a RISC-V guest with neither does not start SSH
   at all. Fusion is the machine that actually has this property, and a
   decision that can only be checked by hand on one laptop is not gated.
   It changes the label, never the pool: the bytes handed out are the same
   bytes either way, so nothing is weakened by asking the question. */
uint32_t entropy_swap_source_for_test(uint32_t source) {
  uint32_t previous = g_entropy.source;
  g_entropy.source = source;
  return previous;
}

/* Whether this machine's randomness is fit for a secret that outlives the
   boot: an SSH host key, a cluster identity, anything an operator would be
   upset to find reproducible.
   A development seed file is not. It is the same on every boot and on every
   machine built from the same image, so a key derived from it is a key
   anyone holding that image already has. This is the question F-05 exists to
   make askable; what an operator does about the answer -- which entropy
   source to provision, and how -- remains theirs to decide. */
uint32_t entropy_is_production_grade(void) {
  /* A random device on the bus counts. It is not the firmware's word, but it
     is a source the machine asked for and received, which is the distinction
     this predicate exists to draw -- the one it must refuse is a file baked
     into an image, identical on every copy. */
  return g_entropy.seeded != 0U &&
         (g_entropy.source == XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG ||
          g_entropy.source == XAIOS_ENTROPY_SOURCE_DEVICE_RNG);
}
