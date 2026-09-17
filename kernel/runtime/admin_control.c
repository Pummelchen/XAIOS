/* Audit log, transactional mutations and model activation of the admin control
 * plane.
 *
 * admin_control.c was split so no source file exceeds 500 lines. What stays
 * here is the part the other two modules call into: the byte and string
 * primitives, the audit log and the mutation transaction framework, plus the
 * model-activation operation and the boot self-test. The configuration
 * subsystem and host-key identity moved to admin_control_config.c; the
 * authentication key database moved to admin_control_auth.c. The split is
 * declared in admin_control_internal.h.
 */

#include "admin_control_internal.h"

#include <xaios/admin_control.h>
#include <xaios/assert.h>
#include <xaios/entropy.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/vfs_xaifs.h>
#include <xaios/xaiboot_fs.h>

/* The bodies below were written against admin_control.c's file-local names.
   These aliases bind the shared primitives, the transaction framework and the
   helpers that moved to admin_control_config.c to their prefixed exports, so
   the retained code reads exactly as it did before the split. */
#define bytes_zero xaios_admin_bytes_zero
#define bytes_copy xaios_admin_bytes_copy
#define bytes_equal xaios_admin_bytes_equal
#define string_length xaios_admin_string_length
#define string_equal xaios_admin_string_equal
#define string_equal_range xaios_admin_string_equal_range
#define string_copy xaios_admin_string_copy
#define fnv1a64 xaios_admin_fnv1a64
#define audit_only xaios_admin_audit_only
#define begin_mutation xaios_admin_mutation_begin
#define finish_mutation xaios_admin_mutation_finish
#define abort_and_audit xaios_admin_mutation_abort_and_audit
#define parse_config_text xaios_admin_parse_config_text
#define config_valid xaios_admin_config_valid
#define principal_valid xaios_admin_principal_valid
#define host_key_entropy_gate xaios_admin_host_key_entropy_gate

void xaios_admin_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0U;
  }
}

void xaios_admin_bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

int xaios_admin_bytes_equal(const void *left, const void *right, uint64_t size) {
  const uint8_t *lhs = (const uint8_t *)left;
  const uint8_t *rhs = (const uint8_t *)right;
  uint8_t difference = 0U;
  for (uint64_t i = 0; i < size; ++i) {
    difference |= lhs[i] ^ rhs[i];
  }
  return difference == 0U;
}

uint64_t xaios_admin_string_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) {
    return 0U;
  }
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

int xaios_admin_string_equal(const char *left, const char *right) {
  if (left == 0 || right == 0) {
    return 0;
  }
  for (uint64_t i = 0;; ++i) {
    if (left[i] != right[i]) {
      return 0;
    }
    if (left[i] == '\0') {
      return 1;
    }
  }
}

int xaios_admin_string_equal_range(const char *text, uint64_t length,
                                   const char *expected) {
  uint64_t expected_length = string_length(expected);
  return length == expected_length && bytes_equal(text, expected, length);
}

void xaios_admin_string_copy(char *dst, uint64_t capacity, const char *src) {
  uint64_t offset = 0U;
  if (dst == 0 || capacity == 0U) {
    return;
  }
  while (src != 0 && src[offset] != '\0' && offset + 1U < capacity) {
    dst[offset] = src[offset];
    ++offset;
  }
  dst[offset] = '\0';
}

uint64_t xaios_admin_fnv1a64(const void *data, uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t hash = UINT64_C(1469598103934665603);
  for (uint64_t i = 0U; i < size; ++i) {
    hash ^= bytes[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static uint64_t audit_checksum(const xaios_admin_audit_log_t *audit) {
  uint64_t bytes = sizeof(*audit) - sizeof(audit->records) +
                   ((uint64_t)audit->record_count * sizeof(audit->records[0]));
  xaios_admin_audit_log_t *copy =
      (xaios_admin_audit_log_t *)kheap_alloc(bytes, 16U);
  if (copy == 0) {
    return 0U;
  }
  bytes_copy(copy, audit, bytes);
  copy->checksum = 0U;
  uint64_t checksum = fnv1a64(copy, bytes);
  kheap_free(copy);
  return checksum;
}

static int audit_valid(const xaios_admin_audit_log_t *audit) {
  uint64_t checksum;
  if (audit == 0 || audit->magic != XAIOS_ADMIN_AUDIT_MAGIC ||
      audit->version != XAIOS_ADMIN_SCHEMA_VERSION ||
      audit->header_size != sizeof(*audit) - sizeof(audit->records) ||
      audit->record_size != sizeof(audit->records[0]) ||
      audit->record_count > XAIOS_ADMIN_MAX_AUDIT_RECORDS ||
      audit->next_sequence == 0U) {
    return 0;
  }
  checksum = audit_checksum(audit);
  return checksum != 0U && checksum == audit->checksum;
}

static void initialize_audit(xaios_admin_audit_log_t *audit) {
  bytes_zero(audit, sizeof(*audit));
  audit->magic = XAIOS_ADMIN_AUDIT_MAGIC;
  audit->version = XAIOS_ADMIN_SCHEMA_VERSION;
  audit->header_size =
      (uint16_t)(sizeof(*audit) - sizeof(audit->records));
  audit->record_size = sizeof(audit->records[0]);
  audit->next_sequence = 1U;
  audit->checksum = audit_checksum(audit);
}

static xaios_admin_result_t load_audit(xaios_admin_audit_log_t *audit) {
  uint64_t size = 0U;
  if (audit == 0) return XAIOS_ADMIN_RESULT_INVALID;
  if (xaiboot_fs_read(XAIOS_ADMIN_AUDIT_PATH, audit, sizeof(*audit), &size) ==
      XAIOS_OK) {
    uint64_t expected = sizeof(*audit) - sizeof(audit->records) +
                        ((uint64_t)audit->record_count *
                         sizeof(audit->records[0]));
    return size == expected && audit_valid(audit)
               ? XAIOS_ADMIN_RESULT_OK
               : XAIOS_ADMIN_RESULT_INVALID;
  }
  initialize_audit(audit);
  return audit->checksum != 0U ? XAIOS_ADMIN_RESULT_OK
                               : XAIOS_ADMIN_RESULT_NO_MEMORY;
}

static int operation_replayed(const char *actor, uint64_t operation_id) {
  xaios_admin_audit_log_t *audit =
      (xaios_admin_audit_log_t *)kheap_alloc(sizeof(*audit), 16U);
  if (audit == 0) return 0;
  int replayed = 0;
  if (load_audit(audit) == XAIOS_ADMIN_RESULT_OK) {
    for (uint32_t i = 0U; i < audit->record_count; ++i) {
      if (audit->records[i].operation_id == operation_id &&
          string_equal(audit->records[i].principal, actor)) {
        replayed = 1;
        break;
      }
    }
  }
  kheap_free(audit);
  return replayed;
}

static xaios_admin_result_t append_audit(const char *actor, uint32_t role,
                                         uint64_t operation_id,
                                         const char *operation,
                                         uint32_t result,
                                         const uint8_t object_hash[32]) {
  xaios_admin_audit_log_t *audit =
      (xaios_admin_audit_log_t *)kheap_alloc(sizeof(*audit), 16U);
  if (audit == 0) return XAIOS_ADMIN_RESULT_NO_MEMORY;
  xaios_admin_result_t load_result = load_audit(audit);
  if (load_result != XAIOS_ADMIN_RESULT_OK) {
    kheap_free(audit);
    return load_result;
  }
  if (audit->next_sequence == UINT64_MAX) {
    kheap_free(audit);
    return XAIOS_ADMIN_RESULT_NO_MEMORY;
  }
  if (audit->record_count >= XAIOS_ADMIN_MAX_AUDIT_RECORDS) {
    for (uint32_t i = 1U; i < audit->record_count; ++i) {
      audit->records[i - 1U] = audit->records[i];
    }
    --audit->record_count;
    bytes_zero(&audit->records[audit->record_count],
               sizeof(audit->records[0]));
  }
  xaios_admin_audit_record_t *record =
      &audit->records[audit->record_count++];
  bytes_zero(record, sizeof(*record));
  record->sequence = audit->next_sequence++;
  record->operation_id = operation_id;
  if (object_hash != 0) {
    bytes_copy(record->object_hash, object_hash, sizeof(record->object_hash));
  }
  string_copy(record->principal, sizeof(record->principal), actor);
  string_copy(record->operation, sizeof(record->operation), operation);
  record->role = role;
  record->result = result;
  audit->checksum = audit_checksum(audit);
  uint64_t bytes = sizeof(*audit) - sizeof(audit->records) +
                   ((uint64_t)audit->record_count * sizeof(audit->records[0]));
  xaios_status_t status =
      audit->checksum != 0U
          ? xaiboot_fs_write(XAIOS_ADMIN_AUDIT_PATH, audit, bytes)
          : XAIOS_ERR_NO_MEMORY;
  kheap_free(audit);
  return status == XAIOS_OK ? XAIOS_ADMIN_RESULT_OK : XAIOS_ADMIN_RESULT_IO;
}

xaios_admin_result_t xaios_admin_audit_only(const char *actor, uint32_t role,
                                            uint64_t operation_id,
                                            const char *operation,
                                            xaios_admin_result_t result) {
  uint8_t object_hash[32];
  bytes_zero(object_hash, sizeof(object_hash));
  if (!principal_valid(actor) || operation_id == 0U ||
      role < XAIOS_ADMIN_ROLE_OBSERVER || role > XAIOS_ADMIN_ROLE_ADMIN) {
    return result;
  }
  if (xaiboot_fs_commit("admin-audit-pre") != XAIOS_OK) {
    return XAIOS_ADMIN_RESULT_IO;
  }
  if (append_audit(actor, role, operation_id, operation, (uint32_t)result,
                   object_hash) != XAIOS_ADMIN_RESULT_OK ||
      xaiboot_fs_commit("admin-audit-post") != XAIOS_OK) {
    (void)xaiboot_fs_rollback();
    return XAIOS_ADMIN_RESULT_IO;
  }
  return result;
}

xaios_admin_result_t xaios_admin_mutation_begin(const char *actor, uint32_t role,
                                                uint32_t required_role,
                                                uint64_t operation_id,
                                                const char *operation) {
  if (!principal_valid(actor) || operation_id == 0U) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  if (operation_replayed(actor, operation_id)) {
    return XAIOS_ADMIN_RESULT_REPLAY;
  }
  if (role < required_role || role > XAIOS_ADMIN_ROLE_ADMIN) {
    return audit_only(actor, role, operation_id, operation,
                      XAIOS_ADMIN_RESULT_DENIED);
  }
  return xaiboot_fs_commit("admin-mutation-pre") == XAIOS_OK
             ? XAIOS_ADMIN_RESULT_OK
             : XAIOS_ADMIN_RESULT_IO;
}

xaios_admin_result_t admin_control_mutation_begin(
    const char *actor, uint32_t role, uint32_t required_role,
    uint64_t operation_id, const char *operation) {
  return begin_mutation(actor, role, required_role, operation_id, operation);
}

xaios_admin_result_t xaios_admin_mutation_finish(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, const uint8_t object_hash[32]) {
  if (append_audit(actor, role, operation_id, operation,
                   XAIOS_ADMIN_RESULT_OK, object_hash) !=
          XAIOS_ADMIN_RESULT_OK ||
      xaiboot_fs_commit("admin-mutation-post") != XAIOS_OK) {
    (void)xaiboot_fs_rollback();
    return XAIOS_ADMIN_RESULT_IO;
  }
  return XAIOS_ADMIN_RESULT_OK;
}

xaios_admin_result_t admin_control_mutation_complete(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, const uint8_t object_hash[32]) {
  return finish_mutation(actor, role, operation_id, operation, object_hash);
}

static void abort_mutation(void) {
  (void)xaiboot_fs_rollback();
}

xaios_admin_result_t xaios_admin_mutation_abort_and_audit(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result) {
  abort_mutation();
  return audit_only(actor, role, operation_id, operation, result);
}

xaios_admin_result_t admin_control_mutation_fail(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result) {
  return abort_and_audit(actor, role, operation_id, operation, result);
}

static int package_id_bytes(const char *package_id, uint8_t output[32]) {
  if (package_id == 0 || output == 0) return 0;
  for (uint32_t index = 0U; index < 32U; ++index) {
    char high_character = package_id[index * 2U];
    char low_character = package_id[index * 2U + 1U];
    uint8_t high = 0U;
    uint8_t low = 0U;
    if (high_character >= '0' && high_character <= '9') {
      high = (uint8_t)(high_character - '0');
    } else if (high_character >= 'a' && high_character <= 'f') {
      high = (uint8_t)(high_character - 'a' + 10);
    } else if (high_character >= 'A' && high_character <= 'F') {
      high = (uint8_t)(high_character - 'A' + 10);
    } else {
      return 0;
    }
    if (low_character >= '0' && low_character <= '9') {
      low = (uint8_t)(low_character - '0');
    } else if (low_character >= 'a' && low_character <= 'f') {
      low = (uint8_t)(low_character - 'a' + 10);
    } else if (low_character >= 'A' && low_character <= 'F') {
      low = (uint8_t)(low_character - 'A' + 10);
    } else {
      return 0;
    }
    output[index] = (uint8_t)((high << 4U) | low);
  }
  return package_id[64] == '\0';
}

static xaios_admin_result_t model_status_result(xaios_status_t status) {
  if (status == XAIOS_OK) return XAIOS_ADMIN_RESULT_OK;
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_ADMIN_RESULT_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_ADMIN_RESULT_CONFLICT;
  }
  if (status == XAIOS_ERR_IO) return XAIOS_ADMIN_RESULT_IO;
  return XAIOS_ADMIN_RESULT_INVALID;
}

xaios_admin_result_t admin_control_model_activate(
    const char *package_id, const char *actor, uint32_t actor_role,
    uint64_t operation_id, uint64_t *generation) {
  uint8_t object_hash[32];
  if (generation == 0 || !package_id_bytes(package_id, object_hash)) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  xaios_admin_result_t result = begin_mutation(
      actor, actor_role, XAIOS_ADMIN_ROLE_ADMIN, operation_id,
      "model.package.activate");
  if (result != XAIOS_ADMIN_RESULT_OK) return result;
  result = model_status_result(
      vfs_xaifs_activate_staging(package_id, generation));
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "model.package.activate", result);
  }
  result = finish_mutation(actor, actor_role, operation_id,
                           "model.package.activate", object_hash);
  if (result != XAIOS_ADMIN_RESULT_OK) {
    klog("admin-control: xaiFS activation committed but audit commit failed operation=%lu generation=%lu\n",
         operation_id, *generation);
  }
  return result;
}

xaios_admin_result_t admin_control_audit_read(
    uint64_t since_sequence, uint32_t limit,
    xaios_admin_audit_record_t *records, uint32_t capacity,
    uint32_t *record_count, uint64_t *next_sequence,
    uint64_t *latest_sequence) {
  if (records == 0 || record_count == 0 || next_sequence == 0 ||
      latest_sequence == 0 || limit == 0U || limit > capacity) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  xaios_admin_audit_log_t *audit =
      (xaios_admin_audit_log_t *)kheap_alloc(sizeof(*audit), 16U);
  if (audit == 0) return XAIOS_ADMIN_RESULT_NO_MEMORY;
  xaios_admin_result_t result = load_audit(audit);
  if (result == XAIOS_ADMIN_RESULT_OK) {
    *record_count = 0U;
    *next_sequence = since_sequence;
    *latest_sequence = audit->next_sequence - 1U;
    for (uint32_t i = 0U; i < audit->record_count && *record_count < limit;
         ++i) {
      if (audit->records[i].sequence <= since_sequence) continue;
      records[*record_count] = audit->records[i];
      *next_sequence = audit->records[i].sequence;
      ++(*record_count);
    }
  }
  kheap_free(audit);
  return result;
}

void admin_control_self_test(void) {
  static const char valid[] =
      "schema=xaios.config.v1\n"
      "ssh.max_connections=32\n"
      "ssh.max_channels_per_connection=2\n"
      "ssh.max_auth_attempts=5\n"
      "ssh.command_rate_per_minute=60\n"
      "ssh.password_auth=disabled\n";
  static const char invalid[] =
      "schema=xaios.config.v1\nssh.unknown=1\n";
  xaios_admin_config_t candidate;
  kassert(xaios_admin_control_initialized() != 0U);
  kassert(parse_config_text(valid, sizeof(valid) - 1U, &candidate) == 0);
  kassert(config_valid(&candidate));
  kassert(parse_config_text(invalid, sizeof(invalid) - 1U, &candidate) != 0);
  kassert(principal_valid("ops.user-1"));
  kassert(!principal_valid("bad principal"));

  /* F-05: minting a host key is refused when the randomness is a file baked
     into the image, and permitted when it is a real source.
     The decision is tested here rather than through a booted machine because
     on every machine this project can boot in a test the answer is always
     "permitted": QEMU's firmware offers an RNG, its bus offers a virtio-rng,
     and a guest with neither does not start SSH at all. Fusion is the machine
     that actually has a development seed file, and a decision that can only
     be checked by hand on one laptop is not gated at all. So the provenance
     is swapped and swapped back -- the label only; the pool and the bytes it
     hands out are untouched -- and the gate is asked directly.
     It is the gate that is called here and not the whole rotation, on
     purpose: rotation opens a filesystem transaction before it reaches this
     question, and a self-test that ran at every boot would commit and roll
     back one on every machine to prove a decision that has nothing to do
     with storage. The wiring between the two is a single call. */
  uint32_t restore = entropy_swap_source_for_test(XAIOS_ENTROPY_SOURCE_SEED_FILE);
  kassert(host_key_entropy_gate() == XAIOS_ADMIN_RESULT_DENIED);
  (void)entropy_swap_source_for_test(XAIOS_ENTROPY_SOURCE_NONE);
  kassert(host_key_entropy_gate() == XAIOS_ADMIN_RESULT_DENIED);

  /* The other half -- that a real source is permitted -- is only askable on a
     machine that has one.
     entropy_swap_source_for_test moves the label and nothing else, and
     entropy_is_production_grade also requires a pool that was actually seeded.
     On a machine with no random device the pool never is, so swapping in a
     production-grade label produces a machine that still refuses, correctly,
     and this used to assert that it would not. It killed the guest at boot on
     the one configuration F-05 exists to describe: `make
     qemu-docker-no-rng-suite` starts a machine with no RNG on purpose, and it
     panicked here instead of coming up and declining to mint.
     So the permit half is asserted where it can be, and its absence is
     reported rather than skipped quietly -- a machine with no entropy is
     supposed to say so. */
  if (entropy_is_seeded() != 0U) {
    (void)entropy_swap_source_for_test(XAIOS_ENTROPY_SOURCE_DEVICE_RNG);
    kassert(host_key_entropy_gate() == XAIOS_ADMIN_RESULT_OK);
    (void)entropy_swap_source_for_test(XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG);
    kassert(host_key_entropy_gate() == XAIOS_ADMIN_RESULT_OK);
    (void)entropy_swap_source_for_test(restore);
    klog("admin-control: host-key rotation refuses development-grade entropy "
         "and permits a real source\n");
  } else {
    (void)entropy_swap_source_for_test(XAIOS_ENTROPY_SOURCE_DEVICE_RNG);
    kassert(host_key_entropy_gate() == XAIOS_ADMIN_RESULT_DENIED);
    (void)entropy_swap_source_for_test(restore);
    klog("admin-control: host-key rotation refuses development-grade entropy; "
         "this machine has no seeded entropy pool, so it refuses a real source "
         "label too and the permit half is not askable here\n");
  }

  klog("admin-control: self-test passed schema=1 invalid=1 principal=2 "
       "transactional=1\n");
}
