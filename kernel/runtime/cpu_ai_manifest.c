/* Model admission and runtime metrics for the CPU AI runtime.
 *
 * Moved verbatim out of kernel/runtime/cpu_ai_runtime.c so no source file
 * exceeds 500 lines. This is the admission/metrics group: the FNV-1a payload
 * hash, the model-image and model-arena manifest validators, the arena
 * registration helper, the initramfs model-file loader, every cpu_ai_runtime_*
 * counter accessor and the counter reset. See cpu_ai_runtime_internal.h for
 * the shared declarations.
 *
 * The counters are defined once here (the original statics) and declared
 * extern in the private header, because cpu_ai_runtime.c's binding path and
 * cpu_ai_fixture.c's kernel path both increment them.
 */

#include "cpu_ai_runtime_internal.h"

#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/model_arena.h>

uint64_t g_cpu_ai_model_load_count;
uint64_t g_cpu_ai_model_load_failure_count;
uint64_t g_cpu_ai_tokenizer_call_count;
uint64_t g_cpu_ai_runtime_call_count;
uint64_t g_cpu_ai_kv_write_count;
uint64_t g_cpu_ai_shared_weight_bind_count;
uint64_t g_cpu_ai_gpu_reject_count;
uint64_t g_cpu_ai_model_file_load_count;
uint64_t g_cpu_ai_model_file_reject_count;
uint64_t g_cpu_ai_model_bytes_loaded;
uint64_t g_cpu_ai_manifest_validation_count;
uint64_t g_cpu_ai_tokenizer_bind_count;
uint64_t g_cpu_ai_kernel_dispatch_count;
uint64_t g_cpu_ai_admission_reject_count;
uint64_t g_cpu_ai_checksum_failure_count;
uint64_t g_cpu_ai_inference_count;

static int range_in_model(uint64_t offset, uint64_t size, uint64_t model_size) {
  if (size == 0 || offset >= model_size) {
    return 0;
  }
  return size <= model_size - offset;
}

static uint64_t fnv1a64_update(uint64_t hash, const uint8_t *bytes,
                               uint64_t size) {
  for (uint64_t i = 0; i < size; ++i) {
    hash ^= bytes[i];
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

uint64_t cpu_ai_manifest_payload_hash(
    const uint8_t *base, const cpu_ai_model_manifest_t *manifest) {
  uint64_t hash = FNV1A64_OFFSET;
  hash = fnv1a64_update(hash, base + manifest->weights_offset,
                        manifest->weights_size);
  hash = fnv1a64_update(hash, base + manifest->tokenizer_offset,
                        manifest->tokenizer_size);
  return hash;
}

static xaios_status_t cpu_ai_manifest_validate_image(
    const void *base, uint64_t size, uint32_t require_read_only,
    const cpu_ai_model_manifest_t **manifest_out) {
  if (base == 0 || size < sizeof(cpu_ai_model_manifest_t) ||
      require_read_only == 0) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const cpu_ai_model_manifest_t *manifest =
      (const cpu_ai_model_manifest_t *)base;
  ++g_cpu_ai_manifest_validation_count;

  /* Check magic and version */
  if (manifest->magic != CPU_AI_MAGIC ||
      manifest->version != CPU_AI_VERSION) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  if (manifest->header_bytes != CPU_AI_HEADER_BYTES) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  if (manifest->quantization != CPU_AI_QUANTIZATION_SUPPORTED ||
      manifest->stride == 0 || manifest->stride > 32U) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  if (manifest->tokenizer_id != CPU_AI_TOKENIZER_BYTE_TABLE) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  if (manifest->runtime_id != CPU_AI_RUNTIME_DETERMINISTIC ||
      (manifest->flags & CPU_AI_FLAG_CPU_ONLY) == 0 ||
      !range_in_model(manifest->weights_offset, manifest->weights_size,
                      size) ||
      !range_in_model(manifest->tokenizer_offset, manifest->tokenizer_size,
                      size) ||
      manifest->weights_size < CPU_AI_MIN_WEIGHT_BYTES ||
      manifest->tokenizer_size < CPU_AI_TOKENIZER_BYTES ||
      manifest->kv_bytes_required == 0) {
    ++g_cpu_ai_admission_reject_count;
    if ((manifest->flags & CPU_AI_FLAG_GPU_REQUIRED) != 0) {
      ++g_cpu_ai_gpu_reject_count;
    }
    return XAIOS_ERR_INVALID;
  }
  if ((manifest->flags & CPU_AI_FLAG_GPU_REQUIRED) != 0) {
    ++g_cpu_ai_gpu_reject_count;
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const uint64_t hash =
      cpu_ai_manifest_payload_hash((const uint8_t *)base, manifest);
  if (hash != manifest->payload_hash) {
    ++g_cpu_ai_checksum_failure_count;
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *weights = (const uint8_t *)base + manifest->weights_offset;
  if (weights[0] != manifest->key || weights[1] != manifest->stride) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  if (manifest_out != 0) {
    *manifest_out = manifest;
  }
  return XAIOS_OK;
}

xaios_status_t cpu_ai_manifest_validate_model(
    const xaios_model_arena_t *model,
    const cpu_ai_model_manifest_t **manifest_out) {
  if (model == 0 || model->base == 0 || model->read_only == 0) {
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  return cpu_ai_manifest_validate_image(model->base, model->size,
                                        model->read_only, manifest_out);
}

xaios_status_t cpu_ai_manifest_register_bytes(uint32_t model_arena_id,
                                             const char *name,
                                             const void *base, uint64_t size) {
  const cpu_ai_model_manifest_t *manifest = 0;
  if (cpu_ai_manifest_validate_image(base, size, 1, &manifest) != XAIOS_OK) {
    ++g_cpu_ai_model_file_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if (model_arena_register_fixture_copy(model_arena_id, name, base, size) !=
      XAIOS_OK) {
    ++g_cpu_ai_model_file_reject_count;
    return XAIOS_ERR_INVALID;
  }
  ++g_cpu_ai_model_file_load_count;
  g_cpu_ai_model_bytes_loaded += size;
  klog("cpu-ai-runtime: model file loaded id=%u name=%s bytes=%lu weights=%lu tokenizer=%lu checksum=0x%lx\n",
       model_arena_id, name, size, manifest->weights_size,
       manifest->tokenizer_size, manifest->payload_hash);
  return XAIOS_OK;
}

xaios_status_t cpu_ai_runtime_load_model_file(uint32_t model_arena_id,
                                             const char *name,
                                             const char *path) {
  if (name == 0 || path == 0) {
    ++g_cpu_ai_model_file_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const xaios_initramfs_file_t *file = 0;
  if (initramfs_lookup(path, &file) != XAIOS_OK || file == 0 ||
      file->base == 0 || file->size == 0 || file->executable != 0 ||
      file->manifest != 0) {
    ++g_cpu_ai_model_file_reject_count;
    ++g_cpu_ai_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  xaios_status_t status = cpu_ai_manifest_register_bytes(
      model_arena_id, name, file->base, file->size);
  if (status == XAIOS_OK) {
    klog("cpu-ai-runtime: model file path=%s admitted arena=%u\n", path,
         model_arena_id);
  }
  return status;
}

uint64_t cpu_ai_runtime_model_load_count(void) {
  return g_cpu_ai_model_load_count;
}

uint64_t cpu_ai_runtime_model_load_failure_count(void) {
  return g_cpu_ai_model_load_failure_count;
}

uint64_t cpu_ai_runtime_tokenizer_call_count(void) {
  return g_cpu_ai_tokenizer_call_count;
}

uint64_t cpu_ai_runtime_runtime_call_count(void) {
  return g_cpu_ai_runtime_call_count;
}

uint64_t cpu_ai_runtime_kv_write_count(void) {
  return g_cpu_ai_kv_write_count;
}

uint64_t cpu_ai_runtime_shared_weight_bind_count(void) {
  return g_cpu_ai_shared_weight_bind_count;
}

uint64_t cpu_ai_runtime_gpu_reject_count(void) {
  return g_cpu_ai_gpu_reject_count;
}

uint64_t cpu_ai_runtime_model_file_load_count(void) {
  return g_cpu_ai_model_file_load_count;
}

uint64_t cpu_ai_runtime_model_file_reject_count(void) {
  return g_cpu_ai_model_file_reject_count;
}

uint64_t cpu_ai_runtime_model_bytes_loaded(void) {
  return g_cpu_ai_model_bytes_loaded;
}

uint64_t cpu_ai_runtime_manifest_validation_count(void) {
  return g_cpu_ai_manifest_validation_count;
}

uint64_t cpu_ai_runtime_tokenizer_bind_count(void) {
  return g_cpu_ai_tokenizer_bind_count;
}

uint64_t cpu_ai_runtime_kernel_dispatch_count(void) {
  return g_cpu_ai_kernel_dispatch_count;
}

uint64_t cpu_ai_runtime_admission_reject_count(void) {
  return g_cpu_ai_admission_reject_count;
}

uint64_t cpu_ai_runtime_checksum_failure_count(void) {
  return g_cpu_ai_checksum_failure_count;
}

uint64_t cpu_ai_runtime_inference_count(void) {
  return g_cpu_ai_inference_count;
}

/* The counter half of the original cpu_ai_runtime_init(): the cell zeroing
   and the init log line stay in cpu_ai_runtime.c, which owns the cell
   table. */
void cpu_ai_metrics_reset(void) {
  g_cpu_ai_model_load_count = 0;
  g_cpu_ai_model_load_failure_count = 0;
  g_cpu_ai_tokenizer_call_count = 0;
  g_cpu_ai_runtime_call_count = 0;
  g_cpu_ai_kv_write_count = 0;
  g_cpu_ai_shared_weight_bind_count = 0;
  g_cpu_ai_gpu_reject_count = 0;
  g_cpu_ai_model_file_load_count = 0;
  g_cpu_ai_model_file_reject_count = 0;
  g_cpu_ai_model_bytes_loaded = 0;
  g_cpu_ai_manifest_validation_count = 0;
  g_cpu_ai_tokenizer_bind_count = 0;
  g_cpu_ai_kernel_dispatch_count = 0;
  g_cpu_ai_admission_reject_count = 0;
  g_cpu_ai_checksum_failure_count = 0;
  g_cpu_ai_inference_count = 0;
}
