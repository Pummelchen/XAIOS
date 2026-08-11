#include <xaios/assert.h>
#include <xaios/arena.h>
#include <xaios/ai_kernels.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/model_arena.h>

/* Picard — “I am Locutus of Borg. Resistance is futile.” */

#define CPU_AI_MAGIC UINT32_C(0x4941494d)
#define CPU_AI_VERSION UINT16_C(1)
#define CPU_AI_HEADER_BYTES UINT16_C(80)
#define CPU_AI_QUANTIZATION_SUPPORTED UINT16_C(8)
#define CPU_AI_FLAG_CPU_ONLY UINT32_C(1)
#define CPU_AI_FLAG_GPU_REQUIRED UINT32_C(1 << 1)
#define CPU_AI_TOKENIZER_BYTE_TABLE UINT32_C(1)
#define CPU_AI_RUNTIME_DETERMINISTIC UINT32_C(1)
#define CPU_AI_MAX_TOKENS 32U
#define CPU_AI_MIN_WEIGHT_BYTES UINT64_C(2)
#define CPU_AI_TOKENIZER_BYTES UINT64_C(256)
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

#define XAIOS_CPU_AI_RUNTIME_STATE_EMPTY 0U
#define XAIOS_CPU_AI_RUNTIME_STATE_BOUND 1U

typedef struct {
  uint32_t magic;
  uint16_t version;
  uint16_t header_bytes;
  uint16_t quantization;
  uint16_t reserved0;
  uint32_t flags;
  uint32_t tokenizer_id;
  uint32_t runtime_id;
  uint64_t weights_offset;
  uint64_t weights_size;
  uint64_t tokenizer_offset;
  uint64_t tokenizer_size;
  uint64_t kv_bytes_required;
  uint64_t payload_hash;
  uint8_t key;
  uint8_t stride;
  uint8_t reserved1[6];
} cpu_ai_model_manifest_t;

typedef struct {
  uint32_t token_id;
  uint8_t source_byte;
} cpu_ai_token_t;

typedef struct {
  uint8_t state;
  uint32_t model_arena_id;
  const uint8_t *model_base;
  uint64_t model_size;
  const uint8_t *weights_base;
  uint64_t weights_size;
  const uint8_t *tokenizer_base;
  uint64_t tokenizer_size;
  uint32_t tokenizer_id;
  uint32_t runtime_id;
  uint64_t kv_base;
  uint64_t kv_bytes;
  uint64_t kv_cursor;
  uint64_t kv_writes;
  uint64_t decode_calls;
  uint64_t bytes_in;
  uint64_t bytes_out;
  uint16_t quantization;
  uint8_t key;
  uint8_t stride;
  xaios_quantization_t quant_format;
  const char *model_name;
} xaios_cpu_ai_runtime_cell_t;

static xaios_cpu_ai_runtime_cell_t g_cells[XAIOS_CPU_AI_RUNTIME_MAX_CELLS];
static const char k_hex[] = "0123456789ABCDEF";
static uint64_t g_model_load_count;
static uint64_t g_model_load_failure_count;
static uint64_t g_tokenizer_call_count;
static uint64_t g_runtime_call_count;
static uint64_t g_kv_write_count;
static uint64_t g_shared_weight_bind_count;
static uint64_t g_gpu_reject_count;
static uint64_t g_model_file_load_count;
static uint64_t g_model_file_reject_count;
static uint64_t g_model_bytes_loaded;
static uint64_t g_manifest_validation_count;
static uint64_t g_tokenizer_bind_count;
static uint64_t g_kernel_dispatch_count;
static uint64_t g_admission_reject_count;
static uint64_t g_checksum_failure_count;
static uint64_t g_inference_count;

static int validate_cell_id(uint32_t cell_id) {
  return cell_id < XAIOS_CPU_AI_RUNTIME_MAX_CELLS;
}

static void bytes_zero(void *bytes, uint64_t size) {
  uint8_t *ptr = (uint8_t *)bytes;
  for (uint64_t i = 0; i < size; ++i) {
    ptr[i] = 0;
  }
}

static int bytes_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint32_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

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

static uint64_t model_payload_hash(const uint8_t *base,
                                   const cpu_ai_model_manifest_t *manifest) {
  uint64_t hash = FNV1A64_OFFSET;
  hash = fnv1a64_update(hash, base + manifest->weights_offset,
                        manifest->weights_size);
  hash = fnv1a64_update(hash, base + manifest->tokenizer_offset,
                        manifest->tokenizer_size);
  return hash;
}

static xaios_status_t validate_model_image(const void *base, uint64_t size,
                                          uint32_t require_read_only,
    const cpu_ai_model_manifest_t **manifest_out) {
  if (base == 0 || size < sizeof(cpu_ai_model_manifest_t) ||
      require_read_only == 0) {
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const cpu_ai_model_manifest_t *manifest =
      (const cpu_ai_model_manifest_t *)base;
  ++g_manifest_validation_count;
  
  /* Check magic and version */
  if (manifest->magic != CPU_AI_MAGIC ||
      manifest->version != CPU_AI_VERSION) {
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  
  if (manifest->header_bytes != CPU_AI_HEADER_BYTES) {
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  
  if (manifest->quantization != CPU_AI_QUANTIZATION_SUPPORTED ||
      manifest->stride == 0 || manifest->stride > 32U) {
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  
  if (manifest->tokenizer_id != CPU_AI_TOKENIZER_BYTE_TABLE) {
    ++g_admission_reject_count;
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
    ++g_admission_reject_count;
    if ((manifest->flags & CPU_AI_FLAG_GPU_REQUIRED) != 0) {
      ++g_gpu_reject_count;
    }
    return XAIOS_ERR_INVALID;
  }
  if ((manifest->flags & CPU_AI_FLAG_GPU_REQUIRED) != 0) {
    ++g_gpu_reject_count;
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const uint64_t hash = model_payload_hash((const uint8_t *)base, manifest);
  if (hash != manifest->payload_hash) {
    ++g_checksum_failure_count;
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *weights = (const uint8_t *)base + manifest->weights_offset;
  if (weights[0] != manifest->key || weights[1] != manifest->stride) {
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  if (manifest_out != 0) {
    *manifest_out = manifest;
  }
  return XAIOS_OK;
}

static xaios_status_t validate_model_manifest(
    const xaios_model_arena_t *model,
    const cpu_ai_model_manifest_t **manifest_out) {
  if (model == 0 || model->base == 0 || model->read_only == 0) {
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }
  return validate_model_image(model->base, model->size, model->read_only,
                              manifest_out);
}

static xaios_status_t register_model_bytes(uint32_t model_arena_id,
                                          const char *name, const void *base,
                                          uint64_t size) {
  const cpu_ai_model_manifest_t *manifest = 0;
  if (validate_model_image(base, size, 1, &manifest) != XAIOS_OK) {
    ++g_model_file_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if (model_arena_register_fixture_copy(model_arena_id, name, base, size) !=
      XAIOS_OK) {
    ++g_model_file_reject_count;
    return XAIOS_ERR_INVALID;
  }
  ++g_model_file_load_count;
  g_model_bytes_loaded += size;
  klog("cpu-ai-runtime: model file loaded id=%u name=%s bytes=%lu weights=%lu tokenizer=%lu checksum=0x%lx\n",
       model_arena_id, name, size, manifest->weights_size,
       manifest->tokenizer_size, manifest->payload_hash);
  return XAIOS_OK;
}

static xaios_status_t tokenizer_encode(xaios_cpu_ai_runtime_cell_t *cell,
                                      const uint8_t *piece,
                                      uint64_t piece_bytes,
                                      cpu_ai_token_t *tokens,
                                      uint64_t token_capacity,
                                      uint64_t *token_count) {
  if (cell == 0 || piece == 0 || tokens == 0 || token_count == 0) {
    return XAIOS_ERR_INVALID;
  }
  
  if (cell->tokenizer_id == CPU_AI_TOKENIZER_BYTE_TABLE) {
    if (cell->tokenizer_base == 0 ||
        cell->tokenizer_size < CPU_AI_TOKENIZER_BYTES ||
        piece_bytes > token_capacity) {
      return XAIOS_ERR_INVALID;
    }
    
    for (uint64_t i = 0; i < piece_bytes; ++i) {
      tokens[i].token_id = cell->tokenizer_base[piece[i]];
      tokens[i].source_byte = piece[i];
    }
    *token_count = piece_bytes;
    ++g_tokenizer_call_count;
    return XAIOS_OK;
  }
  
  return XAIOS_ERR_INVALID;
}

static xaios_status_t kv_record_tokens(xaios_cpu_ai_runtime_cell_t *cell,
                                      const cpu_ai_token_t *tokens,
                                      uint64_t token_count) {
  if (cell == 0 || tokens == 0 || token_count == 0) {
    return XAIOS_OK;
  }
  if (cell->kv_base == 0 || cell->kv_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }

  const uint64_t record_bytes = token_count * sizeof(uint32_t);
  if (record_bytes > cell->kv_bytes ||
      cell->kv_cursor > cell->kv_bytes - record_bytes) {
    return XAIOS_ERR_NO_MEMORY;
  }

  uint32_t *kv = (uint32_t *)(uintptr_t)(cell->kv_base + cell->kv_cursor);
  for (uint64_t i = 0; i < token_count; ++i) {
    kv[i] = tokens[i].token_id;
  }
  cell->kv_cursor += record_bytes;
  cell->kv_writes += token_count;
  g_kv_write_count += token_count;
  return XAIOS_OK;
}

static xaios_status_t deterministic_cpu_kernel(xaios_cpu_ai_runtime_cell_t *cell,
                                              const cpu_ai_token_t *tokens,
                                              uint64_t token_count,
                                              char *output,
                                              uint64_t output_capacity,
                                              uint64_t *output_bytes) {
  if (cell == 0 || tokens == 0 || output == 0 || output_bytes == 0 ||
      cell->weights_base == 0 || cell->weights_size < CPU_AI_MIN_WEIGHT_BYTES) {
    return XAIOS_ERR_INVALID;
  }

  const uint64_t required_output = token_count * 2U;
  if (required_output + 1U > output_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }

  if (kv_record_tokens(cell, tokens, token_count) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }

  for (uint64_t i = 0; i < token_count; ++i) {
    const uint8_t key = cell->weights_base[0];
    const uint8_t stride = cell->weights_base[1];
    const uint8_t mix =
        (uint8_t)(tokens[i].token_id ^
                  (uint8_t)(key + (stride * i)));
    output[(i * 2U)] = k_hex[(mix >> 4) & 0x0fU];
    output[(i * 2U) + 1U] = k_hex[mix & 0x0fU];
  }

  output[required_output] = '\0';
  *output_bytes = required_output;
  ++g_runtime_call_count;
  return XAIOS_OK;
}

/* Legacy scalar kernels replaced by NEON-optimized ai_kernels.c */
/* matmul_q88_scalar() now dispatches to ai_kernel_matmul() with XAIOS_QUANT_Q88 */
/* forward_pass_q88 now dispatches to ai_kernel_forward() */

static xaios_status_t runtime_decode_tokens(xaios_cpu_ai_runtime_cell_t *cell,
                                           const cpu_ai_token_t *tokens,
                                           uint64_t token_count, char *output,
                                           uint64_t output_capacity,
                                           uint64_t *output_bytes) {
  if (cell == 0 || tokens == 0 || output == 0 || output_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }

  ++g_kernel_dispatch_count;
  if (cell->runtime_id == CPU_AI_RUNTIME_DETERMINISTIC) {
    return deterministic_cpu_kernel(cell, tokens, token_count, output,
                                    output_capacity, output_bytes);
  }

  return XAIOS_ERR_INVALID;
}

void cpu_ai_runtime_init(void) {
  for (uint32_t i = 0; i < XAIOS_CPU_AI_RUNTIME_MAX_CELLS; ++i) {
    bytes_zero(&g_cells[i], sizeof(g_cells[i]));
  }
  g_model_load_count = 0;
  g_model_load_failure_count = 0;
  g_tokenizer_call_count = 0;
  g_runtime_call_count = 0;
  g_kv_write_count = 0;
  g_shared_weight_bind_count = 0;
  g_gpu_reject_count = 0;
  g_model_file_load_count = 0;
  g_model_file_reject_count = 0;
  g_model_bytes_loaded = 0;
  g_manifest_validation_count = 0;
  g_tokenizer_bind_count = 0;
  g_kernel_dispatch_count = 0;
  g_admission_reject_count = 0;
  g_checksum_failure_count = 0;
  g_inference_count = 0;
  klog("cpu-ai-runtime: initialized cells=%u\n",
       XAIOS_CPU_AI_RUNTIME_MAX_CELLS);
}

xaios_status_t cpu_ai_runtime_load_model_file(uint32_t model_arena_id,
                                             const char *name,
                                             const char *path) {
  if (name == 0 || path == 0) {
    ++g_model_file_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const xaios_initramfs_file_t *file = 0;
  if (initramfs_lookup(path, &file) != XAIOS_OK || file == 0 ||
      file->base == 0 || file->size == 0 || file->executable != 0 ||
      file->manifest != 0) {
    ++g_model_file_reject_count;
    ++g_admission_reject_count;
    return XAIOS_ERR_INVALID;
  }

  xaios_status_t status =
      register_model_bytes(model_arena_id, name, file->base, file->size);
  if (status == XAIOS_OK) {
    klog("cpu-ai-runtime: model file path=%s admitted arena=%u\n", path,
         model_arena_id);
  }
  return status;
}

xaios_status_t cpu_ai_runtime_bind_model(uint32_t cell_id,
                                        uint32_t model_arena_id) {
  return cpu_ai_runtime_bind_model_with_kv(cell_id, model_arena_id,
                                           UINT64_C(0), UINT64_C(0));
}

xaios_status_t cpu_ai_runtime_bind_model_with_kv(uint32_t cell_id,
                                                uint32_t model_arena_id,
                                                uint64_t kv_base,
                                                uint64_t kv_bytes) {
  if (!validate_cell_id(cell_id)) {
    return XAIOS_ERR_INVALID;
  }

  xaios_cpu_ai_runtime_cell_t *cell = &g_cells[cell_id];
  if (cell->state != XAIOS_CPU_AI_RUNTIME_STATE_EMPTY) {
    return XAIOS_ERR_BUSY;
  }

  const xaios_model_arena_t *model = 0;
  if (model_arena_acquire(model_arena_id, &model) != XAIOS_OK) {
    ++g_model_load_failure_count;
    return XAIOS_ERR_INVALID;
  }

  const cpu_ai_model_manifest_t *manifest = 0;
  if (validate_model_manifest(model, &manifest) != XAIOS_OK) {
    ++g_model_load_failure_count;
    kassert(model_arena_release(model_arena_id) == XAIOS_OK);
    return XAIOS_ERR_INVALID;
  }
  
  const uint64_t kv_required = manifest->kv_bytes_required;
  
  if (kv_base == 0 || kv_bytes < kv_required) {
    ++g_admission_reject_count;
    ++g_model_load_failure_count;
    kassert(model_arena_release(model_arena_id) == XAIOS_OK);
    klog("cpu-ai-runtime: insufficient KV cache cell=%u required=%lu provided=%lu\n",
         cell_id, kv_required, kv_bytes);
    return XAIOS_ERR_INVALID;
  }

  cell->state = XAIOS_CPU_AI_RUNTIME_STATE_BOUND;
  cell->model_arena_id = model_arena_id;
  cell->model_base = (const uint8_t *)model->base;
  cell->model_size = model->size;
  cell->weights_base = cell->model_base + manifest->weights_offset;
  cell->weights_size = manifest->weights_size;
  cell->tokenizer_base = cell->model_base + manifest->tokenizer_offset;
  cell->tokenizer_size = manifest->tokenizer_size;
  cell->tokenizer_id = manifest->tokenizer_id;
  cell->runtime_id = manifest->runtime_id;
  cell->kv_base = kv_base;
  cell->kv_bytes = kv_bytes;
  cell->kv_cursor = 0;
  cell->kv_writes = 0;
  cell->quantization = manifest->quantization;
  cell->key = manifest->key;
  cell->stride = manifest->stride;
  cell->model_name = model->name;
  
  /* The v1 fixture uses Q8.8 only. Real model packages use model.v2. */
  if (manifest->quantization == 8) {
    cell->quant_format = XAIOS_QUANT_Q88;  /* Legacy Q8.8 */
  } else {
    cell->quant_format = XAIOS_QUANT_Q88;  /* Default fallback */
  }
  cell->decode_calls = 0;
  cell->bytes_in = 0;
  cell->bytes_out = 0;
  ++g_model_load_count;
  ++g_shared_weight_bind_count;
  ++g_tokenizer_bind_count;

  klog("cpu-ai-runtime: model manifest loaded cell=%u model_id=%u name=%s quant=%u tokenizer=%u runtime=%u weights=%lu tokenizer_bytes=%lu kv_required=%lu quant_format=%u\n",
       cell_id, model_arena_id,
       cell->model_name != 0 ? cell->model_name : "<anonymous>",
       cell->quantization, cell->tokenizer_id, cell->runtime_id,
       cell->weights_size, cell->tokenizer_size, manifest->kv_bytes_required,
       cell->quant_format);
  klog("cpu-ai-runtime: cell=%u bound model_id=%u name=%s size=%lu quant=%u stride=%u kv=0x%lx kv_bytes=%lu\n",
       cell_id, model_arena_id,
       cell->model_name != 0 ? cell->model_name : "<anonymous>",
       cell->model_size, cell->quantization, cell->stride, cell->kv_base,
       cell->kv_bytes);
  return XAIOS_OK;
}

xaios_status_t cpu_ai_runtime_unbind_model(uint32_t cell_id) {
  if (!validate_cell_id(cell_id)) {
    return XAIOS_ERR_INVALID;
  }

  xaios_cpu_ai_runtime_cell_t *cell = &g_cells[cell_id];
  if (cell->state != XAIOS_CPU_AI_RUNTIME_STATE_BOUND) {
    return XAIOS_ERR_INVALID;
  }

  const uint32_t model_arena_id = cell->model_arena_id;
  kassert(model_arena_release(model_arena_id) == XAIOS_OK);
  bytes_zero(cell, sizeof(*cell));
  klog("cpu-ai-runtime: cell=%u unbound model_id=%u\n", cell_id,
       model_arena_id);
  return XAIOS_OK;
}

xaios_status_t cpu_ai_runtime_fixture_decode_piece(
    uint32_t cell_id, const uint8_t *piece, uint64_t piece_bytes, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  if (!validate_cell_id(cell_id) || piece == 0 || output == 0 ||
      output_bytes == 0 || output_capacity == 0) {
    return XAIOS_ERR_INVALID;
  }

  xaios_cpu_ai_runtime_cell_t *cell = &g_cells[cell_id];
  if (cell->state != XAIOS_CPU_AI_RUNTIME_STATE_BOUND) {
    return XAIOS_ERR_INVALID;
  }

  if (piece_bytes == 0) {
    *output_bytes = 0;
    if (output_capacity > 0) {
      output[0] = '\0';
    }
    return XAIOS_OK;
  }

  if (piece_bytes > CPU_AI_MAX_TOKENS) {
    return XAIOS_ERR_INVALID;
  }

  cpu_ai_token_t tokens[CPU_AI_MAX_TOKENS];
  uint64_t token_count = 0;
  if (tokenizer_encode(cell, piece, piece_bytes, tokens, CPU_AI_MAX_TOKENS,
                       &token_count) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  if (runtime_decode_tokens(cell, tokens, token_count, output, output_capacity,
                            output_bytes) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }

  ++cell->decode_calls;
  cell->bytes_in += piece_bytes;
  cell->bytes_out += *output_bytes;

  klog("cpu-ai-runtime: cell=%u decode piece_len=%lu output_len=%lu\n", cell_id,
       piece_bytes, *output_bytes);
  return XAIOS_OK;
}

xaios_status_t cpu_ai_runtime_decode_piece(uint32_t cell_id,
                                         const uint8_t *piece,
                                         uint64_t piece_bytes, char *output,
                                         uint64_t output_capacity,
                                         uint64_t *output_bytes) {
  (void)cell_id;
  (void)piece;
  (void)piece_bytes;
  if (output != 0 && output_capacity > 0) {
    output[0] = '\0';
  }
  if (output_bytes != 0) {
    *output_bytes = 0;
  }
  return XAIOS_ERR_UNSUPPORTED;
}

static void runtime_append(char *output, uint64_t capacity, uint64_t *offset,
                           const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

static void runtime_append_u64(char *output, uint64_t capacity,
                               uint64_t *offset, uint64_t value) {
  char digits[20];
  uint64_t count = 0;
  if (value == 0) {
    runtime_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    runtime_append(output, capacity, offset, one);
  }
}

xaios_status_t cpu_ai_runtime_run_model(uint32_t cell_id, uint64_t model_kind,
                                       const uint8_t *input,
                                       uint64_t input_bytes, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes) {
  if (input == 0 || input_bytes == 0 || output == 0 || output_capacity < 2U ||
      output_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }
  output[0] = '\0';
  *output_bytes = 0;

  if (model_kind == XAIOS_ML_MODEL_FIXTURE_DECODE) {
    return cpu_ai_runtime_fixture_decode_piece(
        cell_id, input, input_bytes, output, output_capacity, output_bytes);
  }

  ++g_kernel_dispatch_count;
  ++g_runtime_call_count;
  uint64_t offset = 0;
  if (model_kind == XAIOS_ML_MODEL_XOR) {
    if (input_bytes < 2U) {
      return XAIOS_ERR_INVALID;
    }
    const uint8_t lhs = (uint8_t)(input[0] & 1U);
    const uint8_t rhs = (uint8_t)(input[1] & 1U);
    runtime_append(output, output_capacity, &offset,
                   ((lhs ^ rhs) != 0U) ? "1" : "0");
  } else if (model_kind == XAIOS_ML_MODEL_SUM) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < input_bytes; ++i) {
      sum += input[i];
    }
    runtime_append_u64(output, output_capacity, &offset, sum);
  } else if (model_kind == XAIOS_ML_MODEL_PARITY) {
    uint8_t parity = 0;
    for (uint64_t i = 0; i < input_bytes; ++i) {
      parity ^= (uint8_t)(input[i] & 1U);
    }
    runtime_append(output, output_capacity, &offset,
                   parity != 0U ? "odd" : "even");
  } else if (model_kind == XAIOS_ML_MODEL_MATMUL) {
    if (input_bytes < 12U) {
      return XAIOS_ERR_INVALID;
    }
    uint32_t rows_a = (uint32_t)input[0];
    uint32_t cols_a = (uint32_t)input[1];
    uint32_t cols_b = (uint32_t)input[2];
    if (rows_a == 0 || cols_a == 0 || cols_b == 0 ||
        rows_a > XAIOS_CPU_AI_MAX_MATRIX_DIM ||
        cols_a > XAIOS_CPU_AI_MAX_MATRIX_DIM ||
        cols_b > XAIOS_CPU_AI_MAX_MATRIX_DIM) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t mat_bytes =
        (uint64_t)(rows_a * cols_a + cols_a * cols_b) * sizeof(int16_t);
    if (12U + mat_bytes > input_bytes) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t out_bytes = (uint64_t)(rows_a * cols_b) * sizeof(int16_t);
    if (out_bytes > output_capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    const int16_t *mat_a = (const int16_t *)(input + 12U);
    const int16_t *mat_b =
        (const int16_t *)(input + 12U +
                           (uint64_t)(rows_a * cols_a) * sizeof(int16_t));
    ai_kernel_matmul(mat_a, mat_b, output, rows_a, cols_a, cols_b, XAIOS_QUANT_Q88);
    offset = out_bytes;
    ++g_inference_count;
  } else if (model_kind == XAIOS_ML_MODEL_FORWARD) {
    if (input_bytes < 12U) {
      return XAIOS_ERR_INVALID;
    }
    uint32_t batch = (uint32_t)input[0];
    uint32_t in_dim = (uint32_t)input[1];
    uint32_t out_dim = (uint32_t)input[2];
    if (batch == 0 || in_dim == 0 || out_dim == 0 ||
        batch > XAIOS_CPU_AI_MAX_MATRIX_DIM ||
        in_dim > XAIOS_CPU_AI_MAX_MATRIX_DIM ||
        out_dim > XAIOS_CPU_AI_MAX_MATRIX_DIM) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t input_mat_bytes =
        (uint64_t)(batch * in_dim) * sizeof(int16_t);
    if (12U + input_mat_bytes > input_bytes) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t out_bytes = (uint64_t)(batch * out_dim) * sizeof(int16_t);
    if (out_bytes > output_capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    const int16_t *input_mat = (const int16_t *)(input + 12U);
    const xaios_cpu_ai_runtime_cell_t *fwd_cell = 0;
    if (validate_cell_id(cell_id) &&
        g_cells[cell_id].state == XAIOS_CPU_AI_RUNTIME_STATE_BOUND) {
      fwd_cell = &g_cells[cell_id];
    }
    uint64_t weight_bytes = (uint64_t)(in_dim * out_dim) * sizeof(int16_t);
    if ((fwd_cell == 0 || fwd_cell->weights_base == 0 ||
         fwd_cell->weights_size < weight_bytes + 2U) &&
        12U + input_mat_bytes + weight_bytes > input_bytes) {
      return XAIOS_ERR_INVALID;
    }
    const int16_t *layer_weights =
        (fwd_cell != 0 && fwd_cell->weights_base != 0 &&
         fwd_cell->weights_size >= weight_bytes + 2U)
            ? (const int16_t *)(fwd_cell->weights_base + 2U)
            : (const int16_t *)(input + 12U + input_mat_bytes);
    ai_kernel_forward(input_mat, layer_weights, 0, output,
                     batch, in_dim, out_dim, XAIOS_QUANT_Q88, XAIOS_ACT_RELU);
    offset = out_bytes;
    ++g_inference_count;
  } else {
    return XAIOS_ERR_INVALID;
  }

  *output_bytes = offset;
  klog("cpu-ai-runtime: generic ml model kind=%lu input=%lu output=%lu cpu_only=1\n",
       model_kind, input_bytes, offset);
  return XAIOS_OK;
}

uint64_t cpu_ai_runtime_decode_count(uint32_t cell_id) {
  if (!validate_cell_id(cell_id)) {
    return 0;
  }
  return g_cells[cell_id].decode_calls;
}

uint64_t cpu_ai_runtime_model_load_count(void) {
  return g_model_load_count;
}

uint64_t cpu_ai_runtime_model_load_failure_count(void) {
  return g_model_load_failure_count;
}

uint64_t cpu_ai_runtime_tokenizer_call_count(void) {
  return g_tokenizer_call_count;
}

uint64_t cpu_ai_runtime_runtime_call_count(void) {
  return g_runtime_call_count;
}

uint64_t cpu_ai_runtime_kv_write_count(void) {
  return g_kv_write_count;
}

uint64_t cpu_ai_runtime_shared_weight_bind_count(void) {
  return g_shared_weight_bind_count;
}

uint64_t cpu_ai_runtime_gpu_reject_count(void) {
  return g_gpu_reject_count;
}

uint64_t cpu_ai_runtime_model_file_load_count(void) {
  return g_model_file_load_count;
}

uint64_t cpu_ai_runtime_model_file_reject_count(void) {
  return g_model_file_reject_count;
}

uint64_t cpu_ai_runtime_model_bytes_loaded(void) {
  return g_model_bytes_loaded;
}

uint64_t cpu_ai_runtime_manifest_validation_count(void) {
  return g_manifest_validation_count;
}

uint64_t cpu_ai_runtime_tokenizer_bind_count(void) {
  return g_tokenizer_bind_count;
}

uint64_t cpu_ai_runtime_kernel_dispatch_count(void) {
  return g_kernel_dispatch_count;
}

uint64_t cpu_ai_runtime_admission_reject_count(void) {
  return g_admission_reject_count;
}

uint64_t cpu_ai_runtime_checksum_failure_count(void) {
  return g_checksum_failure_count;
}

uint64_t cpu_ai_runtime_inference_count(void) {
  return g_inference_count;
}

typedef struct {
  cpu_ai_model_manifest_t manifest;
  uint8_t weights[32];
  uint8_t tokenizer[256];
} cpu_ai_test_model_image_t;

static void fill_test_model_image(cpu_ai_test_model_image_t *image,
                                  uint32_t flags, uint64_t tokenizer_size,
                                  uint32_t corrupt_hash) {
  bytes_zero(image, sizeof(*image));
  image->weights[0] = 0x5a;
  image->weights[1] = 0x03;
  image->weights[2] = 0xaa;
  image->weights[3] = 0xbb;
  image->weights[4] = 0xcc;
  image->weights[5] = 0xdd;
  for (uint32_t i = 0; i < CPU_AI_TOKENIZER_BYTES; ++i) {
    image->tokenizer[i] = (uint8_t)i;
  }

  image->manifest.magic = CPU_AI_MAGIC;
  image->manifest.version = CPU_AI_VERSION;
  image->manifest.header_bytes = CPU_AI_HEADER_BYTES;
  image->manifest.quantization = CPU_AI_QUANTIZATION_SUPPORTED;
  image->manifest.flags = flags;
  image->manifest.tokenizer_id = CPU_AI_TOKENIZER_BYTE_TABLE;
  image->manifest.runtime_id = CPU_AI_RUNTIME_DETERMINISTIC;
  image->manifest.weights_offset = sizeof(cpu_ai_model_manifest_t);
  image->manifest.weights_size = sizeof(image->weights);
  image->manifest.tokenizer_offset =
      sizeof(cpu_ai_model_manifest_t) + sizeof(image->weights);
  image->manifest.tokenizer_size = tokenizer_size;
  image->manifest.kv_bytes_required = 4096;
  image->manifest.key = 0x5a;
  image->manifest.stride = 0x03;
  image->manifest.payload_hash =
      model_payload_hash((const uint8_t *)image, &image->manifest);
  if (corrupt_hash != 0) {
    image->manifest.payload_hash ^= UINT64_C(0x10);
  }
}

void cpu_ai_runtime_self_test(void) {
  cpu_ai_runtime_init();

  kassert(sizeof(cpu_ai_model_manifest_t) == CPU_AI_HEADER_BYTES);
  kassert(cpu_ai_runtime_load_model_file(2, "cpu-ai-v1-fixture",
                                         "/models/cpu-ai-v1-fixture.xaiosmodel") ==
          XAIOS_OK);
  kassert(cpu_ai_runtime_load_model_file(3, "missing-model",
                                         "/models/missing.xaiosmodel") ==
          XAIOS_ERR_INVALID);

  cpu_ai_test_model_image_t bad_checksum_image;
  cpu_ai_test_model_image_t bad_tokenizer_image;
  cpu_ai_test_model_image_t gpu_model_image;
  fill_test_model_image(&bad_checksum_image, CPU_AI_FLAG_CPU_ONLY,
                        CPU_AI_TOKENIZER_BYTES, 1);
  fill_test_model_image(&bad_tokenizer_image, CPU_AI_FLAG_CPU_ONLY, 16, 0);
  fill_test_model_image(&gpu_model_image,
                        CPU_AI_FLAG_CPU_ONLY | CPU_AI_FLAG_GPU_REQUIRED,
                        CPU_AI_TOKENIZER_BYTES, 0);
  kassert(register_model_bytes(3, "bad-checksum-model", &bad_checksum_image,
                               sizeof(bad_checksum_image)) ==
          XAIOS_ERR_INVALID);
  kassert(register_model_bytes(3, "bad-tokenizer-model", &bad_tokenizer_image,
                               sizeof(bad_tokenizer_image)) ==
          XAIOS_ERR_INVALID);
  kassert(model_arena_register_fixture_copy(
              3, "gpu-rejected-model", &gpu_model_image,
              sizeof(gpu_model_image)) == XAIOS_OK);

  const xaios_arena_t *kv0 = 0;
  const xaios_arena_t *kv1 = 0;
  kassert(arena_create(5, XAIOS_ARENA_KV_CACHE, 0, "cpu-ai-kv-0", 4096, 0,
                       &kv0) == XAIOS_OK);
  kassert(arena_create(6, XAIOS_ARENA_KV_CACHE, 1, "cpu-ai-kv-1", 4096, 0,
                       &kv1) == XAIOS_OK);

  kassert(cpu_ai_runtime_bind_model_with_kv(0, 2, kv0->base, kv0->size) ==
          XAIOS_OK);
  kassert(cpu_ai_runtime_bind_model_with_kv(1, 2, kv1->base, kv1->size) ==
          XAIOS_OK);
  kassert(cpu_ai_runtime_bind_model_with_kv(2, 99, kv1->base, kv1->size) ==
          XAIOS_ERR_INVALID);
  kassert(cpu_ai_runtime_bind_model_with_kv(2, 3, kv1->base, kv1->size) ==
          XAIOS_ERR_INVALID);
  kassert(model_arena_unregister(3) == XAIOS_OK);
  kassert(cpu_ai_runtime_bind_model_with_kv(2, 2, kv1->base, 16) ==
          XAIOS_ERR_INVALID);

  const xaios_model_arena_t *shared = 0;
  kassert(model_arena_acquire(2, &shared) == XAIOS_OK);
  kassert(shared->ref_count == 3);
  kassert(model_arena_release(2) == XAIOS_OK);
  const uint8_t piece[] = {'A', 'B', 'C', 'D'};
  char output[32];
  char output1[32];
  uint64_t out = 0;
  kassert(cpu_ai_runtime_fixture_decode_piece(0, piece, sizeof(piece), output,
                                             sizeof(output), &out) ==
          XAIOS_OK);
  kassert(out == 8);
  kassert(cpu_ai_runtime_decode_count(0) == 1);
  kassert(bytes_equal(output, "1B1F2327"));
  kassert(cpu_ai_runtime_fixture_decode_piece(1, piece, sizeof(piece), output1,
                                             sizeof(output1), &out) ==
          XAIOS_OK);
  kassert(bytes_equal(output1, "1B1F2327"));
  kassert(cpu_ai_runtime_tokenizer_call_count() == 2);
  kassert(cpu_ai_runtime_runtime_call_count() == 2);
  kassert(cpu_ai_runtime_kv_write_count() == 8);
  kassert(cpu_ai_runtime_model_load_failure_count() == 3);
  kassert(cpu_ai_runtime_gpu_reject_count() == 1);
  kassert(cpu_ai_runtime_model_file_load_count() == 1);
  kassert(cpu_ai_runtime_model_file_reject_count() == 3);
  kassert(cpu_ai_runtime_model_bytes_loaded() > 0);
  kassert(cpu_ai_runtime_manifest_validation_count() == 7);
  kassert(cpu_ai_runtime_tokenizer_bind_count() == 2);
  kassert(cpu_ai_runtime_kernel_dispatch_count() == 2);
  kassert(cpu_ai_runtime_admission_reject_count() == 5);
  kassert(cpu_ai_runtime_checksum_failure_count() == 1);
  kassert(cpu_ai_runtime_unbind_model(0) == XAIOS_OK);
  kassert(cpu_ai_runtime_unbind_model(1) == XAIOS_OK);
  klog("cpu-ai-runtime: v1 fixture decode input=ABCD output=%s\n",
       output);
  kassert(cpu_ai_runtime_fixture_decode_piece(0, piece, sizeof(piece), output,
                                             sizeof(output), &out) ==
          XAIOS_ERR_INVALID);
  kassert(cpu_ai_runtime_decode_piece(0, piece, sizeof(piece), output,
                                     sizeof(output), &out) ==
          XAIOS_ERR_UNSUPPORTED);
  kassert(out == 0);
  klog("cpu-ai-runtime: production decode unsupported; fixture path is explicit\n");
  kassert(arena_destroy(5) == XAIOS_OK);
  kassert(arena_destroy(6) == XAIOS_OK);
  klog("cpu-ai-runtime: tokenizer/runtime boundary self-test passed tokenizer_calls=%lu runtime_calls=%lu\n",
       cpu_ai_runtime_tokenizer_call_count(),
       cpu_ai_runtime_runtime_call_count());
  klog("cpu-ai-runtime: multi-cell shared weights self-test passed loads=%lu shared_binds=%lu kv_writes=%lu\n",
       cpu_ai_runtime_model_load_count(),
       cpu_ai_runtime_shared_weight_bind_count(),
       cpu_ai_runtime_kv_write_count());
  klog("cpu-ai-runtime: model load failure self-test passed failures=%lu gpu_rejects=%lu\n",
       cpu_ai_runtime_model_load_failure_count(),
       cpu_ai_runtime_gpu_reject_count());
  klog("cpu-ai-runtime: model file loader self-test passed file_loads=%lu file_rejects=%lu bytes=%lu validations=%lu admission_rejects=%lu checksum_failures=%lu\n",
       cpu_ai_runtime_model_file_load_count(),
       cpu_ai_runtime_model_file_reject_count(),
       cpu_ai_runtime_model_bytes_loaded(),
       cpu_ai_runtime_manifest_validation_count(),
       cpu_ai_runtime_admission_reject_count(),
       cpu_ai_runtime_checksum_failure_count());
  klog("cpu-ai-runtime: tokenizer binding and CPU dispatch self-test passed tokenizer_binds=%lu kernel_dispatches=%lu\n",
       cpu_ai_runtime_tokenizer_bind_count(),
       cpu_ai_runtime_kernel_dispatch_count());

  /* Q8.8 matmul test: I_2x2 * I_2x2 = I_2x2 */
  {
    uint8_t mm[12 + 16];
    mm[0] = 2; mm[1] = 2; mm[2] = 2;
    for (uint32_t i = 3; i < 12; ++i) { mm[i] = 0; }
    int16_t *ma = (int16_t *)&mm[12];
    ma[0] = 256; ma[1] = 0; ma[2] = 0; ma[3] = 256;
    ma[4] = 256; ma[5] = 0; ma[6] = 0; ma[7] = 256;
    char mo[64];
    uint64_t mout = 0;
    kassert(cpu_ai_runtime_run_model(0, XAIOS_ML_MODEL_MATMUL, mm,
                                     sizeof(mm), mo, sizeof(mo),
                                     &mout) == XAIOS_OK);
    kassert(mout == 8);
    int16_t *mr = (int16_t *)mo;
    kassert(mr[0] == 256 && mr[1] == 0 && mr[2] == 0 && mr[3] == 256);
  }

  /* Q8.8 forward pass test: I_2x2 with ReLU */
  {
    uint8_t fp[12 + 16];
    fp[0] = 1; fp[1] = 2; fp[2] = 2;
    for (uint32_t i = 3; i < 12; ++i) { fp[i] = 0; }
    int16_t *fi = (int16_t *)&fp[12];
    fi[0] = 256; fi[1] = 256; fi[2] = 0; fi[3] = 256;
    fi[4] = 256; fi[5] = 0; fi[6] = 0; fi[7] = 256;
    char fo[64];
    uint64_t fout = 0;
    kassert(cpu_ai_runtime_run_model(0, XAIOS_ML_MODEL_FORWARD, fp,
                                     sizeof(fp), fo, sizeof(fo),
                                     &fout) == XAIOS_OK);
    kassert(fout == 4);
  }

  klog("cpu-ai-runtime: Q8.8 kernel self-test passed operations=%lu\n",
       cpu_ai_runtime_inference_count());
  klog("cpu-ai-runtime: self-test passed\n");
}
