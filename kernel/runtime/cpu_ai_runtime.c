#include <xaios/assert.h>
#include <xaios/arena.h>
#include <xaios/ai_kernels.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/smp.h>
#include <xaios/model_arena.h>

#include "cpu_ai_runtime_internal.h"

/* Picard — “I am Locutus of Borg. Resistance is futile.” */

/* Split so no source file exceeds 500 lines. This file keeps the mutable cell
   table, the reentrant guard that protects it, and the model binding and
   decoding entry points. The model admission and metrics group lives in
   cpu_ai_manifest.c; the deterministic fixture kernels and their boot
   self-test live in cpu_ai_fixture.c. See cpu_ai_runtime_internal.h. */

#define XAIOS_CPU_AI_RUNTIME_STATE_EMPTY 0U
#define XAIOS_CPU_AI_RUNTIME_STATE_BOUND 1U

/* C-01: the runtime's model binding and key-value state is reached from
   the decode and run syscalls, which execute on whichever CPU the calling
   thread occupies. See xaios_reentrant_lock. */
static xaios_reentrant_lock_t g_cpu_ai_guard =
    XAIOS_REENTRANT_LOCK_INIT("CPU AI guard");

static void cpu_ai_lock(void) {
  xaios_reentrant_lock(&g_cpu_ai_guard, smp_cpu_id());
}

static void cpu_ai_unlock(void) { xaios_reentrant_unlock(&g_cpu_ai_guard); }

static xaios_cpu_ai_runtime_cell_t g_cells[XAIOS_CPU_AI_RUNTIME_MAX_CELLS];

static int validate_cell_id(uint32_t cell_id) {
  return cell_id < XAIOS_CPU_AI_RUNTIME_MAX_CELLS;
}

/* Defined here and used by cpu_ai_fixture.c's self-test, which builds a
   scratch model image; declared in cpu_ai_runtime_internal.h. */
void cpu_ai_bytes_zero(void *bytes, uint64_t size) {
  uint8_t *ptr = (uint8_t *)bytes;
  for (uint64_t i = 0; i < size; ++i) {
    ptr[i] = 0;
  }
}

void cpu_ai_runtime_init(void) {
  for (uint32_t i = 0; i < XAIOS_CPU_AI_RUNTIME_MAX_CELLS; ++i) {
    cpu_ai_bytes_zero(&g_cells[i], sizeof(g_cells[i]));
  }
  cpu_ai_metrics_reset();
  klog("cpu-ai-runtime: initialized cells=%u\n",
       XAIOS_CPU_AI_RUNTIME_MAX_CELLS);
}

xaios_status_t cpu_ai_runtime_bind_model(uint32_t cell_id,
                                        uint32_t model_arena_id) {
  return cpu_ai_runtime_bind_model_with_kv(cell_id, model_arena_id,
                                           UINT64_C(0), UINT64_C(0));
}

static xaios_status_t cpu_ai_runtime_bind_model_with_kv_unlocked(uint32_t cell_id,
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
    ++g_cpu_ai_model_load_failure_count;
    return XAIOS_ERR_INVALID;
  }

  const cpu_ai_model_manifest_t *manifest = 0;
  if (cpu_ai_manifest_validate_model(model, &manifest) != XAIOS_OK) {
    ++g_cpu_ai_model_load_failure_count;
    kassert(model_arena_release(model_arena_id) == XAIOS_OK);
    return XAIOS_ERR_INVALID;
  }

  const uint64_t kv_required = manifest->kv_bytes_required;

  if (kv_base == 0 || kv_bytes < kv_required) {
    ++g_cpu_ai_admission_reject_count;
    ++g_cpu_ai_model_load_failure_count;
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
  ++g_cpu_ai_model_load_count;
  ++g_cpu_ai_shared_weight_bind_count;
  ++g_cpu_ai_tokenizer_bind_count;

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

xaios_status_t cpu_ai_runtime_bind_model_with_kv(uint32_t cell_id,
                                                uint32_t model_arena_id,
                                                uint64_t kv_base,
                                                uint64_t kv_bytes) {
  cpu_ai_lock();
  xaios_status_t result = cpu_ai_runtime_bind_model_with_kv_unlocked(cell_id, model_arena_id, kv_base, kv_bytes);
  cpu_ai_unlock();
  return result;
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
  cpu_ai_bytes_zero(cell, sizeof(*cell));
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
  if (cpu_ai_fixture_encode(cell, piece, piece_bytes, tokens, CPU_AI_MAX_TOKENS,
                            &token_count) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  if (cpu_ai_fixture_decode(cell, tokens, token_count, output, output_capacity,
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

static xaios_status_t cpu_ai_runtime_decode_piece_unlocked(uint32_t cell_id,
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

xaios_status_t cpu_ai_runtime_decode_piece(uint32_t cell_id,
                                         const uint8_t *piece,
                                         uint64_t piece_bytes, char *output,
                                         uint64_t output_capacity,
                                         uint64_t *output_bytes) {
  cpu_ai_lock();
  xaios_status_t result = cpu_ai_runtime_decode_piece_unlocked(cell_id, piece, piece_bytes, output, output_capacity, output_bytes);
  cpu_ai_unlock();
  return result;
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

static xaios_status_t cpu_ai_runtime_run_model_unlocked(uint32_t cell_id, uint64_t model_kind,
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

  ++g_cpu_ai_kernel_dispatch_count;
  ++g_cpu_ai_runtime_call_count;
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
    ++g_cpu_ai_inference_count;
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
    ++g_cpu_ai_inference_count;
  } else {
    return XAIOS_ERR_INVALID;
  }

  *output_bytes = offset;
  klog("cpu-ai-runtime: generic ml model kind=%lu input=%lu output=%lu cpu_only=1\n",
       model_kind, input_bytes, offset);
  return XAIOS_OK;
}

xaios_status_t cpu_ai_runtime_run_model(uint32_t cell_id, uint64_t model_kind,
                                       const uint8_t *input,
                                       uint64_t input_bytes, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes) {
  cpu_ai_lock();
  xaios_status_t result = cpu_ai_runtime_run_model_unlocked(cell_id, model_kind, input, input_bytes, output, output_capacity, output_bytes);
  cpu_ai_unlock();
  return result;
}

uint64_t cpu_ai_runtime_decode_count(uint32_t cell_id) {
  if (!validate_cell_id(cell_id)) {
    return 0;
  }
  return g_cells[cell_id].decode_calls;
}
