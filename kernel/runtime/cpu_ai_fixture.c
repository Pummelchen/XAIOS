/* Deterministic CPU fixture path and its boot self-test.
 *
 * Moved verbatim out of kernel/runtime/cpu_ai_runtime.c so no source file
 * exceeds 500 lines. This is the fixture execution group: the byte-table
 * tokenizer encoder, the key-value recorder, the deterministic CPU kernel,
 * the dispatch that selects it, and cpu_ai_runtime_self_test() -- which is
 * the boot consumer that drives the whole fixture path. See
 * cpu_ai_runtime_internal.h for the shared declarations.
 *
 * The two entry points the cell-level code in cpu_ai_runtime.c calls are
 * cpu_ai_fixture_encode() and cpu_ai_fixture_decode(); the rest stay static.
 * Nothing here takes a lock: the caller in cpu_ai_runtime.c holds the CPU AI
 * guard around the whole decode, exactly as before the split.
 */

#include "cpu_ai_runtime_internal.h"

#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/model_arena.h>

static const char k_hex[] = "0123456789ABCDEF";

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

xaios_status_t cpu_ai_fixture_encode(xaios_cpu_ai_runtime_cell_t *cell,
                                     const uint8_t *piece, uint64_t piece_bytes,
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
    ++g_cpu_ai_tokenizer_call_count;
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
  g_cpu_ai_kv_write_count += token_count;
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
  ++g_cpu_ai_runtime_call_count;
  return XAIOS_OK;
}

/* Legacy scalar kernels replaced by NEON-optimized ai_kernels.c */
/* matmul_q88_scalar() now dispatches to ai_kernel_matmul() with XAIOS_QUANT_Q88 */
/* forward_pass_q88 now dispatches to ai_kernel_forward() */

xaios_status_t cpu_ai_fixture_decode(xaios_cpu_ai_runtime_cell_t *cell,
                                     const cpu_ai_token_t *tokens,
                                     uint64_t token_count, char *output,
                                     uint64_t output_capacity,
                                     uint64_t *output_bytes) {
  if (cell == 0 || tokens == 0 || output == 0 || output_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }

  ++g_cpu_ai_kernel_dispatch_count;
  if (cell->runtime_id == CPU_AI_RUNTIME_DETERMINISTIC) {
    return deterministic_cpu_kernel(cell, tokens, token_count, output,
                                    output_capacity, output_bytes);
  }

  return XAIOS_ERR_INVALID;
}

typedef struct {
  cpu_ai_model_manifest_t manifest;
  uint8_t weights[32];
  uint8_t tokenizer[256];
} cpu_ai_test_model_image_t;

static void fill_test_model_image(cpu_ai_test_model_image_t *image,
                                  uint32_t flags, uint64_t tokenizer_size,
                                  uint32_t corrupt_hash) {
  cpu_ai_bytes_zero(image, sizeof(*image));
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
      cpu_ai_manifest_payload_hash((const uint8_t *)image, &image->manifest);
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
  kassert(cpu_ai_manifest_register_bytes(3, "bad-checksum-model",
                                         &bad_checksum_image,
                                         sizeof(bad_checksum_image)) ==
          XAIOS_ERR_INVALID);
  kassert(cpu_ai_manifest_register_bytes(3, "bad-tokenizer-model",
                                         &bad_tokenizer_image,
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
