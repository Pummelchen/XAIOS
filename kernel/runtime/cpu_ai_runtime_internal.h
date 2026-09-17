/* Private interface shared by the split modules of the CPU AI runtime.
 *
 * kernel/runtime/cpu_ai_runtime.c was split so no source file exceeds 500
 * lines. The cell table, the reentrant guard and the model binding/unbinding
 * path stay in cpu_ai_runtime.c, because they own the mutable cell state and
 * the lock that protects it. Two cohesive groups moved beside it:
 *
 *   - cpu_ai_manifest.c: model admission -- manifest validation, payload
 *     hashing, arena registration and the model-file loader -- together with
 *     every runtime counter, its accessor and the counter reset (the
 *     metrics/reporting group). The counters are defined once there and
 *     declared extern here, so the code that increments them does not need an
 *     accessor round trip.
 *   - cpu_ai_fixture.c: the deterministic CPU fixture path (tokenizer
 *     encoding, KV recording, the deterministic kernel and its dispatch) and
 *     the boot self-test that drives it.
 *
 * Everything that crosses a file boundary carries the cpu_ai_ prefix. No #if
 * guard is involved: the moved code compiled unconditionally in the original
 * file and stays unconditional here.
 */
#ifndef XAIOS_KERNEL_RUNTIME_CPU_AI_RUNTIME_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_CPU_AI_RUNTIME_INTERNAL_H

#include <xaios/ai_kernels.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/model_arena.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* Model image constants, shared by the validator and the fixture self-test. */
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

/* Byte primitive, defined once in cpu_ai_runtime.c and used by the fixture
   self-test when it builds a scratch model image. */
void cpu_ai_bytes_zero(void *bytes, uint64_t size);

/* Model admission, defined in cpu_ai_manifest.c. */
uint64_t cpu_ai_manifest_payload_hash(const uint8_t *base,
                                      const cpu_ai_model_manifest_t *manifest);
xaios_status_t cpu_ai_manifest_validate_model(
    const xaios_model_arena_t *model,
    const cpu_ai_model_manifest_t **manifest_out);
xaios_status_t cpu_ai_manifest_register_bytes(uint32_t model_arena_id,
                                             const char *name, const void *base,
                                             uint64_t size);
void cpu_ai_metrics_reset(void);

/* Deterministic fixture path, defined in cpu_ai_fixture.c. */
xaios_status_t cpu_ai_fixture_encode(xaios_cpu_ai_runtime_cell_t *cell,
                                     const uint8_t *piece, uint64_t piece_bytes,
                                     cpu_ai_token_t *tokens,
                                     uint64_t token_capacity,
                                     uint64_t *token_count);
xaios_status_t cpu_ai_fixture_decode(xaios_cpu_ai_runtime_cell_t *cell,
                                     const cpu_ai_token_t *tokens,
                                     uint64_t token_count, char *output,
                                     uint64_t output_capacity,
                                     uint64_t *output_bytes);

/* The runtime counters, defined once in cpu_ai_manifest.c. The module prefix
   keeps them from colliding with any other kernel translation unit. */
extern uint64_t g_cpu_ai_model_load_count;
extern uint64_t g_cpu_ai_model_load_failure_count;
extern uint64_t g_cpu_ai_tokenizer_call_count;
extern uint64_t g_cpu_ai_runtime_call_count;
extern uint64_t g_cpu_ai_kv_write_count;
extern uint64_t g_cpu_ai_shared_weight_bind_count;
extern uint64_t g_cpu_ai_gpu_reject_count;
extern uint64_t g_cpu_ai_model_file_load_count;
extern uint64_t g_cpu_ai_model_file_reject_count;
extern uint64_t g_cpu_ai_model_bytes_loaded;
extern uint64_t g_cpu_ai_manifest_validation_count;
extern uint64_t g_cpu_ai_tokenizer_bind_count;
extern uint64_t g_cpu_ai_kernel_dispatch_count;
extern uint64_t g_cpu_ai_admission_reject_count;
extern uint64_t g_cpu_ai_checksum_failure_count;
extern uint64_t g_cpu_ai_inference_count;

#endif /* XAIOS_KERNEL_RUNTIME_CPU_AI_RUNTIME_INTERNAL_H */
