#ifndef XAIOS_CPU_AI_RUNTIME_H
#define XAIOS_CPU_AI_RUNTIME_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_CPU_AI_RUNTIME_MAX_CELLS 4U
#define XAIOS_ML_MODEL_FIXTURE_DECODE UINT64_C(1)
#define XAIOS_ML_MODEL_XOR UINT64_C(2)
#define XAIOS_ML_MODEL_SUM UINT64_C(3)
#define XAIOS_ML_MODEL_PARITY UINT64_C(4)
#define XAIOS_ML_MODEL_MATMUL UINT64_C(5)
#define XAIOS_ML_MODEL_FORWARD UINT64_C(6)
#define XAIOS_CPU_AI_MAX_MATRIX_DIM 16U

void cpu_ai_runtime_init(void);
xaios_status_t cpu_ai_runtime_load_model_file(uint32_t model_arena_id,
                                             const char *name,
                                             const char *path);
xaios_status_t cpu_ai_runtime_bind_model(uint32_t cell_id, uint32_t model_arena_id);
xaios_status_t cpu_ai_runtime_bind_model_with_kv(uint32_t cell_id,
                                                uint32_t model_arena_id,
                                                uint64_t kv_base,
                                                uint64_t kv_bytes);
xaios_status_t cpu_ai_runtime_unbind_model(uint32_t cell_id);
xaios_status_t cpu_ai_runtime_fixture_decode_piece(
    uint32_t cell_id, const uint8_t *piece, uint64_t piece_bytes, char *output,
    uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t cpu_ai_runtime_decode_piece(uint32_t cell_id, const uint8_t *piece,
                                         uint64_t piece_bytes, char *output,
                                         uint64_t output_capacity,
                                         uint64_t *output_bytes);
xaios_status_t cpu_ai_runtime_run_model(uint32_t cell_id, uint64_t model_kind,
                                       const uint8_t *input,
                                       uint64_t input_bytes, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes);
uint64_t cpu_ai_runtime_decode_count(uint32_t cell_id);
uint64_t cpu_ai_runtime_model_load_count(void);
uint64_t cpu_ai_runtime_model_load_failure_count(void);
uint64_t cpu_ai_runtime_tokenizer_call_count(void);
uint64_t cpu_ai_runtime_runtime_call_count(void);
uint64_t cpu_ai_runtime_kv_write_count(void);
uint64_t cpu_ai_runtime_shared_weight_bind_count(void);
uint64_t cpu_ai_runtime_gpu_reject_count(void);
uint64_t cpu_ai_runtime_model_file_load_count(void);
uint64_t cpu_ai_runtime_model_file_reject_count(void);
uint64_t cpu_ai_runtime_model_bytes_loaded(void);
uint64_t cpu_ai_runtime_manifest_validation_count(void);
uint64_t cpu_ai_runtime_tokenizer_bind_count(void);
uint64_t cpu_ai_runtime_kernel_dispatch_count(void);
uint64_t cpu_ai_runtime_admission_reject_count(void);
uint64_t cpu_ai_runtime_checksum_failure_count(void);
uint64_t cpu_ai_runtime_inference_count(void);
void cpu_ai_runtime_self_test(void);

#endif
