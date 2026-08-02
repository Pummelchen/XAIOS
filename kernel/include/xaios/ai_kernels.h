#ifndef XAIOS_AI_KERNELS_H
#define XAIOS_AI_KERNELS_H

#include <xaios/status.h>
#include <xaios/types.h>

/*
 * Optimized AI Compute Kernels for AArch64
 *
 * - NEON SIMD vectorization (8-16× speedup)
 * - Multi-threaded matrix multiplication
 * - Multiple quantization formats (FP32, FP16, INT8, INT4, Q8.8)
 *
 * All kernels are optimized for ARM NEON and scale across multiple cores.
 */

/* Quantization formats */
typedef enum xaios_quantization {
  XAIOS_QUANT_FP32 = 0,   /* 32-bit float, 4 bytes/param */
  XAIOS_QUANT_FP16 = 1,   /* 16-bit float, 2 bytes/param */
  XAIOS_QUANT_INT8 = 2,   /* 8-bit integer, 1 byte/param */
  XAIOS_QUANT_INT4 = 3,   /* 4-bit integer, 0.5 bytes/param */
  XAIOS_QUANT_Q88 = 4,    /* Q8.8 fixed-point, 2 bytes/param (legacy) */
  XAIOS_QUANT_INT6 = 5,   /* 6-bit integer, 0.75 bytes/param (Qwen optimized) */
} xaios_quantization_t;

/* Work unit for multi-threaded matmul */
typedef struct xaios_matmul_work {
  const void *mat_a;
  const void *mat_b;
  void *result;
  uint32_t row_start;
  uint32_t row_end;
  uint32_t cols_a;
  uint32_t cols_b;
  xaios_quantization_t quant;
} xaios_matmul_work_t;

/* Activation functions */
typedef enum xaios_activation {
  XAIOS_ACT_LINEAR = 0,   /* No activation */
  XAIOS_ACT_RELU = 1,     /* ReLU: max(0, x) */
  XAIOS_ACT_SIGMOID = 2,  /* Sigmoid: 1 / (1 + exp(-x)) */
  XAIOS_ACT_TANH = 3,     /* Tanh */
} xaios_activation_t;

/*
 * NEON-optimized matrix multiplication
 *
 * Computes: result = mat_a @ mat_b
 * Dimensions: (rows_a × cols_a) @ (cols_a × cols_b) → (rows_a × cols_b)
 *
 * Automatically selects optimized kernel based on quantization format.
 */
void ai_kernel_matmul(const void *mat_a, const void *mat_b, void *result,
                     uint32_t rows_a, uint32_t cols_a, uint32_t cols_b,
                     xaios_quantization_t quant);

/*
 * Multi-threaded matrix multiplication
 *
 * Splits work across num_threads cores. Each thread processes a row range.
 * Caller must ensure thread safety and synchronization.
 */
void ai_kernel_matmul_multithread(const xaios_matmul_work_t *work_units,
                                  uint32_t num_threads);

/*
 * Forward pass with activation
 *
 * Computes: output = activation(matmul(input, weights) + bias)
 */
void ai_kernel_forward(const void *input, const void *weights,
                      const void *bias, void *output,
                      uint32_t batch, uint32_t in_dim, uint32_t out_dim,
                      xaios_quantization_t quant, xaios_activation_t activation);

/*
 * Quantization conversion utilities
 */
xaios_status_t ai_kernel_quantize_fp32_to_int8(const float *fp32, int8_t *int8,
                                               float *scales, uint32_t count);
xaios_status_t ai_kernel_quantize_fp32_to_int6(const float *fp32, int8_t *int6,
                                               float *scales, uint32_t count);
xaios_status_t ai_kernel_quantize_fp32_to_int4(const float *fp32, int8_t *int4,
                                               float *scales, uint32_t count);
xaios_status_t ai_kernel_dequantize_int8_to_fp32(const int8_t *int8,
                                                 const float *scales,
                                                 float *fp32, uint32_t count);
xaios_status_t ai_kernel_dequantize_int6_to_fp32(const int8_t *int6,
                                                 const float *scales,
                                                 float *fp32, uint32_t count);

/*
 * Paged attention kernel (for LLM KV cache)
 *
 * Computes attention with paged KV cache for memory efficiency.
 */
void ai_kernel_paged_attention(const void *query, const void **kv_pages,
                              const uint32_t *page_table, void *output,
                              uint32_t num_tokens, uint32_t head_dim,
                              uint32_t num_pages, uint32_t block_size);

/*
 * Memory prefetching utilities
 *
 * Prefetches data into CPU cache to hide memory latency.
 * Provides 10-20% speedup for memory-bound operations.
 */

/* Prefetch data for reading (low temporal locality) */
static inline void ai_prefetch_read_once(const void *addr) {
  __builtin_prefetch(addr, 0, 0);
}

/* Prefetch data for reading (high temporal locality) */
static inline void ai_prefetch_read_keep(const void *addr) {
  __builtin_prefetch(addr, 0, 3);
}

/* Prefetch data for writing (low temporal locality) */
static inline void ai_prefetch_write_once(const void *addr) {
  __builtin_prefetch(addr, 1, 0);
}

/* Prefetch data for writing (high temporal locality) */
static inline void ai_prefetch_write_keep(const void *addr) {
  __builtin_prefetch(addr, 1, 3);
}

/* Prefetch next layer weights while computing current layer */
static inline void ai_prefetch_next_layer(const void *current_weights,
                                         const void *next_weights,
                                         uint64_t weight_bytes) {
  (void)current_weights;
  /* Prefetch entire next layer with high locality (will be used soon) */
  const uint8_t *bytes = (const uint8_t *)next_weights;
  for (uint64_t i = 0; i < weight_bytes; i += 64) {  /* Cache line size */
    __builtin_prefetch(&bytes[i], 0, 3);
  }
}

/*
 * Heterogeneous Scheduling Utilities
 *
 * Routes work to appropriate CPU cores based on workload type.
 * Performance cores for compute-heavy, efficiency cores for light work.
 */

/* Core types */
typedef enum xaios_core_type {
  XAIOS_CORE_EFFICIENCY = 0,  /* Low-power, high-efficiency */
  XAIOS_CORE_PERFORMANCE = 1, /* High-performance, power-hungry */
} xaios_core_type_t;

/* Determine best core type for workload */
static inline xaios_core_type_t ai_select_core_type(uint64_t compute_intensity,
                                                    uint64_t memory_bytes) {
  /* Heuristic: high compute + large memory = performance core */
  if (compute_intensity > 1000 && memory_bytes > 65536) {
    return XAIOS_CORE_PERFORMANCE;
  }
  return XAIOS_CORE_EFFICIENCY;
}

/*
 * Model Compilation Interface
 *
 * Implementations may compile model graphs to optimized kernels at load time.
 */

/* Compiled kernel descriptor */
typedef struct xaios_compiled_kernel {
  uint32_t kernel_id;
  uint32_t input_dims[4];
  uint32_t output_dims[4];
  xaios_quantization_t quant;
  void (*execute)(const void *input, void *output);  /* Generated function */
} xaios_compiled_kernel_t;

/* Compile a model graph to an optimized kernel. */
xaios_status_t ai_compile_model(const char *model_graph,
                                xaios_compiled_kernel_t *kernel_out);

/* Execute compiled kernel */
xaios_status_t ai_execute_compiled(const xaios_compiled_kernel_t *kernel,
                                   const void *input,
                                   void *output,
                                   uint64_t input_bytes,
                                   uint64_t output_bytes);

/*
 * BPE Tokenizer Interface
 */
#include <xaios/bpe_tokenizer.h>

xaios_status_t ai_bpe_tokenizer_init(const uint8_t *data, uint64_t size,
                                     xaios_bpe_tokenizer_t *tokenizer);
xaios_status_t ai_bpe_tokenize(xaios_bpe_tokenizer_t *tokenizer,
                               const char *input, uint32_t input_len,
                               uint32_t *output_tokens,
                               uint32_t *token_count,
                               uint32_t max_tokens);
xaios_status_t ai_bpe_detokenize(xaios_bpe_tokenizer_t *tokenizer,
                                 const uint32_t *tokens,
                                 uint32_t token_count,
                                 char *output, uint32_t *output_len,
                                 uint32_t max_output_len);
uint32_t ai_bpe_vocab_size(xaios_bpe_tokenizer_t *tokenizer);
const char *ai_bpe_get_token(xaios_bpe_tokenizer_t *tokenizer,
                              uint32_t token_id);

/*
 * Rotary Position Embedding (RoPE)
 */
void ai_kernel_rope_apply(float *query, float *key,
                         uint32_t num_tokens, uint32_t head_dim,
                         uint32_t position_offset, float theta_base);

#endif
