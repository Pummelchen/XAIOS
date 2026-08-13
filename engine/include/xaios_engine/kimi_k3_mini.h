#ifndef XAIOS_ENGINE_KIMI_K3_MINI_H
#define XAIOS_ENGINE_KIMI_K3_MINI_H

#include <stdint.h>

#include <xaios_engine/model_v2.h>

#define XAIOS_K3_MINI_MXFP4_BLOCK_VALUES 32U

xaios_engine_status_t xaios_k3_mini_kda_step(
    const float *query, const float *key, const float *value,
    const float *decay, float beta, uint64_t key_dimension,
    uint64_t value_dimension, float *state, float *output);
xaios_engine_status_t xaios_k3_mini_mla_step(
    const float *query, const float *key, const float *value, float output_gate,
    uint64_t key_dimension, uint64_t value_dimension, float *key_cache,
    float *value_cache, uint64_t cache_capacity, uint64_t *cache_length,
    float *output, float *score_scratch);
xaios_engine_status_t xaios_k3_mini_route_topk(
    const float *logits, const float *correction_bias, uint64_t expert_count,
    uint64_t top_k, float routed_scaling_factor, uint64_t *expert_ids,
    float *expert_weights, float *score_scratch);
xaios_engine_status_t xaios_k3_mini_reduce_experts(
    const float *expert_outputs, const uint64_t *expert_ids,
    const float *expert_weights, uint64_t selected_count,
    uint64_t expert_count, uint64_t expert_stride, const float *shared_output,
    float *output);
xaios_engine_status_t xaios_k3_mini_situ(
    const float *gate, const float *up, uint64_t count, float beta,
    float linear_beta, float *output);
xaios_engine_status_t xaios_k3_mini_mxfp4_dequantize(
    const uint8_t packed[XAIOS_K3_MINI_MXFP4_BLOCK_VALUES / 2U],
    uint8_t e8m0_scale,
    float output[XAIOS_K3_MINI_MXFP4_BLOCK_VALUES]);

#endif
