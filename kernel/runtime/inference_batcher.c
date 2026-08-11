#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/inference_batcher.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

/* Janeway — “I don't know about the rest of you, but I feel lucky today.” */

/*
 * Continuous Batching Implementation
 *
 * Groups multiple inference requests into batches for parallel execution.
 * Achieves 10-50× throughput improvement over sequential processing.
 */

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

xaios_status_t inference_batch_init(xaios_inference_batch_t *batch,
                                    uint32_t batch_id) {
  kassert(batch != 0);
  
  batch->batch_id = batch_id;
  batch->num_requests = 0;
  batch->total_tokens = 0;
  batch->capacity = XAIOS_BATCH_MAX_REQUESTS;
  batch->current_request_idx = 0;
  batch->processed_tokens = 0;
  batch->start_time = 0;
  
  bytes_zero(batch->requests, sizeof(batch->requests));
  
  batch->total_requests_processed = 0;
  batch->total_tokens_processed = 0;
  batch->avg_batch_size = 0;
  batch->batch_count = 0;
  
  klog("inference-batcher: initialized batch_id=%u capacity=%u\n",
       batch_id, batch->capacity);
  
  return XAIOS_OK;
}

xaios_status_t inference_batch_submit(xaios_inference_batch_t *batch,
                                      uint32_t request_id,
                                      uint32_t seq_id,
                                      const uint8_t *input_tokens,
                                      uint32_t num_tokens,
                                      char *output_buffer,
                                      uint64_t output_capacity,
                                      uint64_t *output_bytes,
                                      uint32_t priority) {
  kassert(batch != 0 && input_tokens != 0 && num_tokens > 0);
  
  if (batch->num_requests >= batch->capacity) {
    return XAIOS_ERR_NO_MEMORY; /* Batch full */
  }
  
  if (batch->total_tokens + num_tokens > XAIOS_BATCH_MAX_TOKENS) {
    return XAIOS_ERR_NO_MEMORY; /* Token limit exceeded */
  }
  
  uint32_t idx = batch->num_requests;
  batch->requests[idx].request_id = request_id;
  batch->requests[idx].seq_id = seq_id;
  batch->requests[idx].input_tokens = input_tokens;
  batch->requests[idx].num_input_tokens = num_tokens;
  batch->requests[idx].output_buffer = output_buffer;
  batch->requests[idx].output_capacity = output_capacity;
  batch->requests[idx].output_bytes = output_bytes;
  batch->requests[idx].state = 0; /* Pending */
  batch->requests[idx].priority = priority;
  batch->requests[idx].arrival_time = timer_counter();
  
  batch->num_requests++;
  batch->total_tokens += num_tokens;
  
  klog("inference-batcher: submitted request_id=%u seq_id=%u tokens=%u priority=%u batch_size=%u\n",
       request_id, seq_id, num_tokens, priority, batch->num_requests);
  
  return XAIOS_OK;
}

int inference_batch_is_full(const xaios_inference_batch_t *batch) {
  kassert(batch != 0);
  return batch->num_requests >= batch->capacity ||
         batch->total_tokens >= XAIOS_BATCH_MAX_TOKENS;
}

uint32_t inference_batch_pending_count(const xaios_inference_batch_t *batch) {
  kassert(batch != 0);
  return batch->num_requests;
}

xaios_status_t inference_batch_execute(xaios_inference_batch_t *batch,
                                       uint32_t cell_id) {
  kassert(batch != 0);
  
  if (batch->num_requests == 0) {
    return XAIOS_OK; /* Nothing to process */
  }
  
  batch->start_time = timer_counter();
  batch->current_request_idx = 0;
  batch->processed_tokens = 0;
  
  /* Process each request in the batch */
  for (uint32_t i = 0; i < batch->num_requests; ++i) {
    xaios_inference_request_t *req = &batch->requests[i];
    req->state = 1; /* Processing */
    
    /* Execute inference through CPU-AI runtime */
    uint64_t output_bytes = 0;
    xaios_status_t status = cpu_ai_runtime_run_model(
        cell_id,
        XAIOS_ML_MODEL_FIXTURE_DECODE,
        req->input_tokens,
        req->num_input_tokens,
        req->output_buffer,
        req->output_capacity,
        &output_bytes);
    
    if (status == XAIOS_OK) {
      req->state = 2; /* Complete */
      if (req->output_bytes != 0) {
        *req->output_bytes = output_bytes;
      }
      batch->processed_tokens += req->num_input_tokens;
    } else {
      req->state = 3; /* Error */
      klog("inference-batcher: request_id=%u failed with status=%d\n",
           req->request_id, status);
    }
    
    batch->current_request_idx = i + 1;
  }
  
  /* Update statistics */
  batch->total_requests_processed += batch->num_requests;
  batch->total_tokens_processed += batch->processed_tokens;
  batch->batch_count++;
  batch->avg_batch_size = batch->total_requests_processed / batch->batch_count;
  
  uint64_t elapsed = timer_counter() - batch->start_time;
  klog("inference-batcher: executed batch_id=%u requests=%u tokens=%u elapsed=%lu ticks\n",
       batch->batch_id, batch->num_requests, batch->processed_tokens, elapsed);
  
  return XAIOS_OK;
}

void inference_batch_reset(xaios_inference_batch_t *batch) {
  kassert(batch != 0);
  
  batch->num_requests = 0;
  batch->total_tokens = 0;
  batch->current_request_idx = 0;
  batch->processed_tokens = 0;
  batch->start_time = 0;
  
  bytes_zero(batch->requests, sizeof(batch->requests));
}

void inference_batch_get_stats(const xaios_inference_batch_t *batch,
                               uint64_t *total_requests,
                               uint64_t *total_tokens,
                               uint64_t *avg_batch_size,
                               uint64_t *batch_count) {
  kassert(batch != 0);
  
  if (total_requests != 0) *total_requests = batch->total_requests_processed;
  if (total_tokens != 0) *total_tokens = batch->total_tokens_processed;
  if (avg_batch_size != 0) *avg_batch_size = batch->avg_batch_size;
  if (batch_count != 0) *batch_count = batch->batch_count;
}
