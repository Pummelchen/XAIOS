#include <xaios_engine/inference.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct file_reader_context {
  FILE *file;
} file_reader_context_t;

typedef struct async_test_context {
  uint8_t source[8192];
  uint32_t completions;
  uint32_t cancellations;
  xaios_engine_status_t completion_status;
  uint64_t completion_bytes;
} async_test_context_t;

static void async_completion(void *opaque,
                             xaios_engine_io_request_id_t request_id,
                             xaios_engine_status_t status,
                             uint64_t bytes_transferred) {
  async_test_context_t *context = (async_test_context_t *)opaque;
  if (request_id == 7U) ++context->completions;
  context->completion_status = status;
  context->completion_bytes = bytes_transferred;
}

static xaios_engine_status_t async_submit(
    void *opaque, uint64_t offset, void *destination, uint64_t length,
    xaios_engine_io_completion_fn completion, void *completion_context,
    xaios_engine_io_request_id_t *request_id) {
  async_test_context_t *context = (async_test_context_t *)opaque;
  if (context == NULL || destination == NULL || completion == NULL ||
      request_id == NULL || offset > sizeof(context->source) ||
      length > sizeof(context->source) - offset) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memcpy(destination, context->source + offset, (size_t)length);
  *request_id = 7U;
  completion(completion_context, *request_id, XAIOS_ENGINE_OK, length);
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t async_cancel(
    void *opaque, xaios_engine_io_request_id_t request_id) {
  async_test_context_t *context = (async_test_context_t *)opaque;
  if (context == NULL || request_id != 7U) return XAIOS_ENGINE_ERR_NOT_FOUND;
  ++context->cancellations;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t file_read_at(void *opaque, uint64_t offset,
                                          void *destination, size_t length) {
  file_reader_context_t *context = (file_reader_context_t *)opaque;
  if (context == NULL || context->file == NULL || destination == NULL ||
      offset > (uint64_t)LONG_MAX ||
      fseek(context->file, (long)offset, SEEK_SET) != 0 ||
      fread(destination, 1U, length, context->file) != length) {
    return XAIOS_ENGINE_ERR_IO;
  }
  return XAIOS_ENGINE_OK;
}

static int test_interfaces(void) {
  const xaios_architecture_adapter_t *fixture =
      xaios_architecture_find("xaios_fixture");
  const xaios_architecture_adapter_t *kimi =
      xaios_architecture_find("kimi_k3");
  if (xaios_architecture_count() != 2U || fixture == NULL || kimi == NULL ||
      fixture->status != XAIOS_ARCHITECTURE_INTERFACE_ONLY ||
      kimi->status != XAIOS_ARCHITECTURE_INTERFACE_ONLY ||
      xaios_architecture_find("Qwen3.8") != NULL) {
    return 1;
  }

  const xaios_backend_t *backend = xaios_backend_select(0);
  if (backend == NULL || backend->validate() != XAIOS_ENGINE_OK ||
      backend->probe_capabilities() != XAIOS_BACKEND_CAP_SCALAR ||
      ((xaios_backend_select(XAIOS_BACKEND_CAP_AVX2) != NULL) !=
       (xaios_packed_avx2_available() != 0)) ||
      ((xaios_backend_select(XAIOS_BACKEND_CAP_NEON) != NULL) !=
       (xaios_packed_neon_available() != 0)) ||
      xaios_backend_select(XAIOS_BACKEND_CAP_SVE) != NULL ||
      xaios_backend_select(XAIOS_BACKEND_CAP_SVE2) != NULL) {
    return 1;
  }
  const float input[2] = {2.0f, 3.0f};
  const float weights[4] = {1.0f, 2.0f, -1.0f, 1.0f};
  float output[2] = {0.0f, 0.0f};
  if (backend->dense_projection(input, weights, NULL, output, 2U, 2U) !=
          XAIOS_ENGINE_OK ||
      output[0] != 8.0f || output[1] != 1.0f) {
    return 1;
  }
  return 0;
}

static int test_service_lifecycle(void) {
  xaios_engine_model_slot_t models[2];
  xaios_engine_session_slot_t sessions[4];
  xaios_engine_service_t service;
  if (xaios_engine_service_init(&service, models, 2U, sessions, 4U) !=
      XAIOS_ENGINE_OK) {
    return 1;
  }
  async_test_context_t io_context = {{0}, 0U, 0U, XAIOS_ENGINE_ERR_INVALID,
                                     0U};
  for (uint32_t i = 0U; i < sizeof(io_context.source); ++i) {
    io_context.source[i] = (uint8_t)(i * 17U);
  }
  models[0].model_id = 42U;
  models[0].active = 1U;
  models[0].package.header.file_size = sizeof(io_context.source);
  models[0].async_io = (xaios_engine_async_io_t){
      &io_context, async_submit, async_cancel, 4096U, 4096U};

  union aligned_destination {
    uint64_t alignment;
    uint8_t bytes[4096];
  } destination;
  models[0].async_io.required_alignment = sizeof(uint64_t);
  xaios_engine_io_request_id_t request_id = 0U;
  if (xaios_engine_service_read_range_async(
          &service, 42U, 4096U, destination.bytes, sizeof(destination.bytes),
          async_completion, &io_context, &request_id) != XAIOS_ENGINE_OK ||
      request_id != 7U || io_context.completions != 1U ||
      io_context.completion_status != XAIOS_ENGINE_OK ||
      io_context.completion_bytes != sizeof(destination.bytes) ||
      memcmp(destination.bytes, io_context.source + 4096U,
             sizeof(destination.bytes)) != 0 ||
      xaios_engine_service_read_range_async(
          &service, 42U, 4096U, destination.bytes + 1U,
          sizeof(destination.bytes) - sizeof(uint64_t), async_completion,
          &io_context, &request_id) != XAIOS_ENGINE_ERR_INVALID ||
      xaios_engine_service_cancel_io(&service, 42U, request_id) !=
          XAIOS_ENGINE_OK ||
      io_context.cancellations != 1U) {
    return 1;
  }

  uint64_t parent = 0U;
  uint64_t child = 0U;
  xaios_engine_session_slot_t snapshot;
  service.next_session_id = UINT64_MAX;
  if (xaios_engine_session_create(&service, 42U, &parent) != XAIOS_ENGINE_OK ||
      parent != UINT64_MAX ||
      xaios_engine_session_append(&service, parent, 10U) != XAIOS_ENGINE_OK ||
      xaios_engine_session_commit(&service, parent) != XAIOS_ENGINE_OK ||
      xaios_engine_session_append(&service, parent, 4U) != XAIOS_ENGINE_OK ||
      xaios_engine_session_rollback(&service, parent) != XAIOS_ENGINE_OK ||
      xaios_engine_session_snapshot(&service, parent, &snapshot) !=
          XAIOS_ENGINE_OK ||
      snapshot.position != 10U || snapshot.committed_position != 10U ||
      snapshot.transaction_open != 0U || snapshot.prefix_hash == 0U ||
      xaios_engine_session_fork(&service, parent, &child) != XAIOS_ENGINE_OK ||
      child != 1U ||
      xaios_engine_service_decode(&service, child) !=
          XAIOS_ENGINE_ERR_UNSUPPORTED ||
      xaios_engine_session_destroy(&service, parent) != XAIOS_ENGINE_ERR_BUSY ||
      xaios_engine_session_destroy(&service, child) != XAIOS_ENGINE_OK ||
      xaios_engine_session_destroy(&service, parent) != XAIOS_ENGINE_OK ||
      xaios_engine_service_release_model(&service, 42U) != XAIOS_ENGINE_OK) {
    return 1;
  }
  return 0;
}

static int inspect_package(const char *path) {
  FILE *file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
    if (file != NULL) {
      fclose(file);
    }
    return 1;
  }
  long end = ftell(file);
  if (end < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return 1;
  }

  file_reader_context_t context = {file};
  xaios_model_v2_reader_t reader = {&context, file_read_at, (uint64_t)end};
  xaios_model_v2_package_t package;
  xaios_engine_status_t status = xaios_model_v2_open(&reader, &package);
  if (status != XAIOS_ENGINE_OK) {
    fprintf(stderr, "model-v2 open failed: %d\n", (int)status);
    fclose(file);
    return 1;
  }

  uint8_t scratch[4096];
  for (uint64_t i = 0; i < package.header.section_count; ++i) {
    xaios_model_v2_section_t section;
    status = xaios_model_v2_read_section(&package, i, &section);
    if (status != XAIOS_ENGINE_OK ||
        xaios_model_v2_verify_section(&package, &section, scratch,
                                      sizeof(scratch)) != XAIOS_ENGINE_OK) {
      fprintf(stderr, "model-v2 section validation failed: %llu\n",
              (unsigned long long)i);
      fclose(file);
      return 1;
    }
  }
  for (uint64_t i = 0; i < package.header.tensor_count; ++i) {
    xaios_model_v2_tensor_t tensor;
    status = xaios_model_v2_read_tensor(&package, i, &tensor);
    if (status != XAIOS_ENGINE_OK) {
      fprintf(stderr, "model-v2 tensor validation failed: %d\n", (int)status);
      fclose(file);
      return 1;
    }
  }
  printf("model-v2: ok architecture=%s sections=%llu tensors=%llu\n",
         package.header.architecture_id,
         (unsigned long long)package.header.section_count,
         (unsigned long long)package.header.tensor_count);
  fclose(file);
  return 0;
}

int main(int argc, char **argv) {
  if (test_interfaces() != 0 || test_service_lifecycle() != 0) {
    fprintf(stderr, "hosted engine interface canary failed\n");
    return 1;
  }
  if (argc == 1) {
    puts("hosted engine: scalar, registry, async I/O, and session lifecycle passed");
    return 0;
  }
  if (argc != 2) {
    fprintf(stderr, "usage: test-engine [model-v2-package]\n");
    return 2;
  }
  return inspect_package(argv[1]);
}
