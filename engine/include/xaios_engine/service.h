#ifndef XAIOS_ENGINE_SERVICE_H
#define XAIOS_ENGINE_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/architecture.h>
#include <xaios_engine/backend.h>
#include <xaios_engine/model_v2.h>

typedef uint64_t xaios_engine_io_request_id_t;

typedef void (*xaios_engine_io_completion_fn)(
    void *context, xaios_engine_io_request_id_t request_id,
    xaios_engine_status_t status, uint64_t bytes_transferred);

typedef xaios_engine_status_t (*xaios_engine_io_submit_fn)(
    void *context, uint64_t offset, void *destination, uint64_t length,
    xaios_engine_io_completion_fn completion, void *completion_context,
    xaios_engine_io_request_id_t *request_id);

typedef xaios_engine_status_t (*xaios_engine_io_cancel_fn)(
    void *context, xaios_engine_io_request_id_t request_id);

typedef struct xaios_engine_async_io {
  void *context;
  xaios_engine_io_submit_fn submit;
  xaios_engine_io_cancel_fn cancel;
  uint64_t required_alignment;
  uint64_t max_transfer;
} xaios_engine_async_io_t;

typedef struct xaios_engine_model_slot {
  uint64_t model_id;
  uint64_t last_used_generation;
  uint64_t pin_count;
  uint32_t active;
  uint32_t resident;
  uint32_t executable;
  xaios_model_v2_package_t package;
  const xaios_architecture_adapter_t *adapter;
  const xaios_backend_t *backend;
  xaios_engine_async_io_t async_io;
} xaios_engine_model_slot_t;

typedef struct xaios_engine_session_slot {
  uint64_t session_id;
  uint64_t model_id;
  uint64_t parent_session_id;
  uint64_t position;
  uint64_t committed_position;
  uint64_t prefix_hash;
  uint64_t generation;
  uint32_t active;
  uint32_t transaction_open;
} xaios_engine_session_slot_t;

typedef struct xaios_engine_service {
  xaios_engine_model_slot_t *models;
  uint64_t model_capacity;
  xaios_engine_session_slot_t *sessions;
  uint64_t session_capacity;
  uint64_t next_model_id;
  uint64_t next_session_id;
  uint64_t lifecycle_generation;
} xaios_engine_service_t;

xaios_engine_status_t xaios_engine_service_init(
    xaios_engine_service_t *service, xaios_engine_model_slot_t *models,
    uint64_t model_capacity, xaios_engine_session_slot_t *sessions,
    uint64_t session_capacity);
xaios_engine_status_t xaios_engine_service_admit_model(
    xaios_engine_service_t *service, const xaios_model_v2_reader_t *reader,
    const xaios_engine_async_io_t *async_io,
    uint64_t required_backend_capabilities, uint64_t *model_id);
xaios_engine_status_t xaios_engine_service_release_model(
    xaios_engine_service_t *service, uint64_t model_id);
xaios_engine_status_t xaios_engine_service_activate_model(
    xaios_engine_service_t *service, uint64_t model_id);
xaios_engine_status_t xaios_engine_service_pin_model(
    xaios_engine_service_t *service, uint64_t model_id);
xaios_engine_status_t xaios_engine_service_unpin_model(
    xaios_engine_service_t *service, uint64_t model_id);
xaios_engine_status_t xaios_engine_service_evict_model(
    xaios_engine_service_t *service, uint64_t model_id);
xaios_engine_status_t xaios_engine_service_evict_lru(
    xaios_engine_service_t *service, uint64_t *model_id);
xaios_engine_status_t xaios_engine_service_model_snapshot(
    const xaios_engine_service_t *service, uint64_t model_id,
    xaios_engine_model_slot_t *snapshot);
xaios_engine_status_t xaios_engine_service_read_range_async(
    xaios_engine_service_t *service, uint64_t model_id, uint64_t offset,
    void *destination, uint64_t length,
    xaios_engine_io_completion_fn completion, void *completion_context,
    xaios_engine_io_request_id_t *request_id);
xaios_engine_status_t xaios_engine_service_cancel_io(
    xaios_engine_service_t *service, uint64_t model_id,
    xaios_engine_io_request_id_t request_id);

xaios_engine_status_t xaios_engine_session_create(
    xaios_engine_service_t *service, uint64_t model_id, uint64_t *session_id);
xaios_engine_status_t xaios_engine_session_append(
    xaios_engine_service_t *service, uint64_t session_id,
    uint64_t position_count);
xaios_engine_status_t xaios_engine_session_fork(
    xaios_engine_service_t *service, uint64_t parent_session_id,
    uint64_t *child_session_id);
xaios_engine_status_t xaios_engine_session_commit(
    xaios_engine_service_t *service, uint64_t session_id);
xaios_engine_status_t xaios_engine_session_rollback(
    xaios_engine_service_t *service, uint64_t session_id);
xaios_engine_status_t xaios_engine_session_destroy(
    xaios_engine_service_t *service, uint64_t session_id);
xaios_engine_status_t xaios_engine_session_snapshot(
    const xaios_engine_service_t *service, uint64_t session_id,
    xaios_engine_session_slot_t *snapshot);
xaios_engine_status_t xaios_engine_service_decode(
    xaios_engine_service_t *service, uint64_t session_id);

#endif
