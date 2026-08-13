#include <xaios_engine/service.h>

#include <string.h>

static xaios_engine_model_slot_t *find_model(xaios_engine_service_t *service,
                                              uint64_t model_id) {
  if (service == NULL || model_id == 0U) return NULL;
  for (uint64_t i = 0U; i < service->model_capacity; ++i) {
    if (service->models[i].active != 0U &&
        service->models[i].model_id == model_id) {
      return &service->models[i];
    }
  }
  return NULL;
}

static xaios_engine_session_slot_t *find_session(
    xaios_engine_service_t *service, uint64_t session_id) {
  if (service == NULL || session_id == 0U) return NULL;
  for (uint64_t i = 0U; i < service->session_capacity; ++i) {
    if (service->sessions[i].active != 0U &&
        service->sessions[i].session_id == session_id) {
      return &service->sessions[i];
    }
  }
  return NULL;
}

static int model_has_sessions(const xaios_engine_service_t *service,
                              uint64_t model_id) {
  if (service == NULL) return 0;
  for (uint64_t i = 0U; i < service->session_capacity; ++i) {
    if (service->sessions[i].active != 0U &&
        service->sessions[i].model_id == model_id) {
      return 1;
    }
  }
  return 0;
}

static xaios_engine_status_t touch_model(xaios_engine_service_t *service,
                                         xaios_engine_model_slot_t *model) {
  if (service == NULL || model == NULL) return XAIOS_ENGINE_ERR_INVALID;
  if (service->lifecycle_generation == UINT64_MAX) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  model->last_used_generation = ++service->lifecycle_generation;
  return XAIOS_ENGINE_OK;
}

static uint64_t allocate_model_id(xaios_engine_service_t *service) {
  for (uint64_t attempt = 0U; attempt <= service->model_capacity; ++attempt) {
    uint64_t candidate = service->next_model_id++;
    if (candidate != 0U && find_model(service, candidate) == NULL) {
      return candidate;
    }
  }
  return 0U;
}

static uint64_t allocate_session_id(xaios_engine_service_t *service) {
  for (uint64_t attempt = 0U; attempt <= service->session_capacity; ++attempt) {
    uint64_t candidate = service->next_session_id++;
    if (candidate != 0U && find_session(service, candidate) == NULL) {
      return candidate;
    }
  }
  return 0U;
}

static uint64_t prefix_hash(uint64_t parent, uint64_t position,
                            uint64_t generation) {
  uint64_t value = UINT64_C(0xcbf29ce484222325);
  const uint64_t words[3] = {parent, position, generation};
  for (uint32_t word = 0U; word < 3U; ++word) {
    uint64_t input = words[word];
    for (uint32_t byte = 0U; byte < 8U; ++byte) {
      value ^= input & UINT64_C(0xff);
      value *= UINT64_C(0x100000001b3);
      input >>= 8U;
    }
  }
  return value;
}

xaios_engine_status_t xaios_engine_service_init(
    xaios_engine_service_t *service, xaios_engine_model_slot_t *models,
    uint64_t model_capacity, xaios_engine_session_slot_t *sessions,
    uint64_t session_capacity) {
  if (service == NULL || models == NULL || model_capacity == 0U ||
      sessions == NULL || session_capacity == 0U ||
      model_capacity > SIZE_MAX / sizeof(*models) ||
      session_capacity > SIZE_MAX / sizeof(*sessions)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(models, 0, model_capacity * sizeof(*models));
  memset(sessions, 0, session_capacity * sizeof(*sessions));
  *service = (xaios_engine_service_t){models, model_capacity, sessions,
                                      session_capacity, 1U, 1U, 0U};
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_service_admit_model(
    xaios_engine_service_t *service, const xaios_model_v2_reader_t *reader,
    const xaios_engine_async_io_t *async_io,
    uint64_t required_backend_capabilities, uint64_t *model_id) {
  if (service == NULL || reader == NULL || model_id == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *model_id = 0U;
  xaios_engine_model_slot_t *slot = NULL;
  for (uint64_t i = 0U; i < service->model_capacity; ++i) {
    if (service->models[i].active == 0U) {
      slot = &service->models[i];
      break;
    }
  }
  if (slot == NULL) return XAIOS_ENGINE_ERR_BUSY;
  xaios_model_v2_package_t package;
  xaios_engine_status_t status = xaios_model_v2_open(reader, &package);
  if (status != XAIOS_ENGINE_OK) return status;
  const xaios_architecture_adapter_t *adapter =
      xaios_architecture_find(package.header.architecture_id);
  if (adapter == NULL) return XAIOS_ENGINE_ERR_UNSUPPORTED;
  const xaios_backend_t *backend =
      xaios_backend_select(required_backend_capabilities);
  if (backend == NULL || backend->validate() != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }
  memset(slot, 0, sizeof(*slot));
  slot->model_id = allocate_model_id(service);
  if (slot->model_id == 0U) return XAIOS_ENGINE_ERR_BUSY;
  slot->package = package;
  slot->adapter = adapter;
  slot->backend = backend;
  if (async_io != NULL) slot->async_io = *async_io;
  slot->executable =
      adapter->status >= XAIOS_ARCHITECTURE_SCALAR_CORRECTNESS_COMPLETE;
  slot->resident = 1U;
  slot->active = 1U;
  status = touch_model(service, slot);
  if (status != XAIOS_ENGINE_OK) {
    memset(slot, 0, sizeof(*slot));
    return status;
  }
  *model_id = slot->model_id;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_service_release_model(
    xaios_engine_service_t *service, uint64_t model_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (model->pin_count != 0U || model_has_sessions(service, model_id)) {
    return XAIOS_ENGINE_ERR_BUSY;
  }
  memset(model, 0, sizeof(*model));
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_service_activate_model(
    xaios_engine_service_t *service, uint64_t model_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  uint32_t was_resident = model->resident;
  model->resident = 1U;
  xaios_engine_status_t status = touch_model(service, model);
  if (status != XAIOS_ENGINE_OK) model->resident = was_resident;
  return status;
}

xaios_engine_status_t xaios_engine_service_pin_model(
    xaios_engine_service_t *service, uint64_t model_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (model->pin_count == UINT64_MAX) return XAIOS_ENGINE_ERR_OVERFLOW;
  uint32_t was_resident = model->resident;
  model->resident = 1U;
  ++model->pin_count;
  xaios_engine_status_t status = touch_model(service, model);
  if (status != XAIOS_ENGINE_OK) {
    --model->pin_count;
    model->resident = was_resident;
  }
  return status;
}

xaios_engine_status_t xaios_engine_service_unpin_model(
    xaios_engine_service_t *service, uint64_t model_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (model->pin_count == 0U) return XAIOS_ENGINE_ERR_INVALID;
  --model->pin_count;
  xaios_engine_status_t status = touch_model(service, model);
  if (status != XAIOS_ENGINE_OK) ++model->pin_count;
  return status;
}

xaios_engine_status_t xaios_engine_service_evict_model(
    xaios_engine_service_t *service, uint64_t model_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (model->pin_count != 0U || model_has_sessions(service, model_id)) {
    return XAIOS_ENGINE_ERR_BUSY;
  }
  if (model->resident == 0U) return XAIOS_ENGINE_ERR_INVALID;
  model->resident = 0U;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_service_evict_lru(
    xaios_engine_service_t *service, uint64_t *model_id) {
  if (service == NULL || model_id == NULL) return XAIOS_ENGINE_ERR_INVALID;
  *model_id = 0U;
  xaios_engine_model_slot_t *candidate = NULL;
  for (uint64_t i = 0U; i < service->model_capacity; ++i) {
    xaios_engine_model_slot_t *model = &service->models[i];
    if (model->active == 0U || model->resident == 0U ||
        model->pin_count != 0U || model_has_sessions(service, model->model_id)) {
      continue;
    }
    if (candidate == NULL ||
        model->last_used_generation < candidate->last_used_generation ||
        (model->last_used_generation == candidate->last_used_generation &&
         model->model_id < candidate->model_id)) {
      candidate = model;
    }
  }
  if (candidate == NULL) return XAIOS_ENGINE_ERR_BUSY;
  candidate->resident = 0U;
  *model_id = candidate->model_id;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_service_model_snapshot(
    const xaios_engine_service_t *service, uint64_t model_id,
    xaios_engine_model_slot_t *snapshot) {
  if (service == NULL || model_id == 0U || snapshot == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t i = 0U; i < service->model_capacity; ++i) {
    if (service->models[i].active != 0U &&
        service->models[i].model_id == model_id) {
      *snapshot = service->models[i];
      return XAIOS_ENGINE_OK;
    }
  }
  return XAIOS_ENGINE_ERR_NOT_FOUND;
}

xaios_engine_status_t xaios_engine_service_read_range_async(
    xaios_engine_service_t *service, uint64_t model_id, uint64_t offset,
    void *destination, uint64_t length,
    xaios_engine_io_completion_fn completion, void *completion_context,
    xaios_engine_io_request_id_t *request_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (model->resident == 0U) return XAIOS_ENGINE_ERR_BUSY;
  if (destination == NULL || length == 0U || completion == NULL ||
      request_id == NULL || offset > model->package.header.file_size ||
      length > model->package.header.file_size - offset) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  const xaios_engine_async_io_t *io = &model->async_io;
  if (io->submit == NULL) return XAIOS_ENGINE_ERR_UNSUPPORTED;
  if ((io->required_alignment != 0U &&
       (((uint64_t)(uintptr_t)destination % io->required_alignment) != 0U ||
        (offset % io->required_alignment) != 0U ||
        (length % io->required_alignment) != 0U)) ||
      (io->max_transfer != 0U && length > io->max_transfer)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_status_t status = touch_model(service, model);
  if (status != XAIOS_ENGINE_OK) return status;
  return io->submit(io->context, offset, destination, length, completion,
                    completion_context, request_id);
}

xaios_engine_status_t xaios_engine_service_cancel_io(
    xaios_engine_service_t *service, uint64_t model_id,
    xaios_engine_io_request_id_t request_id) {
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  return model->async_io.cancel == NULL
             ? XAIOS_ENGINE_ERR_UNSUPPORTED
             : model->async_io.cancel(model->async_io.context, request_id);
}

xaios_engine_status_t xaios_engine_session_create(
    xaios_engine_service_t *service, uint64_t model_id, uint64_t *session_id) {
  if (session_id == NULL) return XAIOS_ENGINE_ERR_INVALID;
  *session_id = 0U;
  xaios_engine_model_slot_t *model = find_model(service, model_id);
  if (model == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (model->resident == 0U) return XAIOS_ENGINE_ERR_BUSY;
  xaios_engine_status_t status = touch_model(service, model);
  if (status != XAIOS_ENGINE_OK) return status;
  for (uint64_t i = 0U; i < service->session_capacity; ++i) {
    xaios_engine_session_slot_t *slot = &service->sessions[i];
    if (slot->active != 0U) continue;
    memset(slot, 0, sizeof(*slot));
    slot->session_id = allocate_session_id(service);
    if (slot->session_id == 0U) return XAIOS_ENGINE_ERR_BUSY;
    slot->model_id = model_id;
    slot->generation = 1U;
    slot->prefix_hash = prefix_hash(0U, 0U, slot->generation);
    slot->active = 1U;
    *session_id = slot->session_id;
    return XAIOS_ENGINE_OK;
  }
  return XAIOS_ENGINE_ERR_BUSY;
}

xaios_engine_status_t xaios_engine_session_append(
    xaios_engine_service_t *service, uint64_t session_id,
    uint64_t position_count) {
  xaios_engine_session_slot_t *session = find_session(service, session_id);
  if (session == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (position_count == 0U || position_count > UINT64_MAX - session->position) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  session->position += position_count;
  session->transaction_open = 1U;
  session->prefix_hash = prefix_hash(session->parent_session_id,
                                     session->position, session->generation);
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_session_fork(
    xaios_engine_service_t *service, uint64_t parent_session_id,
    uint64_t *child_session_id) {
  xaios_engine_session_slot_t *parent =
      find_session(service, parent_session_id);
  if (parent == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  xaios_engine_status_t status = xaios_engine_session_create(
      service, parent->model_id, child_session_id);
  if (status != XAIOS_ENGINE_OK) return status;
  xaios_engine_session_slot_t *child = find_session(service, *child_session_id);
  child->parent_session_id = parent_session_id;
  child->position = parent->position;
  child->committed_position = parent->position;
  child->prefix_hash = parent->prefix_hash;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_session_commit(
    xaios_engine_service_t *service, uint64_t session_id) {
  xaios_engine_session_slot_t *session = find_session(service, session_id);
  if (session == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (session->transaction_open == 0U) return XAIOS_ENGINE_ERR_INVALID;
  if (session->generation == UINT64_MAX) return XAIOS_ENGINE_ERR_INVALID;
  session->committed_position = session->position;
  session->transaction_open = 0U;
  ++session->generation;
  session->prefix_hash = prefix_hash(session->parent_session_id,
                                     session->position, session->generation);
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_session_rollback(
    xaios_engine_service_t *service, uint64_t session_id) {
  xaios_engine_session_slot_t *session = find_session(service, session_id);
  if (session == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  if (session->transaction_open == 0U) return XAIOS_ENGINE_ERR_INVALID;
  if (session->generation == UINT64_MAX) return XAIOS_ENGINE_ERR_INVALID;
  session->position = session->committed_position;
  session->transaction_open = 0U;
  ++session->generation;
  session->prefix_hash = prefix_hash(session->parent_session_id,
                                     session->position, session->generation);
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_session_destroy(
    xaios_engine_service_t *service, uint64_t session_id) {
  xaios_engine_session_slot_t *session = find_session(service, session_id);
  if (session == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  for (uint64_t i = 0U; i < service->session_capacity; ++i) {
    if (service->sessions[i].active != 0U &&
        service->sessions[i].parent_session_id == session_id) {
      return XAIOS_ENGINE_ERR_BUSY;
    }
  }
  memset(session, 0, sizeof(*session));
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_engine_session_snapshot(
    const xaios_engine_service_t *service, uint64_t session_id,
    xaios_engine_session_slot_t *snapshot) {
  if (service == NULL || snapshot == NULL) return XAIOS_ENGINE_ERR_INVALID;
  for (uint64_t i = 0U; i < service->session_capacity; ++i) {
    if (service->sessions[i].active != 0U &&
        service->sessions[i].session_id == session_id) {
      *snapshot = service->sessions[i];
      return XAIOS_ENGINE_OK;
    }
  }
  return XAIOS_ENGINE_ERR_NOT_FOUND;
}

xaios_engine_status_t xaios_engine_service_decode(
    xaios_engine_service_t *service, uint64_t session_id) {
  xaios_engine_session_slot_t *session = find_session(service, session_id);
  if (session == NULL) return XAIOS_ENGINE_ERR_NOT_FOUND;
  xaios_engine_model_slot_t *model = find_model(service, session->model_id);
  return model != NULL && model->resident != 0U && model->executable != 0U
             ? model->backend->decode(NULL)
             : XAIOS_ENGINE_ERR_UNSUPPORTED;
}
