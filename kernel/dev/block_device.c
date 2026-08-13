#include <xaios/block_device.h>

static xaios_block_device_t *g_devices[XAIOS_BLOCK_MAX_DEVICES];

static uint64_t string_length_bounded(const char *value, uint64_t capacity) {
  uint64_t length = 0U;
  if (value == 0) return capacity;
  while (length < capacity && value[length] != '\0') ++length;
  return length;
}

static int strings_equal(const char *left, const char *right,
                         uint64_t capacity) {
  if (left == 0 || right == 0) return 0;
  for (uint64_t i = 0U; i < capacity; ++i) {
    if (left[i] != right[i]) return 0;
    if (left[i] == '\0') return 1;
  }
  return 0;
}

static int add_overflows(uint64_t left, uint64_t right) {
  return right > UINT64_MAX - left;
}

static int multiply_overflows(uint64_t left, uint64_t right) {
  return left != 0U && right > UINT64_MAX / left;
}

static int power_of_two(uint64_t value) {
  return value != 0U && (value & (value - 1U)) == 0U;
}

static int device_is_registered(const xaios_block_device_t *device) {
  if (device == 0 || device->registered == 0U) return 0;
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] == device) return 1;
  }
  return 0;
}

static xaios_status_t validate_range(const xaios_block_device_t *device,
                                     uint64_t byte_offset,
                                     uint64_t length) {
  if (!device_is_registered(device) || length == 0U ||
      device->info.logical_sector_size == 0U ||
      byte_offset % device->info.logical_sector_size != 0U ||
      length % device->info.logical_sector_size != 0U ||
      add_overflows(byte_offset, length) ||
      byte_offset + length > device->info.capacity_bytes) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t validate_discard_range(
    const xaios_block_device_t *device, uint64_t byte_offset,
    uint64_t length) {
  if (validate_range(device, byte_offset, length) != XAIOS_OK ||
      device->info.discard_granularity == 0U ||
      length % device->info.discard_granularity != 0U ||
      byte_offset % device->info.discard_granularity !=
          device->info.discard_alignment %
              device->info.discard_granularity) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static uint64_t transfer_limit(const xaios_block_device_t *device,
                               uint64_t remaining) {
  uint64_t limit = device->info.max_transfer_bytes;
  if (limit == 0U || limit > remaining) limit = remaining;
  return limit;
}

xaios_status_t block_device_register(
    xaios_block_device_t *device, const xaios_block_device_info_t *info,
    const xaios_block_backend_ops_t *ops, void *context) {
  if (device == 0 || info == 0 || ops == 0 || ops->read == 0 ||
      string_length_bounded(info->identifier, XAIOS_BLOCK_DEVICE_ID_MAX) ==
          XAIOS_BLOCK_DEVICE_ID_MAX ||
      string_length_bounded(info->identifier, XAIOS_BLOCK_DEVICE_ID_MAX) == 0U ||
      string_length_bounded(info->backend, XAIOS_BLOCK_BACKEND_MAX) ==
          XAIOS_BLOCK_BACKEND_MAX ||
      string_length_bounded(info->backend, XAIOS_BLOCK_BACKEND_MAX) == 0U ||
      info->capacity_bytes == 0U || info->capacity_logical_sectors == 0U ||
      !power_of_two(info->logical_sector_size) ||
      info->physical_block_size < info->logical_sector_size ||
      info->physical_block_size % info->logical_sector_size != 0U ||
      multiply_overflows(info->capacity_logical_sectors,
                         info->logical_sector_size) ||
      info->capacity_logical_sectors * info->logical_sector_size !=
          info->capacity_bytes ||
      (info->max_transfer_bytes != 0U &&
       (info->max_transfer_bytes < info->logical_sector_size ||
        info->max_transfer_bytes % info->logical_sector_size != 0U)) ||
      (info->read_only == 0U && ops->write == 0) ||
      (info->flush_supported != 0U && ops->flush == 0) ||
      (info->discard_supported != 0U &&
       (ops->discard == 0 || info->discard_granularity == 0U ||
        info->discard_granularity % info->logical_sector_size != 0U ||
        info->discard_alignment >= info->discard_granularity ||
        info->max_discard_bytes < info->discard_granularity ||
        info->max_discard_bytes % info->discard_granularity != 0U ||
        info->max_discard_ranges == 0U)) ||
      (info->write_zeroes_supported != 0U &&
       (ops->write_zeroes == 0 ||
        info->max_write_zeroes_bytes < info->logical_sector_size ||
        info->max_write_zeroes_bytes % info->logical_sector_size != 0U))) {
    return XAIOS_ERR_INVALID;
  }
  if (device->registered != 0U) return XAIOS_ERR_BUSY;
  uint32_t free_index = XAIOS_BLOCK_MAX_DEVICES;
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] != 0 &&
        strings_equal(g_devices[i]->info.identifier, info->identifier,
                      XAIOS_BLOCK_DEVICE_ID_MAX)) {
      return XAIOS_ERR_BUSY;
    }
    if (g_devices[i] == 0 && free_index == XAIOS_BLOCK_MAX_DEVICES) {
      free_index = i;
    }
  }
  if (free_index == XAIOS_BLOCK_MAX_DEVICES) return XAIOS_ERR_NO_MEMORY;
  device->info = *info;
  device->ops = ops;
  device->async_ops = 0;
  device->context = context;
  device->open_count = 0U;
  device->registered = 1U;
  g_devices[free_index] = device;
  return XAIOS_OK;
}

xaios_status_t block_device_unregister(xaios_block_device_t *device) {
  if (!device_is_registered(device)) return XAIOS_ERR_NOT_FOUND;
  if (device->open_count != 0U) return XAIOS_ERR_BUSY;
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] == device) {
      g_devices[i] = 0;
      device->registered = 0U;
      device->ops = 0;
      device->async_ops = 0;
      device->context = 0;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t block_device_set_async_ops(
    xaios_block_device_t *device, const xaios_block_async_ops_t *ops) {
  if (!device_is_registered(device) || ops == 0 || ops->submit == 0 ||
      ops->poll == 0 || ops->cancel == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (device->async_ops != 0) return XAIOS_ERR_BUSY;
  device->async_ops = ops;
  return XAIOS_OK;
}

xaios_status_t block_device_list(xaios_block_device_info_t *devices,
                                 uint64_t capacity, uint64_t *out_count) {
  if (out_count == 0 || (capacity != 0U && devices == 0)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t found = 0U;
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] == 0) continue;
    if (found < capacity) devices[found] = g_devices[i]->info;
    ++found;
  }
  *out_count = found;
  return XAIOS_OK;
}

xaios_status_t block_device_open(const char *identifier,
                                 xaios_block_device_t **out_device) {
  if (identifier == 0 || out_device == 0) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] != 0 &&
        strings_equal(g_devices[i]->info.identifier, identifier,
                      XAIOS_BLOCK_DEVICE_ID_MAX)) {
      if (g_devices[i]->open_count == UINT32_MAX) return XAIOS_ERR_BUSY;
      ++g_devices[i]->open_count;
      *out_device = g_devices[i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t block_device_close(xaios_block_device_t *device) {
  if (!device_is_registered(device) || device->open_count == 0U) {
    return XAIOS_ERR_INVALID;
  }
  --device->open_count;
  return XAIOS_OK;
}

xaios_status_t block_device_info(const xaios_block_device_t *device,
                                 xaios_block_device_info_t *out_info) {
  if (!device_is_registered(device) || out_info == 0) {
    return XAIOS_ERR_INVALID;
  }
  *out_info = device->info;
  return XAIOS_OK;
}

xaios_status_t block_device_open_count(const xaios_block_device_t *device,
                                       uint32_t *out_count) {
  if (!device_is_registered(device) || out_count == 0) {
    return XAIOS_ERR_INVALID;
  }
  *out_count = device->open_count;
  return XAIOS_OK;
}

xaios_status_t block_read(xaios_block_device_t *device, uint64_t byte_offset,
                          void *buffer, uint64_t length) {
  if (buffer == 0 || validate_range(device, byte_offset, length) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t completed = 0U;
  while (completed < length) {
    uint64_t count = transfer_limit(device, length - completed);
    xaios_status_t status = device->ops->read(
        device->context, byte_offset + completed,
        (uint8_t *)buffer + completed, count);
    if (status != XAIOS_OK) {
      ++device->info.io_errors;
      return status;
    }
    ++device->info.read_operations;
    device->info.read_bytes += count;
    completed += count;
  }
  return XAIOS_OK;
}

xaios_status_t block_write(xaios_block_device_t *device, uint64_t byte_offset,
                           const void *buffer, uint64_t length) {
  if (buffer == 0 || validate_range(device, byte_offset, length) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (device->info.read_only != 0U) return XAIOS_ERR_UNSUPPORTED;
  uint64_t completed = 0U;
  while (completed < length) {
    uint64_t count = transfer_limit(device, length - completed);
    xaios_status_t status = device->ops->write(
        device->context, byte_offset + completed,
        (const uint8_t *)buffer + completed, count);
    if (status != XAIOS_OK) {
      ++device->info.io_errors;
      return status;
    }
    ++device->info.write_operations;
    device->info.write_bytes += count;
    completed += count;
  }
  return XAIOS_OK;
}

xaios_status_t block_flush(xaios_block_device_t *device) {
  if (!device_is_registered(device)) return XAIOS_ERR_INVALID;
  if (device->info.flush_supported == 0U || device->ops->flush == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  xaios_status_t status = device->ops->flush(device->context);
  if (status != XAIOS_OK) {
    ++device->info.io_errors;
    return status;
  }
  ++device->info.flush_operations;
  return XAIOS_OK;
}

xaios_status_t block_flush_all(uint64_t *flushed, uint64_t *unsupported,
                               uint64_t *failed) {
  uint64_t completed = 0U;
  uint64_t skipped = 0U;
  uint64_t errors = 0U;
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    xaios_block_device_t *device = g_devices[i];
    if (device == 0) continue;
    if (device->info.flush_supported == 0U || device->ops->flush == 0) {
      ++skipped;
      continue;
    }
    if (block_flush(device) == XAIOS_OK) ++completed;
    else ++errors;
  }
  if (flushed != 0) *flushed = completed;
  if (unsupported != 0) *unsupported = skipped;
  if (failed != 0) *failed = errors;
  return errors == 0U ? XAIOS_OK : XAIOS_ERR_IO;
}

xaios_status_t block_discard(xaios_block_device_t *device,
                             uint64_t byte_offset, uint64_t length) {
  if (!device_is_registered(device)) return XAIOS_ERR_INVALID;
  if (device->info.read_only != 0U || device->info.discard_supported == 0U ||
      device->ops->discard == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (validate_discard_range(device, byte_offset, length) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t completed = 0U;
  while (completed < length) {
    uint64_t count = length - completed;
    if (count > device->info.max_discard_bytes) {
      count = device->info.max_discard_bytes;
    }
    xaios_status_t status = device->ops->discard(
        device->context, byte_offset + completed, count);
    if (status != XAIOS_OK) {
      ++device->info.io_errors;
      return status;
    }
    ++device->info.discard_operations;
    device->info.discarded_bytes += count;
    completed += count;
  }
  return XAIOS_OK;
}

xaios_status_t block_write_zeroes(xaios_block_device_t *device,
                                  uint64_t byte_offset, uint64_t length) {
  if (!device_is_registered(device)) return XAIOS_ERR_INVALID;
  if (device->info.read_only != 0U ||
      device->info.write_zeroes_supported == 0U ||
      device->ops->write_zeroes == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (validate_range(device, byte_offset, length) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t completed = 0U;
  while (completed < length) {
    uint64_t count = length - completed;
    if (count > device->info.max_write_zeroes_bytes) {
      count = device->info.max_write_zeroes_bytes;
    }
    xaios_status_t status = device->ops->write_zeroes(
        device->context, byte_offset + completed, count);
    if (status != XAIOS_OK) {
      ++device->info.io_errors;
      return status;
    }
    ++device->info.write_zeroes_operations;
    device->info.write_zeroes_bytes += count;
    completed += count;
  }
  return XAIOS_OK;
}

void block_async_complete(xaios_block_async_request_t *request,
                          xaios_status_t status) {
  if (request == 0 || request->state == XAIOS_BLOCK_ASYNC_COMPLETE) {
    return;
  }
  xaios_block_device_t *device = request->device;
  request->status = status;
  request->state = XAIOS_BLOCK_ASYNC_COMPLETE;
  if (device != 0 && status == XAIOS_OK) {
    if (request->operation == XAIOS_BLOCK_ASYNC_READ) {
      ++device->info.read_operations;
      device->info.read_bytes += request->length;
    } else if (request->operation == XAIOS_BLOCK_ASYNC_WRITE) {
      ++device->info.write_operations;
      device->info.write_bytes += request->length;
    } else if (request->operation == XAIOS_BLOCK_ASYNC_FLUSH) {
      ++device->info.flush_operations;
    }
  } else if (device != 0 && status != XAIOS_ERR_CANCELLED) {
    ++device->info.io_errors;
  }
  if (request->completion != 0) {
    request->completion(request, request->completion_context);
  }
}

xaios_status_t block_async_submit(
    xaios_block_device_t *device, xaios_block_async_request_t *request,
    xaios_block_async_operation_t operation, uint64_t byte_offset,
    void *buffer, uint64_t length, xaios_block_async_completion_t completion,
    void *completion_context) {
  if (!device_is_registered(device) || request == 0 ||
      request->state == XAIOS_BLOCK_ASYNC_PENDING ||
      request->state == XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED ||
      (operation != XAIOS_BLOCK_ASYNC_READ &&
       operation != XAIOS_BLOCK_ASYNC_WRITE &&
       operation != XAIOS_BLOCK_ASYNC_FLUSH)) {
    return XAIOS_ERR_INVALID;
  }
  if (operation == XAIOS_BLOCK_ASYNC_FLUSH) {
    if (buffer != 0 || length != 0U || byte_offset != 0U ||
        device->info.flush_supported == 0U || device->ops->flush == 0) {
      return XAIOS_ERR_INVALID;
    }
  } else {
    if (buffer == 0 || validate_range(device, byte_offset, length) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (operation == XAIOS_BLOCK_ASYNC_WRITE &&
        device->info.read_only != 0U) {
      return XAIOS_ERR_UNSUPPORTED;
    }
  }
  *request = (xaios_block_async_request_t){
      .operation = operation,
      .state = XAIOS_BLOCK_ASYNC_PENDING,
      .byte_offset = byte_offset,
      .buffer = buffer,
      .length = length,
      .status = XAIOS_ERR_BUSY,
      .completion = completion,
      .completion_context = completion_context,
      .device = device,
  };
  if (device->async_ops != 0) {
    xaios_status_t status =
        device->async_ops->submit(device->context, request);
    if (status != XAIOS_OK) {
      request->state = XAIOS_BLOCK_ASYNC_COMPLETE;
      request->status = status;
      request->device = 0;
    }
    return status;
  }
  xaios_status_t status = XAIOS_ERR_UNSUPPORTED;
  if (operation == XAIOS_BLOCK_ASYNC_READ) {
    status = device->ops->read(device->context, byte_offset, buffer, length);
  } else if (operation == XAIOS_BLOCK_ASYNC_WRITE) {
    status = device->ops->write(device->context, byte_offset, buffer, length);
  } else {
    status = device->ops->flush(device->context);
  }
  block_async_complete(request, status);
  return XAIOS_OK;
}

uint32_t block_async_poll(xaios_block_device_t *device, uint32_t budget) {
  if (!device_is_registered(device) || device->async_ops == 0 || budget == 0U) {
    return 0U;
  }
  return device->async_ops->poll(device->context, budget);
}

xaios_status_t block_async_cancel(xaios_block_async_request_t *request) {
  if (request == 0 || request->device == 0 ||
      request->state != XAIOS_BLOCK_ASYNC_PENDING) {
    return XAIOS_ERR_INVALID;
  }
  xaios_block_device_t *device = request->device;
  if (device->async_ops == 0) return XAIOS_ERR_UNSUPPORTED;
  xaios_status_t status =
      device->async_ops->cancel(device->context, request);
  if (status == XAIOS_OK) request->state = XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED;
  return status;
}

xaios_status_t block_device_test_reset(void) {
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] != 0 && g_devices[i]->open_count != 0U) {
      return XAIOS_ERR_BUSY;
    }
  }
  for (uint32_t i = 0U; i < XAIOS_BLOCK_MAX_DEVICES; ++i) {
    if (g_devices[i] != 0) {
      g_devices[i]->registered = 0U;
      g_devices[i]->ops = 0;
      g_devices[i]->async_ops = 0;
      g_devices[i]->context = 0;
      g_devices[i] = 0;
    }
  }
  return XAIOS_OK;
}
