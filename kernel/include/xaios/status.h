#ifndef XAIOS_STATUS_H
#define XAIOS_STATUS_H

typedef enum xaios_status {
  XAIOS_OK = 0,
  XAIOS_ERR_INVALID = -1,
  XAIOS_ERR_NO_MEMORY = -2,
  XAIOS_ERR_NOT_FOUND = -3,
  XAIOS_ERR_IO = -4,
  XAIOS_ERR_BUSY = -5,
  XAIOS_ERR_UNSUPPORTED = -6,
  XAIOS_ERR_CANCELLED = -7,
} xaios_status_t;

#endif
