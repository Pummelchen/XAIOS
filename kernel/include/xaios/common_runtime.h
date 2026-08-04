#ifndef XAIOS_COMMON_RUNTIME_H
#define XAIOS_COMMON_RUNTIME_H

#include <xaios/types.h>

#define XAIOS_COMMON_RUNTIME_INTEGRITY UINT32_C(1)
#define XAIOS_COMMON_RUNTIME_BLOCK UINT32_C(1 << 1)
#define XAIOS_COMMON_RUNTIME_VFS UINT32_C(1 << 2)
#define XAIOS_COMMON_RUNTIME_ENGINE UINT32_C(1 << 3)

uint32_t xaios_common_runtime_probe(void);

#endif
