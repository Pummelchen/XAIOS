#ifndef XAIOS_SOCKET_BUFFER_H
#define XAIOS_SOCKET_BUFFER_H

#include <xaios/status.h>
#include <xaios/types.h>

#define SOCKET_BUFFER_SIZE 16384U
#define SOCKET_BUFFER_COUNT 32U /* 16 sockets x 2 directions */

/*
 * Circular ring buffer for socket I/O.
 * Data is written at head, read from tail.
 * count tracks bytes currently stored.
 */
typedef struct socket_buffer {
  uint8_t  data[SOCKET_BUFFER_SIZE];
  uint32_t head;   /* write position */
  uint32_t tail;   /* read position */
  uint32_t count;  /* bytes currently stored */
} socket_buffer_t;

void sockbuf_init(socket_buffer_t *buf);
uint32_t sockbuf_write(socket_buffer_t *buf, const uint8_t *data, uint32_t len);
uint32_t sockbuf_read(socket_buffer_t *buf, uint8_t *data, uint32_t len);
uint32_t sockbuf_discard(socket_buffer_t *buf, uint32_t len);
uint32_t sockbuf_available(const socket_buffer_t *buf);
uint32_t sockbuf_used(const socket_buffer_t *buf);

/* Pool allocator for socket buffers */
void sockbuf_pool_init(void);
socket_buffer_t *sockbuf_alloc(void);
void sockbuf_free(socket_buffer_t *buf);

void sockbuf_self_test(void);

#endif
