#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/socket_buffer.h>
#include <xaios/spinlock.h>

/* Pool of socket buffers with in-use tracking */
typedef struct sockbuf_pool_entry {
  socket_buffer_t buf;
  uint32_t in_use;
} sockbuf_pool_entry_t;

static sockbuf_pool_entry_t g_pool[SOCKET_BUFFER_COUNT];
static xaios_spinlock_t g_sockbuf_lock;

void sockbuf_init(socket_buffer_t *buf) {
  if (buf == 0) {
    return;
  }
  buf->head = 0;
  buf->tail = 0;
  buf->count = 0;
}

uint32_t sockbuf_write(socket_buffer_t *buf, const uint8_t *data,
                        uint32_t len) {
  if (buf == 0 || data == 0 || len == 0) {
    return 0;
  }
  uint32_t space = SOCKET_BUFFER_SIZE - buf->count;
  uint32_t to_write = (len < space) ? len : space;
  for (uint32_t i = 0; i < to_write; ++i) {
    buf->data[buf->head] = data[i];
    buf->head = (buf->head + 1U) % SOCKET_BUFFER_SIZE;
  }
  buf->count += to_write;
  return to_write;
}

uint32_t sockbuf_read(socket_buffer_t *buf, uint8_t *data, uint32_t len) {
  if (buf == 0 || data == 0 || len == 0) {
    return 0;
  }
  uint32_t to_read = (len < buf->count) ? len : buf->count;
  for (uint32_t i = 0; i < to_read; ++i) {
    data[i] = buf->data[buf->tail];
    buf->tail = (buf->tail + 1U) % SOCKET_BUFFER_SIZE;
  }
  buf->count -= to_read;
  return to_read;
}

uint32_t sockbuf_discard(socket_buffer_t *buf, uint32_t len) {
  if (buf == 0 || len == 0U) return 0;
  uint32_t to_discard = len < buf->count ? len : buf->count;
  buf->tail = (buf->tail + to_discard) % SOCKET_BUFFER_SIZE;
  buf->count -= to_discard;
  return to_discard;
}

uint32_t sockbuf_available(const socket_buffer_t *buf) {
  if (buf == 0) {
    return 0;
  }
  return SOCKET_BUFFER_SIZE - buf->count;
}

uint32_t sockbuf_used(const socket_buffer_t *buf) {
  if (buf == 0) {
    return 0;
  }
  return buf->count;
}

void sockbuf_pool_init(void) {
  xaios_spin_init(&g_sockbuf_lock);
  for (uint32_t i = 0; i < SOCKET_BUFFER_COUNT; ++i) {
    g_pool[i].in_use = 0;
    sockbuf_init(&g_pool[i].buf);
  }
}

socket_buffer_t *sockbuf_alloc(void) {
  xaios_spin_lock(&g_sockbuf_lock);
  for (uint32_t i = 0; i < SOCKET_BUFFER_COUNT; ++i) {
    if (g_pool[i].in_use == 0) {
      g_pool[i].in_use = 1;
      sockbuf_init(&g_pool[i].buf);
      xaios_spin_unlock(&g_sockbuf_lock);
      return &g_pool[i].buf;
    }
  }
  xaios_spin_unlock(&g_sockbuf_lock);
  klog("sockbuf: pool exhausted (all %u buffers in use)\n",
       SOCKET_BUFFER_COUNT);
  return 0;
}

void sockbuf_free(socket_buffer_t *buf) {
  if (buf == 0) {
    return;
  }
  xaios_spin_lock(&g_sockbuf_lock);
  for (uint32_t i = 0; i < SOCKET_BUFFER_COUNT; ++i) {
    if (&g_pool[i].buf == buf) {
      g_pool[i].in_use = 0;
      sockbuf_init(&g_pool[i].buf);
      xaios_spin_unlock(&g_sockbuf_lock);
      return;
    }
  }
  xaios_spin_unlock(&g_sockbuf_lock);
}

void sockbuf_self_test(void) {
  socket_buffer_t test_buf;
  sockbuf_init(&test_buf);

  /* Basic write/read round-trip */
  uint8_t wdata[16];
  for (uint32_t i = 0; i < 16; ++i) {
    wdata[i] = (uint8_t)(i & 0xFF);
  }
  uint32_t written = sockbuf_write(&test_buf, wdata, 16);
  kassert(written == 16);
  kassert(sockbuf_used(&test_buf) == 16);
  kassert(sockbuf_available(&test_buf) == SOCKET_BUFFER_SIZE - 16);

  uint8_t rdata[16];
  uint32_t rd = sockbuf_read(&test_buf, rdata, 16);
  kassert(rd == 16);
  kassert(sockbuf_used(&test_buf) == 0);
  for (uint32_t i = 0; i < 16; ++i) {
    kassert(rdata[i] == (uint8_t)(i & 0xFF));
  }

  written = sockbuf_write(&test_buf, wdata, 16U);
  kassert(written == 16U);
  kassert(sockbuf_discard(&test_buf, 7U) == 7U);
  kassert(sockbuf_used(&test_buf) == 9U);
  kassert(sockbuf_discard(&test_buf, 32U) == 9U);
  kassert(sockbuf_used(&test_buf) == 0U);

  /* Wrap-around: fill near capacity, read some, write more */
  uint8_t big[4090];
  for (uint32_t i = 0; i < 4090; ++i) {
    big[i] = (uint8_t)(i & 0xFF);
  }
  sockbuf_init(&test_buf);
  written = sockbuf_write(&test_buf, big, 4090);
  kassert(written == 4090);
  rd = sockbuf_read(&test_buf, big, 4090);
  kassert(rd == 4090);
  /* Now head/tail are near end; write 20 bytes (wraps around) */
  uint8_t wrap[20];
  for (uint32_t i = 0; i < 20; ++i) {
    wrap[i] = (uint8_t)(0xA0 + i);
  }
  written = sockbuf_write(&test_buf, wrap, 20);
  kassert(written == 20);
  uint8_t rwrap[20];
  rd = sockbuf_read(&test_buf, rwrap, 20);
  kassert(rd == 20);
  for (uint32_t i = 0; i < 20; ++i) {
    kassert(rwrap[i] == (uint8_t)(0xA0 + i));
  }

  /* Full buffer: write should return partial */
  sockbuf_init(&test_buf);
  uint8_t full[SOCKET_BUFFER_SIZE];
  written = sockbuf_write(&test_buf, full, SOCKET_BUFFER_SIZE);
  kassert(written == SOCKET_BUFFER_SIZE);
  written = sockbuf_write(&test_buf, full, 1);
  kassert(written == 0); /* no space */

  /* Empty buffer: read should return 0 */
  sockbuf_init(&test_buf);
  rd = sockbuf_read(&test_buf, full, 1);
  kassert(rd == 0);

  /* Pool alloc/free */
  sockbuf_pool_init();
  socket_buffer_t *p1 = sockbuf_alloc();
  kassert(p1 != 0);
  kassert(sockbuf_used(p1) == 0);
  sockbuf_free(p1);

  klog("sockbuf: self-test passed\n");
}
