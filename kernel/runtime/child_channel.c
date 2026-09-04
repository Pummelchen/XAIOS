#include <xaios/child_channel.h>

#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>

typedef struct xaios_child_ring {
  uint8_t bytes[XAIOS_CHILD_CHANNEL_BUFFER_BYTES];
  uint32_t head;
  uint32_t used;
} xaios_child_ring_t;

typedef struct xaios_child_channel {
  uint64_t channel_id;
  uint64_t session_id;
  uint32_t parent_pid;
  uint32_t child_pid;
  uint32_t active;
  uint32_t state;
  /* The parent has read a status that was not RUNNING, so the exit is no
     longer news a wait should wake it for. */
  uint32_t exit_seen;
  int exit_code;
  xaios_child_ring_t parent_to_child;
  xaios_child_ring_t child_to_parent;
} xaios_child_channel_t;

static xaios_child_channel_t *g_channels;
static xaios_spinlock_t g_channel_lock = XAIOS_SPINLOCK_INIT;
static uint64_t g_next_channel_id;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static xaios_child_channel_t *find_channel_locked(uint64_t channel_id) {
  for (uint32_t i = 0U; i < XAIOS_CHILD_CHANNEL_CAPACITY; ++i) {
    if (g_channels[i].active != 0U && g_channels[i].channel_id == channel_id) {
      return &g_channels[i];
    }
  }
  return 0;
}

static xaios_status_t ring_write(xaios_child_ring_t *ring,
                                  const uint8_t *data, uint64_t size) {
  if (ring == 0 || (data == 0 && size != 0U) ||
      size > XAIOS_CHILD_CHANNEL_BUFFER_BYTES - ring->used) {
    return XAIOS_ERR_BUSY;
  }
  for (uint64_t i = 0U; i < size; ++i) {
    ring->bytes[(ring->head + ring->used + i) % XAIOS_CHILD_CHANNEL_BUFFER_BYTES] =
        data[i];
  }
  ring->used += (uint32_t)size;
  return XAIOS_OK;
}

static uint64_t ring_read(xaios_child_ring_t *ring, uint8_t *data,
                          uint64_t capacity) {
  uint64_t size = ring->used < capacity ? ring->used : capacity;
  for (uint64_t i = 0U; i < size; ++i) {
    data[i] = ring->bytes[(ring->head + i) % XAIOS_CHILD_CHANNEL_BUFFER_BYTES];
  }
  ring->head = (ring->head + (uint32_t)size) % XAIOS_CHILD_CHANNEL_BUFFER_BYTES;
  ring->used -= (uint32_t)size;
  return size;
}

void child_channel_init(void) {
  g_channels = (xaios_child_channel_t *)kheap_calloc(
      sizeof(*g_channels) * XAIOS_CHILD_CHANNEL_CAPACITY, 64U);
  kassert(g_channels != 0);
  g_next_channel_id = 1U;
  xaios_spin_init(&g_channel_lock);
  klog("child-channel: initialized capacity=%u bytes=%u\n",
       XAIOS_CHILD_CHANNEL_CAPACITY, XAIOS_CHILD_CHANNEL_BUFFER_BYTES);
}

xaios_status_t child_channel_open(uint32_t parent_pid, uint64_t session_id,
                                  uint64_t *channel_id) {
  if (parent_pid == 0U || session_id == 0U || channel_id == 0) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_channel_lock);
  for (uint32_t i = 0U; i < XAIOS_CHILD_CHANNEL_CAPACITY; ++i) {
    if (g_channels[i].active != 0U) continue;
    bytes_zero(&g_channels[i], sizeof(g_channels[i]));
    uint64_t id = g_next_channel_id++;
    if (id == 0U) id = g_next_channel_id++;
    g_channels[i].channel_id = id;
    g_channels[i].session_id = session_id;
    g_channels[i].parent_pid = parent_pid;
    g_channels[i].active = 1U;
    g_channels[i].state = XAIOS_CHILD_CHANNEL_RUNNING;
    *channel_id = id;
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_OK;
  }
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_ERR_BUSY;
}

xaios_status_t child_channel_bind_child(uint64_t channel_id,
                                        uint32_t child_pid) {
  if (channel_id == 0U || child_pid == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0 || channel->child_pid != 0U ||
      channel->state != XAIOS_CHILD_CHANNEL_RUNNING) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  channel->child_pid = child_pid;
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_OK;
}

xaios_status_t child_channel_write(uint64_t channel_id, uint32_t sender_pid,
                                   const void *data, uint64_t size) {
  if (channel_id == 0U || sender_pid == 0U || data == 0 || size == 0U ||
      size > XAIOS_CHILD_CHANNEL_BUFFER_BYTES) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0 || channel->state != XAIOS_CHILD_CHANNEL_RUNNING) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_child_ring_t *ring = 0;
  if (sender_pid == channel->parent_pid) ring = &channel->parent_to_child;
  if (sender_pid == channel->child_pid) ring = &channel->child_to_parent;
  if (ring == 0) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = ring_write(ring, (const uint8_t *)data, size);
  xaios_spin_unlock(&g_channel_lock);
  return status;
}

xaios_status_t child_channel_read(uint64_t channel_id, uint32_t reader_pid,
                                  void *data, uint64_t capacity,
                                  uint64_t *out_size) {
  if (channel_id == 0U || reader_pid == 0U || data == 0 || capacity == 0U ||
      out_size == 0 || capacity > XAIOS_CHILD_CHANNEL_BUFFER_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_child_ring_t *ring = 0;
  if (reader_pid == channel->parent_pid) ring = &channel->child_to_parent;
  if (reader_pid == channel->child_pid) ring = &channel->parent_to_child;
  if (ring == 0) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  *out_size = ring_read(ring, (uint8_t *)data, capacity);
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_OK;
}

xaios_status_t child_channel_status(uint64_t channel_id, uint32_t owner_pid,
                                    uint64_t *out_status) {
  if (channel_id == 0U || owner_pid == 0U || out_status == 0) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0 || (owner_pid != channel->parent_pid &&
                       owner_pid != channel->child_pid)) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  *out_status = ((uint64_t)(uint32_t)channel->exit_code << 32U) |
                (uint64_t)channel->state;
  if (owner_pid == channel->parent_pid &&
      channel->state != XAIOS_CHILD_CHANNEL_RUNNING) {
    channel->exit_seen = 1U;
  }
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_OK;
}

int child_channel_pending_for(uint32_t pid) {
  if (pid == 0U || g_channels == 0) return 0;
  int pending = 0;
  xaios_spin_lock(&g_channel_lock);
  for (uint32_t i = 0U; i < XAIOS_CHILD_CHANNEL_CAPACITY; ++i) {
    xaios_child_channel_t *channel = &g_channels[i];
    if (channel->active == 0U) continue;
    if (channel->parent_pid == pid &&
        (channel->child_to_parent.used != 0U ||
         (channel->state != XAIOS_CHILD_CHANNEL_RUNNING &&
          channel->exit_seen == 0U))) {
      pending = 1;
      break;
    }
    if (channel->child_pid == pid &&
        (channel->parent_to_child.used != 0U ||
         channel->state != XAIOS_CHILD_CHANNEL_RUNNING)) {
      pending = 1;
      break;
    }
  }
  xaios_spin_unlock(&g_channel_lock);
  return pending;
}

xaios_status_t child_channel_finish(uint64_t channel_id, uint32_t child_pid,
                                    int exit_code) {
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0 || child_pid == 0U || channel->child_pid != child_pid ||
      channel->state != XAIOS_CHILD_CHANNEL_RUNNING) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  channel->exit_code = exit_code;
  channel->state = exit_code == 0 ? XAIOS_CHILD_CHANNEL_EXITED
                                  : XAIOS_CHILD_CHANNEL_FAILED;
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_OK;
}

xaios_status_t child_channel_cancel(uint64_t channel_id,
                                    uint32_t parent_pid) {
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0 || channel->parent_pid != parent_pid) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  channel->state = XAIOS_CHILD_CHANNEL_CANCELLED;
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_OK;
}

xaios_status_t child_channel_release(uint64_t channel_id,
                                     uint32_t parent_pid) {
  xaios_spin_lock(&g_channel_lock);
  xaios_child_channel_t *channel = find_channel_locked(channel_id);
  if (channel == 0 || channel->parent_pid != parent_pid ||
      channel->state == XAIOS_CHILD_CHANNEL_RUNNING) {
    xaios_spin_unlock(&g_channel_lock);
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(channel, sizeof(*channel));
  xaios_spin_unlock(&g_channel_lock);
  return XAIOS_OK;
}

void child_channel_self_test(void) {
  uint64_t capacity_ids[XAIOS_CHILD_CHANNEL_CAPACITY];
  uint64_t channel_id = 0U;
  uint64_t size = 0U;
  uint64_t status = 0U;
  uint8_t buffer[8];
  static const uint8_t parent_data[] = {'p', 'i', 'n', 'g'};
  static const uint8_t child_data[] = {'p', 'o', 'n', 'g'};

  kassert(child_channel_open(101U, 1U, &channel_id) == XAIOS_OK);
  kassert(child_channel_bind_child(channel_id, 202U) == XAIOS_OK);
  kassert(child_channel_write(channel_id, 101U, parent_data,
                              sizeof(parent_data)) == XAIOS_OK);
  kassert(child_channel_read(channel_id, 202U, buffer, sizeof(buffer),
                             &size) == XAIOS_OK);
  kassert(size == sizeof(parent_data));
  for (uint32_t i = 0U; i < sizeof(parent_data); ++i) {
    kassert(buffer[i] == parent_data[i]);
  }
  kassert(child_channel_write(channel_id, 202U, child_data,
                              sizeof(child_data)) == XAIOS_OK);
  kassert(child_channel_read(channel_id, 101U, buffer, sizeof(buffer),
                             &size) == XAIOS_OK);
  kassert(size == sizeof(child_data));
  for (uint32_t i = 0U; i < sizeof(child_data); ++i) {
    kassert(buffer[i] == child_data[i]);
  }
  kassert(child_channel_finish(channel_id, 202U, 0) == XAIOS_OK);
  kassert(child_channel_status(channel_id, 101U, &status) == XAIOS_OK);
  kassert((uint32_t)status == XAIOS_CHILD_CHANNEL_EXITED);
  kassert(child_channel_release(channel_id, 101U) == XAIOS_OK);

  kassert(child_channel_open(101U, 2U, &channel_id) == XAIOS_OK);
  kassert(child_channel_cancel(channel_id, 101U) == XAIOS_OK);
  kassert(child_channel_status(channel_id, 101U, &status) == XAIOS_OK);
  kassert((uint32_t)status == XAIOS_CHILD_CHANNEL_CANCELLED);
  kassert(child_channel_release(channel_id, 101U) == XAIOS_OK);

  for (uint32_t i = 0U; i < XAIOS_CHILD_CHANNEL_CAPACITY; ++i) {
    kassert(child_channel_open(101U, UINT64_C(1000) + i,
                               &capacity_ids[i]) == XAIOS_OK);
    kassert(child_channel_cancel(capacity_ids[i], 101U) == XAIOS_OK);
  }
  kassert(child_channel_open(101U, UINT64_C(2000), &channel_id) ==
          XAIOS_ERR_BUSY);
  for (uint32_t i = 0U; i < XAIOS_CHILD_CHANNEL_CAPACITY; ++i) {
    kassert(child_channel_release(capacity_ids[i], 101U) == XAIOS_OK);
  }
  klog("child-channel: self-test passed\n");
}
