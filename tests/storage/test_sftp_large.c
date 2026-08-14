#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <xaios_user.h>

#include "ssh_channel.h"
#include "sftp_server.h"

#define FXP_OPEN 3U
#define FXP_CLOSE 4U
#define FXP_READ 5U
#define FXP_WRITE 6U
#define FXP_FSTAT 8U
#define FXP_FSETSTAT 10U
#define FXP_EXTENDED 200U
#define FXP_STATUS 101U
#define FXP_HANDLE 102U
#define FXP_DATA 103U
#define FXP_ATTRS 105U
#define FXF_READ 1U
#define FXF_WRITE 2U
#define FXF_APPEND 4U
#define FXF_CREAT 8U
#define FXF_TRUNC 16U

static uint8_t g_response[12000];
static uint32_t g_response_size;
static uint32_t g_response_channel;
static uint64_t g_file_size;
static uint64_t g_data_base = UINT64_MAX;
static uint8_t g_data[64];
static uint32_t g_write_calls;
static uint32_t g_fsync_calls;
static uint32_t g_close_calls;
static uint32_t g_open_flags;
static int g_fail_reads;

uint32_t ssh_read_u32_be(const uint8_t *value) {
  return ((uint32_t)value[0] << 24U) | ((uint32_t)value[1] << 16U) |
         ((uint32_t)value[2] << 8U) | value[3];
}

void ssh_write_u32_be(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t length) {
  (void)sockfd;
  assert(length <= sizeof(g_response));
  memcpy(g_response, data, length);
  g_response_size = length;
  g_response_channel = remote_id;
  return 0;
}

int xaios_fs_open(const char *path, u32 flags) {
  if (strcmp(path, "/tmp/large.bin") != 0) return -1;
  g_open_flags = flags;
  if ((flags & XAIOS_MFS_OPEN_TRUNCATE) != 0U) {
    g_file_size = 0U;
    g_data_base = UINT64_MAX;
    memset(g_data, 0, sizeof(g_data));
  }
  return 11;
}

int xaios_fs_close(int fd) {
  ++g_close_calls;
  return fd == 11 ? 0 : -1;
}

s64 xaios_fs_pwrite(int fd, const void *buffer, u64 size, u64 offset) {
  if (fd != 11 || size == 0U) return -1;
  if (size > sizeof(g_data)) {
    if (offset > UINT64_MAX - size) return -1;
    if (offset + size > g_file_size) g_file_size = offset + size;
    ++g_write_calls;
    return (s64)size;
  }
  uint64_t count = size > 3U ? 3U : size;
  if (g_data_base == UINT64_MAX) g_data_base = offset;
  if (offset < g_data_base) {
    return -1;
  }
  uint64_t relative = offset - g_data_base;
  if (relative > sizeof(g_data) || count > sizeof(g_data) - relative ||
      offset > UINT64_MAX - count) {
    return -1;
  }
  memcpy(g_data + (size_t)relative, buffer, (size_t)count);
  if (offset + count > g_file_size) g_file_size = offset + count;
  ++g_write_calls;
  return (s64)count;
}

s64 xaios_fs_pread(int fd, void *buffer, u64 size, u64 offset) {
  if (fd != 11 || g_fail_reads) return -1;
  if (offset >= g_file_size) return 0;
  uint64_t count = size < g_file_size - offset ? size : g_file_size - offset;
  if (g_data_base == UINT64_MAX || offset < g_data_base) {
    return -1;
  }
  uint64_t relative = offset - g_data_base;
  if (relative > sizeof(g_data) || count > sizeof(g_data) - relative) {
    return -1;
  }
  memcpy(buffer, g_data + (size_t)relative, (size_t)count);
  return (s64)count;
}

int xaios_fs_fsync(int fd) {
  if (fd != 11) return -1;
  ++g_fsync_calls;
  return 0;
}

int xaios_fs_stat(const char *path, xaios_mfs_stat_user_t *value) {
  memset(value, 0, sizeof(*value));
  if (strcmp(path, "/tmp") == 0 || strcmp(path, "/") == 0) {
    value->type = XAIOS_FS_TYPE_DIRECTORY;
    return 0;
  }
  if (strcmp(path, "/tmp/large.bin") != 0) return -1;
  value->type = XAIOS_FS_TYPE_FILE;
  value->size = g_file_size;
  return 0;
}

int xaios_fs_list(const char *path, char *buffer, u64 capacity, u64 *out_size) {
  static const char listing[] = "large.bin\n";
  if (strcmp(path, "/tmp") != 0 || capacity < sizeof(listing)) return -1;
  memcpy(buffer, listing, sizeof(listing));
  *out_size = sizeof(listing) - 1U;
  return 0;
}

int xaios_fs_mkdir(const char *path) { (void)path; return 0; }
int xaios_fs_delete(const char *path) { (void)path; return 0; }
int xaios_fs_rename(const char *old_path, const char *new_path) {
  (void)old_path;
  (void)new_path;
  return 0;
}

static uint32_t get_u32(const uint8_t *value) {
  return ssh_read_u32_be(value);
}

static void put_u32(uint8_t *output, uint32_t value) {
  ssh_write_u32_be(output, value);
}

static void put_u64(uint8_t *output, uint64_t value) {
  put_u32(output, (uint32_t)(value >> 32U));
  put_u32(output + 4U, (uint32_t)value);
}

static uint32_t append_string(uint8_t *packet, uint32_t position,
                              const void *value, uint32_t length) {
  put_u32(packet + position, length);
  memcpy(packet + position + 4U, value, length);
  return position + 4U + length;
}

static uint32_t response_type(void) {
  assert(g_response_size >= 5U);
  assert(get_u32(g_response) == g_response_size - 4U);
  return g_response[4];
}

static uint32_t response_status(void) {
  assert(response_type() == FXP_STATUS);
  return get_u32(g_response + 9U);
}

static uint32_t response_request_id(void) {
  assert(g_response_size >= 9U);
  return get_u32(g_response + 5U);
}

static uint32_t open_file(const char *path) {
  uint8_t packet[512];
  uint32_t position = 0U;
  packet[position++] = FXP_OPEN;
  put_u32(packet + position, 1U); position += 4U;
  position = append_string(packet, position, path, (uint32_t)strlen(path));
  put_u32(packet + position, FXF_READ | FXF_WRITE | FXF_CREAT | FXF_TRUNC);
  position += 4U;
  put_u32(packet + position, 0x00000004U); position += 4U;
  put_u32(packet + position, 0644U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(g_response_channel == 42U && response_type() == FXP_HANDLE);
  assert(get_u32(g_response + 9U) == 4U);
  return get_u32(g_response + 13U);
}

#ifdef XAIOS_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0U || size > UINT32_MAX) return 0;
  g_response_size = 0U;
  (void)sftp_handle_message(91, 77U, data, (uint32_t)size);
  return 0;
}
#else
int main(void) {
  static uint8_t packet[40000];
  uint32_t position = 0U;

  assert(SSH_CHANNEL_SFTP_REQUEST_MAX >= 32793U);
  assert(SSH_CHANNEL_SFTP_BUFFER_SIZE >=
         SSH_CHANNEL_SFTP_REQUEST_MAX + SSH_CHANNEL_MAX_PACKET);
  assert(SSH_CHANNEL_PENDING_SIZE >= 32768U + 13U);

  packet[position++] = FXP_OPEN;
  put_u32(packet + position, 9U); position += 4U;
  static const char alias[] = "/state//control/config.bin";
  position = append_string(packet, position, alias, sizeof(alias) - 1U);
  put_u32(packet + position, FXF_READ); position += 4U;
  put_u32(packet + position, 0U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 3U);

  position = 0U;
  packet[position++] = FXP_OPEN;
  put_u32(packet + position, 10U); position += 4U;
  position = append_string(packet, position, "/tmp/unsupported-size.bin", 25U);
  put_u32(packet + position, FXF_WRITE | FXF_CREAT); position += 4U;
  put_u32(packet + position, 0x00000001U); position += 4U;
  put_u64(packet + position, 1U); position += 8U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 8U);

  uint32_t handle = open_file("/tmp/large.bin");
  assert((g_open_flags & XAIOS_MFS_OPEN_TRUNCATE) != 0U);
  static uint8_t large_payload[32768];
  for (uint32_t index = 0U; index < sizeof(large_payload); ++index) {
    large_payload[index] = (uint8_t)index;
  }
  position = 0U;
  packet[position++] = FXP_WRITE;
  put_u32(packet + position, 11U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  put_u64(packet + position, 0U); position += 8U;
  put_u32(packet + position, sizeof(large_payload)); position += 4U;
  memcpy(packet + position, large_payload, sizeof(large_payload));
  position += sizeof(large_payload);
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 0U && g_file_size == sizeof(large_payload));

  uint64_t high_offset = (UINT64_C(4) << 30U) + 4096U;
  static const uint8_t payload[] = "payload";
  position = 0U;
  packet[position++] = FXP_WRITE;
  put_u32(packet + position, 2U); position += 4U;
  position = append_string(packet, position, &handle, 0U);
  put_u32(packet + position - 4U, 4U);
  put_u32(packet + position, handle); position += 4U;
  put_u64(packet + position, high_offset); position += 8U;
  put_u32(packet + position, sizeof(payload) - 1U); position += 4U;
  memcpy(packet + position, payload, sizeof(payload) - 1U);
  position += sizeof(payload) - 1U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 0U);
  assert(g_write_calls == 4U && g_file_size == high_offset + 7U);

  position = 0U;
  packet[position++] = FXP_FSTAT;
  put_u32(packet + position, 3U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_type() == FXP_ATTRS);
  uint64_t reported_size = ((uint64_t)get_u32(g_response + 13U) << 32U) |
                           get_u32(g_response + 17U);
  assert(reported_size == high_offset + 7U);

  position = 0U;
  packet[position++] = FXP_FSETSTAT;
  put_u32(packet + position, 14U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  put_u32(packet + position, 0x00000001U); position += 4U;
  put_u64(packet + position, high_offset + 7U); position += 8U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_request_id() == 14U && response_status() == 0U);

  position = 0U;
  packet[position++] = FXP_FSETSTAT;
  put_u32(packet + position, 15U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  put_u32(packet + position, 0x00000001U); position += 4U;
  put_u64(packet + position, high_offset + 8U); position += 8U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_request_id() == 15U && response_status() == 8U);

  position = 0U;
  packet[position++] = 250U;
  put_u32(packet + position, 0x12345678U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_request_id() == 0x12345678U && response_status() == 8U);

  position = 0U;
  packet[position++] = FXP_READ;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  put_u64(packet + position, high_offset); position += 8U;
  put_u32(packet + position, 7U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_type() == FXP_DATA && get_u32(g_response + 9U) == 7U);
  assert(memcmp(g_response + 13U, payload, 7U) == 0);

  position = 0U;
  packet[position++] = FXP_WRITE;
  put_u32(packet + position, 5U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  put_u64(packet + position, UINT64_MAX - 1U); position += 8U;
  put_u32(packet + position, 4U); position += 4U;
  memcpy(packet + position, "fail", 4U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 5U && g_write_calls == 4U);

  static const char extension[] = "fsync@openssh.com";
  position = 0U;
  packet[position++] = FXP_EXTENDED;
  put_u32(packet + position, 6U); position += 4U;
  position = append_string(packet, position, extension, sizeof(extension) - 1U);
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 0U && g_fsync_calls == 1U);

  g_fail_reads = 1;
  position = 0U;
  packet[position++] = FXP_READ;
  put_u32(packet + position, 7U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  put_u64(packet + position, high_offset); position += 8U;
  put_u32(packet + position, 1U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 4U);
  g_fail_reads = 0;

  position = 0U;
  packet[position++] = FXP_CLOSE;
  put_u32(packet + position, 8U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, handle); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 0U && g_fsync_calls == 1U &&
         g_close_calls == 1U);

  position = 0U;
  packet[position++] = FXP_OPEN;
  put_u32(packet + position, 12U); position += 4U;
  position = append_string(packet, position, "/tmp/large.bin", 14U);
  put_u32(packet + position, FXF_WRITE | FXF_APPEND | FXF_CREAT);
  position += 4U;
  put_u32(packet + position, 0U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_type() == FXP_HANDLE);
  uint32_t append_handle = get_u32(g_response + 13U);

  position = 0U;
  packet[position++] = FXP_WRITE;
  put_u32(packet + position, 13U); position += 4U;
  put_u32(packet + position, 4U); position += 4U;
  put_u32(packet + position, append_handle); position += 4U;
  put_u64(packet + position, 0U); position += 8U;
  put_u32(packet + position, 4U); position += 4U;
  memcpy(packet + position, "tail", 4U); position += 4U;
  assert(sftp_handle_message(7, 42U, packet, position) == 0);
  assert(response_status() == 0U && g_file_size == high_offset + 11U);

  uint32_t fuzz_state = UINT32_C(0x53465450);
  for (uint32_t case_id = 0U; case_id < 4096U; ++case_id) {
    fuzz_state = fuzz_state * UINT32_C(1664525) + UINT32_C(1013904223);
    uint32_t fuzz_length = (fuzz_state % 512U) + 1U;
    for (uint32_t index = 0U; index < fuzz_length; ++index) {
      fuzz_state =
          fuzz_state * UINT32_C(1664525) + UINT32_C(1013904223);
      packet[index] = (uint8_t)(fuzz_state >> 24U);
    }
    assert(sftp_handle_message(91, 77U, packet, fuzz_length) == 0);
  }

  puts("sftp: 64-bit I/O and deterministic malformed corpus passed");
  return 0;
}
#endif
