/*
 * Tar command handler: ustar archive creation, plus the listing and extraction
 * that remote_login_archive.c's ustar_walk() performs.
 *
 * Split out of remote_login.c. The code came from an arm of remote_login.c
 * compiled only when XAIOS_BOOT_TEST_APPS is on, so the whole file keeps that
 * guard and a build with it off compiles none of it.
 */

#include "remote_login_archive_internal.h"

#include <xaios/kheap.h>

#if XAIOS_BOOT_TEST_APPS

void remote_login_bytes_zero(void *data, uint64_t size) {
  uint8_t *bytes = (uint8_t *)data;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static xaios_status_t ustar_put_octal(char *field, uint64_t width,
                                    uint64_t value) {
  if (field == 0 || width < 2U) return XAIOS_ERR_INVALID;
  for (uint64_t i = 0U; i + 1U < width; ++i) field[i] = '0';
  field[width - 1U] = '\0';
  uint64_t cursor = width - 1U;
  do {
    if (cursor == 0U) return XAIOS_ERR_INVALID;
    field[--cursor] = (char)('0' + (value & 7U));
    value >>= 3U;
  } while (value != 0U);
  return XAIOS_OK;
}

static xaios_status_t ustar_set_path(char *header, const char *path) {
  uint64_t length = cstr_len(path);
  if (header == 0 || path == 0 || length == 0U || length > 255U)
    return XAIOS_ERR_INVALID;
  if (length <= 100U) {
    for (uint64_t i = 0U; i < length; ++i) header[i] = path[i];
    return XAIOS_OK;
  }
  uint64_t split = length;
  while (split > 0U) {
    --split;
    if (path[split] == '/' && split <= 155U && length - split - 1U <= 100U) {
      for (uint64_t i = 0U; i < split; ++i) header[345U + i] = path[i];
      for (uint64_t i = 0U; i < length - split - 1U; ++i)
        header[i] = path[split + 1U + i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_INVALID;
}

static xaios_status_t ustar_append_header(char *archive, uint64_t capacity,
                                         uint64_t *size, const char *path,
                                         uint64_t data_size, char type) {
  if (archive == 0 || size == 0 || *size > capacity ||
      capacity - *size < XAIOS_USTAR_BLOCK_SIZE)
    return XAIOS_ERR_NO_MEMORY;
  char *header = archive + *size;
  remote_login_bytes_zero(header, XAIOS_USTAR_BLOCK_SIZE);
  if (ustar_set_path(header, path) != XAIOS_OK ||
      ustar_put_octal(header + 100U, 8U, type == '5' ? 0755U : 0644U) !=
          XAIOS_OK ||
      ustar_put_octal(header + 108U, 8U, 0U) != XAIOS_OK ||
      ustar_put_octal(header + 116U, 8U, 0U) != XAIOS_OK ||
      ustar_put_octal(header + 124U, 12U, data_size) != XAIOS_OK ||
      ustar_put_octal(header + 136U, 12U, 0U) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  for (uint64_t i = 148U; i < 156U; ++i) header[i] = ' ';
  header[156U] = type;
  header[257U] = 'u'; header[258U] = 's'; header[259U] = 't';
  header[260U] = 'a'; header[261U] = 'r';
  header[263U] = '0'; header[264U] = '0';
  (void)copy_cstr(header + 265U, 32U, "admin");
  (void)copy_cstr(header + 297U, 32U, "admin");
  uint64_t checksum = 0U;
  for (uint64_t i = 0U; i < XAIOS_USTAR_BLOCK_SIZE; ++i)
    checksum += (uint8_t)header[i];
  if (ustar_put_octal(header + 148U, 7U, checksum) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  header[154U] = '\0';
  header[155U] = ' ';
  *size += XAIOS_USTAR_BLOCK_SIZE;
  return XAIOS_OK;
}

static xaios_status_t ustar_build_path(const char *source, const char *name,
                                      char *archive, uint64_t capacity,
                                      uint64_t *archive_size) {
  xaios_xbfs_stat_t stat;
  if (xaiboot_fs_stat(source, &stat) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  if (stat.type == 1U) {
    if (ustar_append_header(archive, capacity, archive_size, name, 0U, '5') !=
        XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
    char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    uint64_t listing_size = 0U;
    if (xaiboot_fs_list(source, listing, sizeof(listing), &listing_size) !=
        XAIOS_OK)
      return XAIOS_ERR_IO;
    for (uint64_t start = 0U; start < listing_size;) {
      uint64_t end = start;
      while (end < listing_size && listing[end] != '\n') ++end;
      if (end != start) {
        char child[XAIOS_XBFS_PATH_MAX];
        char child_source[XAIOS_XBFS_PATH_MAX];
        char child_name[XAIOS_XBFS_PATH_MAX];
        if (copy_cstr_range(child, sizeof(child), listing + start, end - start) !=
                XAIOS_OK ||
            path_join(child_source, sizeof(child_source), source, child) !=
                XAIOS_OK ||
            path_join(child_name, sizeof(child_name), name, child) != XAIOS_OK ||
            ustar_build_path(child_source, child_name, archive, capacity,
                             archive_size) != XAIOS_OK)
          return XAIOS_ERR_INVALID;
      }
      start = end + 1U;
    }
    return XAIOS_OK;
  }
  if (stat.type != 2U || stat.size > XAIOS_XBFS_MAX_FILE_BYTES_V5)
    return XAIOS_ERR_INVALID;
  if (stat.size > UINT64_MAX - 511U) return XAIOS_ERR_INVALID;
  uint64_t padded = (stat.size + 511U) & ~UINT64_C(511);
  if (capacity - *archive_size < XAIOS_USTAR_BLOCK_SIZE + padded ||
      ustar_append_header(archive, capacity, archive_size, name, stat.size,
                          '0') != XAIOS_OK)
    return XAIOS_ERR_NO_MEMORY;
  uint64_t read_size = 0U;
  if (xaiboot_fs_read(source, archive + *archive_size, stat.size, &read_size) !=
          XAIOS_OK ||
      read_size != stat.size)
    return XAIOS_ERR_IO;
  remote_login_bytes_zero(archive + *archive_size + stat.size, padded - stat.size);
  *archive_size += padded;
  return XAIOS_OK;
}

xaios_status_t remote_login_handle_tar(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  uint64_t arg_index = 0U;
  char mode[32];
  char token[XAIOS_XBFS_PATH_MAX];
  char archive_token[XAIOS_XBFS_PATH_MAX];
  char archive_path[XAIOS_XBFS_PATH_MAX];
  char destination_path[XAIOS_XBFS_PATH_MAX];
  int operation = 0;
  int has_file = 0;
  int verbose = 0;
  int gzip = 0;

  if (token_next(args, &arg_index, mode, sizeof(mode)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                       "tar: missing options");
  }
  uint64_t option_start = mode[0] == '-' ? 1U : 0U;
  for (uint64_t i = option_start; mode[i] != '\0'; ++i) {
    if (mode[i] == 'c' || mode[i] == 'x' || mode[i] == 't') {
      if (operation != 0) return command_fail(output, output_capacity,
                                               output_bytes,
                                               "tar: conflicting operation");
      operation = mode[i];
    } else if (mode[i] == 'f') {
      has_file = 1;
    } else if (mode[i] == 'v') {
      verbose = 1;
    } else if (mode[i] == 'z') {
      gzip = 1;
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: unsupported option");
    }
  }
  if (operation == 0)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: missing operation");
  if (operation == 'c' && gzip != 0)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: gzip creation is not supported; use zip -r");
  if (has_file == 0) {
    if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK ||
        string_equal(token, "-f") == 0)
      return command_fail(output, output_capacity, output_bytes,
                          "tar: archive must be specified with -f");
  }
  if (token_next(args, &arg_index, archive_token, sizeof(archive_token)) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "tar: missing archive");
  }
  if (remote_path_resolve(remote_login_cwd(), archive_token, archive_path,
                          sizeof(archive_path)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "tar: cannot resolve archive");
  }

  if (operation == 't') {
    if (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: too many arguments");
    }
    if (ustar_walk(archive_path, remote_login_cwd(), 0, output,
                   output_capacity, output_bytes) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: cannot list archive");
    }
    return XAIOS_OK;
  }

  if (operation == 'x') {
    int saw_destination = 0;
    while (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
      if (string_equal(token, "-C") == 1U) {
        if (saw_destination != 0U) {
          return command_fail(output, output_capacity, output_bytes,
                              "tar: duplicate destination");
        }
        if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "tar: missing destination");
        }
        if (copy_cstr(destination_path, sizeof(destination_path), token) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        saw_destination = 1;
        continue;
      }
      return command_fail(output, output_capacity, output_bytes,
                         "tar: unsupported option");
    }
    if (saw_destination == 0U) {
      if (copy_cstr(destination_path, sizeof(destination_path),
                   remote_login_cwd()) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "tar: destination state error");
      }
    }
    if (remote_path_resolve(remote_login_cwd(), destination_path,
                            destination_path, sizeof(destination_path)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: invalid destination");
    }
    xaios_xbfs_stat_t destination_stat;
    if (xaiboot_fs_stat(destination_path, &destination_stat) != XAIOS_OK ||
        destination_stat.type != 1U ||
        ustar_walk(archive_path, destination_path, 1,
                   verbose != 0 ? output : 0, output_capacity,
                   output_bytes) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                         "tar: extract failed");
    }
    output[0] = '\0';
    return XAIOS_OK;
  }

  char *archive = (char *)kheap_alloc(XAIOS_XBFS_MAX_FILE_BYTES_V5, 16U);
  if (archive == 0)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: memory unavailable");
  uint64_t archive_size = 0U;
  uint32_t sources = 0U;
  xaios_status_t status = XAIOS_OK;
  while (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
    char source_path[XAIOS_XBFS_PATH_MAX];
    char source_name[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(remote_login_cwd(), token, source_path,
                            sizeof(source_path)) != XAIOS_OK ||
        remote_login_path_basename(source_path, source_name, sizeof(source_name)) !=
            XAIOS_OK ||
        ustar_build_path(source_path, source_name, archive,
                         XAIOS_XBFS_MAX_FILE_BYTES_V5 - 1024U,
                         &archive_size) != XAIOS_OK) {
      status = XAIOS_ERR_INVALID;
      break;
    }
    if (verbose != 0) {
      output_append(output, output_capacity, output_bytes, source_name);
      output_append_char(output, output_capacity, output_bytes, '\n');
    }
    ++sources;
  }
  if (status == XAIOS_OK && sources != 0U) {
    remote_login_bytes_zero(archive + archive_size, 1024U);
    archive_size += 1024U;
    status = write_buffer_to_path(archive_path, archive, archive_size);
  }
  kheap_free(archive);
  if (sources == 0U)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: missing files");
  if (status != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "tar: cannot create archive");
  }
  return XAIOS_OK;
}

#endif /* XAIOS_BOOT_TEST_APPS */
