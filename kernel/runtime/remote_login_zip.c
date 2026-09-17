/*
 * Zip command handlers: zip creation, unzip extraction and listing, and the
 * cpio handler that speaks the XAIOSARCHIVE format of remote_login_archive.c.
 *
 * Split out of remote_login.c. The code came from an arm of remote_login.c
 * compiled only when XAIOS_BOOT_TEST_APPS is on, so the whole file keeps that
 * guard and a build with it off compiles none of it.
 */

#include "remote_login_archive_internal.h"

#include <xaios/crc32.h>
#include <xaios/inflate.h>
#include <xaios/kheap.h>

#if XAIOS_BOOT_TEST_APPS

static xaios_status_t zip_append_path(
    const char *source, const char *name, int recursive, uint8_t *archive,
    uint64_t capacity, uint64_t *archive_size, xaios_zip_entry_t *entries,
    uint32_t *entry_count) {
  xaios_xbfs_stat_t stat;
  if (*entry_count >= XAIOS_ZIP_MAX_ENTRIES ||
      xaiboot_fs_stat(source, &stat) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  uint64_t name_len = cstr_len(name);
  if (name_len == 0U || name_len > UINT16_MAX) return XAIOS_ERR_INVALID;
  if (stat.type == 1U && recursive == 0) return XAIOS_ERR_INVALID;

  char entry_name[XAIOS_XBFS_PATH_MAX];
  if (copy_cstr(entry_name, sizeof(entry_name), name) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  if (stat.type == 1U && entry_name[name_len - 1U] != '/') {
    if (name_len + 2U > sizeof(entry_name)) return XAIOS_ERR_INVALID;
    entry_name[name_len++] = '/';
    entry_name[name_len] = '\0';
  }
  uint64_t data_size = stat.type == 2U ? stat.size : 0U;
  if (data_size > UINT32_MAX ||
      capacity - *archive_size < 30U + name_len + data_size)
    return XAIOS_ERR_NO_MEMORY;
  xaios_zip_entry_t *entry = &entries[*entry_count];
  remote_login_bytes_zero(entry, sizeof(*entry));
  if (copy_cstr(entry->name, sizeof(entry->name), entry_name) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  entry->size = (uint32_t)data_size;
  entry->local_offset = (uint32_t)*archive_size;
  entry->directory = stat.type == 1U ? 1U : 0U;

  uint8_t *header = archive + *archive_size;
  remote_login_bytes_zero(header, 30U);
  remote_login_write_le32(header, UINT32_C(0x04034b50));
  remote_login_write_le16(header + 4U, 20U);
  remote_login_write_le16(header + 8U, 0U);
  remote_login_write_le16(header + 26U, (uint16_t)name_len);
  for (uint64_t i = 0U; i < name_len; ++i) header[30U + i] = entry_name[i];
  *archive_size += 30U + name_len;
  if (data_size != 0U) {
    uint64_t got = 0U;
    if (xaiboot_fs_read(source, archive + *archive_size, data_size, &got) !=
            XAIOS_OK ||
        got != data_size)
      return XAIOS_ERR_IO;
    entry->crc32 = xaios_crc32(archive + *archive_size, data_size);
    *archive_size += data_size;
  }
  remote_login_write_le32(header + 14U, entry->crc32);
  remote_login_write_le32(header + 18U, entry->size);
  remote_login_write_le32(header + 22U, entry->size);
  ++(*entry_count);

  if (stat.type != 1U) return XAIOS_OK;
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
          zip_append_path(child_source, child_name, recursive, archive,
                          capacity, archive_size, entries, entry_count) !=
              XAIOS_OK)
        return XAIOS_ERR_INVALID;
    }
    start = end + 1U;
  }
  return XAIOS_OK;
}

xaios_status_t remote_login_handle_zip(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  uint64_t index = 0U;
  int recursive = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  char archive_token[XAIOS_XBFS_PATH_MAX];
  if (token_next(args, &index, token, sizeof(token)) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "zip: missing archive");
  if (string_equal(token, "-r")) {
    recursive = 1;
    if (token_next(args, &index, archive_token, sizeof(archive_token)) !=
        XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "zip: missing archive");
  } else if (copy_cstr(archive_token, sizeof(archive_token), token) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "zip: invalid archive");
  }
  char archive_path[XAIOS_XBFS_PATH_MAX];
  if (remote_path_resolve(remote_login_cwd(), archive_token, archive_path,
                          sizeof(archive_path)) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "zip: invalid archive");
  uint8_t *archive = (uint8_t *)kheap_alloc(XAIOS_XBFS_MAX_FILE_BYTES_V5, 16U);
  xaios_zip_entry_t *entries = (xaios_zip_entry_t *)kheap_calloc(
      sizeof(xaios_zip_entry_t) * XAIOS_ZIP_MAX_ENTRIES, 16U);
  if (archive == 0 || entries == 0) {
    kheap_free(archive);
    kheap_free(entries);
    return command_fail(output, output_capacity, output_bytes,
                        "zip: memory unavailable");
  }
  uint64_t archive_size = 0U;
  uint32_t entry_count = 0U;
  xaios_status_t status = XAIOS_OK;
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    char source[XAIOS_XBFS_PATH_MAX];
    char name[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(remote_login_cwd(), token, source,
                            sizeof(source)) != XAIOS_OK ||
        remote_login_path_basename(source, name, sizeof(name)) != XAIOS_OK ||
        zip_append_path(source, name, recursive, archive,
                        XAIOS_XBFS_MAX_FILE_BYTES_V5, &archive_size, entries,
                        &entry_count) != XAIOS_OK) {
      status = XAIOS_ERR_INVALID;
      break;
    }
    output_append(output, output_capacity, output_bytes, "  adding: ");
    output_append(output, output_capacity, output_bytes, name);
    output_append_char(output, output_capacity, output_bytes, '\n');
  }
  if (entry_count == 0U) status = XAIOS_ERR_INVALID;
  if (status == XAIOS_OK)
    status = remote_login_zip_finish(archive, XAIOS_XBFS_MAX_FILE_BYTES_V5, &archive_size,
                        entries, entry_count);
  if (status == XAIOS_OK)
    status = write_buffer_to_path(archive_path, (const char *)archive,
                                  archive_size);
  kheap_free(entries);
  kheap_free(archive);
  if (status != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "zip: cannot create archive");
  return XAIOS_OK;
}

static xaios_status_t unzip_archive(const char *archive_path,
                                    const char *destination, int list_only,
                                    char *output, uint64_t output_capacity,
                                    uint64_t *output_bytes) {
  uint8_t *archive = (uint8_t *)kheap_alloc(XAIOS_XBFS_MAX_FILE_BYTES_V5, 16U);
  uint64_t archive_size = 0U;
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (archive == 0) return XAIOS_ERR_NO_MEMORY;
  if (xaiboot_fs_read(archive_path, archive, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                      &archive_size) != XAIOS_OK ||
      archive_size < 22U)
    goto done;
  uint64_t end_offset = archive_size - 22U;
  uint64_t search_floor = archive_size > 65557U ? archive_size - 65557U : 0U;
  while (remote_login_read_le32(archive + end_offset) != UINT32_C(0x06054b50)) {
    if (end_offset == search_floor) goto done;
    --end_offset;
  }
  uint16_t entries = remote_login_read_le16(archive + end_offset + 10U);
  uint32_t central_size = remote_login_read_le32(archive + end_offset + 12U);
  uint32_t central_offset = remote_login_read_le32(archive + end_offset + 16U);
  if (remote_login_read_le16(archive + end_offset + 4U) != 0U ||
      remote_login_read_le16(archive + end_offset + 6U) != 0U ||
      entries != remote_login_read_le16(archive + end_offset + 8U) ||
      (uint64_t)central_offset + central_size > end_offset)
    goto done;
  uint64_t cursor = central_offset;
  for (uint16_t entry_index = 0U; entry_index < entries; ++entry_index) {
    if (cursor + 46U > archive_size ||
        remote_login_read_le32(archive + cursor) != UINT32_C(0x02014b50))
      goto done;
    uint16_t flags = remote_login_read_le16(archive + cursor + 8U);
    uint16_t method = remote_login_read_le16(archive + cursor + 10U);
    uint32_t crc = remote_login_read_le32(archive + cursor + 16U);
    uint32_t compressed = remote_login_read_le32(archive + cursor + 20U);
    uint32_t uncompressed = remote_login_read_le32(archive + cursor + 24U);
    uint16_t name_len = remote_login_read_le16(archive + cursor + 28U);
    uint16_t extra_len = remote_login_read_le16(archive + cursor + 30U);
    uint16_t comment_len = remote_login_read_le16(archive + cursor + 32U);
    uint32_t local_offset = remote_login_read_le32(archive + cursor + 42U);
    uint64_t next = cursor + 46U + name_len + extra_len + comment_len;
    if (name_len == 0U || name_len >= XAIOS_XBFS_PATH_MAX ||
        next > archive_size || (flags & 1U) != 0U ||
        (method != 0U && method != 8U))
      goto done;
    char name[XAIOS_XBFS_PATH_MAX];
    if (copy_cstr_range(name, sizeof(name),
                        (const char *)archive + cursor + 46U, name_len) !=
            XAIOS_OK ||
        archive_path_is_safe(name) == 0)
      goto done;
    output_append(output, output_capacity, output_bytes, name);
    output_append_char(output, output_capacity, output_bytes, '\n');
    int directory = name[name_len - 1U] == '/';
    if (list_only == 0) {
      char target[XAIOS_XBFS_PATH_MAX];
      if (path_join(target, sizeof(target), destination, name) != XAIOS_OK)
        goto done;
      if (directory != 0) {
        if (mkdir_resolved(target, 1) != XAIOS_OK) goto done;
      } else {
        if ((uint64_t)local_offset + 30U > archive_size ||
            remote_login_read_le32(archive + local_offset) != UINT32_C(0x04034b50))
          goto done;
        uint16_t local_name = remote_login_read_le16(archive + local_offset + 26U);
        uint16_t local_extra = remote_login_read_le16(archive + local_offset + 28U);
        uint64_t data_offset = (uint64_t)local_offset + 30U + local_name +
                               local_extra;
        if (data_offset > archive_size || compressed > archive_size - data_offset ||
            uncompressed > XAIOS_XBFS_MAX_FILE_BYTES_V5)
          goto done;
        uint8_t *decoded = archive + data_offset;
        uint8_t *allocated = 0;
        uint64_t decoded_size = compressed;
        if (method == 8U) {
          allocated = (uint8_t *)kheap_alloc(uncompressed == 0U ? 1U : uncompressed,
                                             16U);
          if (allocated == 0 ||
              xaios_inflate_raw(archive + data_offset, compressed, allocated,
                                uncompressed, &decoded_size) != XAIOS_OK) {
            kheap_free(allocated);
            goto done;
          }
          decoded = allocated;
        }
        if (decoded_size != uncompressed ||
            xaios_crc32(decoded, decoded_size) != crc ||
            remote_ensure_parent(target) != XAIOS_OK ||
            write_buffer_to_path(target, (const char *)decoded, decoded_size) !=
                XAIOS_OK) {
          kheap_free(allocated);
          goto done;
        }
        kheap_free(allocated);
      }
    }
    cursor = next;
  }
  status = XAIOS_OK;
done:
  kheap_free(archive);
  return status;
}

xaios_status_t remote_login_handle_unzip(const char *args, char *output,
                                  uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  uint64_t index = 0U;
  int list_only = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  char archive_token[XAIOS_XBFS_PATH_MAX];
  if (token_next(args, &index, token, sizeof(token)) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "unzip: missing archive");
  if (string_equal(token, "-l")) {
    list_only = 1;
    if (token_next(args, &index, archive_token, sizeof(archive_token)) !=
        XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "unzip: missing archive");
  } else if (copy_cstr(archive_token, sizeof(archive_token), token) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "unzip: invalid archive");
  }
  char destination[XAIOS_XBFS_PATH_MAX];
  if (copy_cstr(destination, sizeof(destination), remote_login_cwd()) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  if (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (list_only != 0 || string_equal(token, "-d") == 0 ||
        token_next(args, &index, token, sizeof(token)) != XAIOS_OK ||
        remote_path_resolve(remote_login_cwd(), token, destination,
                            sizeof(destination)) != XAIOS_OK ||
        has_more_args(args, index) != 0)
      return command_fail(output, output_capacity, output_bytes,
                          "unzip: invalid destination");
  }
  char archive_path[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t stat;
  if (remote_path_resolve(remote_login_cwd(), archive_token, archive_path,
                          sizeof(archive_path)) != XAIOS_OK ||
      (list_only == 0 &&
       (xaiboot_fs_stat(destination, &stat) != XAIOS_OK || stat.type != 1U)) ||
      unzip_archive(archive_path, destination, list_only, output,
                    output_capacity, output_bytes) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "unzip: invalid or unsupported archive");
  return XAIOS_OK;
}

xaios_status_t remote_login_handle_cpio(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char mode[32];
  char token[XAIOS_XBFS_PATH_MAX];
  char archive_token[XAIOS_XBFS_PATH_MAX];
  char archive_path[XAIOS_XBFS_PATH_MAX];
  char source_token[XAIOS_XBFS_PATH_MAX];
  char source_path[XAIOS_XBFS_PATH_MAX];
  char source_archive_name[XAIOS_XBFS_PATH_MAX];
  char archive[XAIOS_XBFS_MAX_FILE_BYTES];
  uint64_t archive_size = 0;
  uint64_t source_count = 0;
  int can_create = 0;
  int can_extract = 0;
  int can_list = 0;
  int has_archive = 0;

  if (token_next(args, &arg_index, mode, sizeof(mode)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                       "cpio: missing options");
  }
  if (mode[0] != '-') {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: unsupported option");
  }
  for (uint64_t i = 1U; mode[i] != '\0'; ++i) {
    if (mode[i] == 'o') {
      can_create = 1;
      continue;
    }
    if (mode[i] == 'i') {
      can_extract = 1;
      continue;
    }
    if (mode[i] == 't') {
      can_list = 1;
      continue;
    }
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: unsupported option");
  }
  if ((can_create + can_extract + can_list) != 1) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: unsupported option");
  }

  if (can_create != 0U) {
    if (remote_login_buffer_append_text(archive, sizeof(archive), &archive_size,
                          g_remote_login_archive_magic) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: archive too large");
    }
    if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: missing source");
    }
    while (1) {
      if (string_equal(token, "-O") == 1U) {
        if (token_next(args, &arg_index, archive_token, sizeof(archive_token)) !=
            XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: missing archive");
        }
        if (copy_cstr(archive_path, sizeof(archive_path), archive_token) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid archive");
        }
        if (remote_path_resolve(remote_login_cwd(), archive_path, archive_path,
                                sizeof(archive_path)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid archive");
        }
        has_archive = 1;
      } else if (token[0] == '-') {
        return command_fail(output, output_capacity, output_bytes,
                            "cpio: unsupported option");
      } else {
        if (copy_cstr(source_token, sizeof(source_token), token) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid source");
        }
        if (remote_path_resolve(remote_login_cwd(), source_token, source_path,
                                sizeof(source_path)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid source");
        }
        if (remote_login_path_basename(source_path, source_archive_name,
                          sizeof(source_archive_name)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid source");
        }
        if (archive_build_from_path(source_path, source_archive_name, archive,
                                   sizeof(archive), &archive_size) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: cannot add source");
        }
        ++source_count;
      }
      if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
        break;
      }
    }
    if (has_archive == 0U) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: missing archive");
    }
    if (source_count == 0U) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: missing source");
    }
    if (write_buffer_to_path(archive_path, archive, archive_size) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: cannot write archive");
    }
    output[0] = '\0';
    return XAIOS_OK;
  }

  if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: missing archive");
  }
  if (string_equal(token, "-I") != 1U) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: expected -I");
  }
  if (token_next(args, &arg_index, archive_token, sizeof(archive_token)) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: missing archive");
  }
  if (copy_cstr(archive_path, sizeof(archive_path), archive_token) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "cpio: invalid archive");
  }
  if (remote_path_resolve(remote_login_cwd(), archive_path, archive_path,
                          sizeof(archive_path)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: invalid archive");
  }
  if (has_archive == 0U) {
    has_archive = 1;
  }
  if (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: too many arguments");
  }
  if (can_list != 0) {
    if (archive_list(archive_path, output, output_capacity, output_bytes) !=
        XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: list failed");
    return XAIOS_OK;
  }
  if (archive_extract_to(archive_path, remote_login_cwd()) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: extract failed");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

#endif /* XAIOS_BOOT_TEST_APPS */
