/*
 * Archive support for the remote-login shell: the XAIOSARCHIVE container that
 * `tar` and `cpio` build, and the ustar reader that `tar` and `unzip` walk.
 *
 * Split out of remote_login.c, which keeps the command dispatch and the
 * session state these entry points read through remote_login_cwd(). The body
 * is compiled only when XAIOS_BOOT_TEST_APPS is on, exactly as it was inside
 * remote_login.c; in the shipped configuration no archive command is
 * registered and none of this exists.
 */

#include "remote_login_internal.h"

#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

#if XAIOS_BOOT_TEST_APPS

xaios_status_t archive_build_from_path(const char *source,
                                       const char *archive_path,
                                       char *archive,
                                       uint64_t archive_capacity,
                                       uint64_t *archive_size) {
  xaios_xbfs_stat_t source_stat;
  if (source == 0 || archive == 0 || archive_size == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (xaiboot_fs_stat(source, &source_stat) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (source_stat.type == 1U) {
    uint64_t archive_entry_name_len = cstr_len(archive_path);
    if (archive_entry_name_len == 0U) {
      return XAIOS_ERR_INVALID;
    }
    if (archive_append_entry(archive, archive_capacity, archive_size, 'D',
                            archive_path, "", 0U) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    uint64_t listing_size = 0;
    if (xaiboot_fs_list(source, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t line_start = 0;
    while (line_start < listing_size) {
      uint64_t line_end = line_start;
      while (line_end < listing_size && listing[line_end] != '\n') {
        ++line_end;
      }
      uint64_t child_name_len = line_end - line_start;
      if (child_name_len != 0U) {
        char child_name[XAIOS_XBFS_PATH_MAX];
        char child_source[XAIOS_XBFS_PATH_MAX];
        char child_archive_path[XAIOS_XBFS_PATH_MAX];
        if (copy_cstr_range(child_name, sizeof(child_name), listing + line_start,
                            child_name_len) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        if (path_join(child_source, sizeof(child_source), source, child_name) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        if (path_join(child_archive_path, sizeof(child_archive_path),
                      archive_path, child_name) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        if (archive_build_from_path(child_source, child_archive_path, archive,
                                   archive_capacity, archive_size) != XAIOS_OK) {
          return XAIOS_ERR_INVALID;
        }
      }
      line_start = line_end + 1U;
    }
    return XAIOS_OK;
  }
  if (source_stat.type == 2U) {
    char data[XAIOS_XBFS_MAX_FILE_BYTES];
    uint64_t data_size = 0;
    if (read_file_buffer(source, data, sizeof(data), &data_size) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (archive_append_entry(archive, archive_capacity, archive_size, 'F',
                            archive_path, data, data_size) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    return XAIOS_OK;
  }
  return XAIOS_ERR_INVALID;
}

xaios_status_t archive_extract_to(const char *archive_path,
                                  const char *extract_base) {
  char archive[XAIOS_XBFS_MAX_FILE_BYTES];
  char path[XAIOS_XBFS_PATH_MAX];
  char resolved_path[XAIOS_XBFS_PATH_MAX];
  char entry_path[XAIOS_XBFS_PATH_MAX];
  uint64_t archive_size = 0;
  uint64_t cursor = 0;
  uint64_t magic_len = cstr_len(g_remote_login_archive_magic);
  if (archive_path == 0 || extract_base == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (read_file_buffer(archive_path, archive, sizeof(archive), &archive_size) !=
          XAIOS_OK ||
      archive_size <= magic_len ||
      copy_cstr(path, sizeof(path), g_remote_login_archive_magic) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (archive_size < magic_len + 1U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < magic_len; ++i) {
    if (archive[i] != g_remote_login_archive_magic[i]) {
      return XAIOS_ERR_INVALID;
    }
  }
  cursor = magic_len;
  while (cursor < archive_size) {
    if (archive[cursor] == '\r' || archive[cursor] == '\n' ||
        archive[cursor] == '\0') {
      ++cursor;
      if (cursor >= archive_size) {
        return XAIOS_OK;
      }
      continue;
    }
    uint64_t line_start = cursor;
    while (cursor < archive_size && archive[cursor] != '\n') {
      ++cursor;
    }
    if (cursor >= archive_size) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t line_size = cursor - line_start;
    if (line_size == 0U) {
      ++cursor;
      continue;
    }
    char line[XAIOS_XBFS_MAX_FILE_BYTES];
    if (line_size >= sizeof(line)) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (copy_cstr_range(line, sizeof(line), archive + line_start, line_size) !=
        XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    line[line_size] = '\0';
    ++cursor;

    char kind = 0;
    uint64_t data_size = 0;
    uint64_t entry_path_len = 0;
    if (archive_parse_entry(line, line_size, &kind, &data_size, &entry_path_len,
                            entry_path, sizeof(entry_path)) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (entry_path_len + 1U >= sizeof(entry_path)) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (entry_path[0] == '/') {
      return XAIOS_ERR_INVALID;
    }
    if (path_join(resolved_path, sizeof(resolved_path), extract_base,
                  entry_path) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (kind == 'D') {
      if (remote_path_resolve(remote_login_cwd(), resolved_path, path,
                             sizeof(path)) != XAIOS_OK ||
          remote_ensure_parent(path) != XAIOS_OK ||
          xaiboot_fs_mkdir(path) != XAIOS_OK) {
        return XAIOS_ERR_INVALID;
      }
      continue;
    }
    if (kind != 'F') {
      return XAIOS_ERR_INVALID;
    }
    if (cursor + data_size > archive_size) {
      return XAIOS_ERR_INVALID;
    }
    if (remote_path_resolve(remote_login_cwd(), resolved_path, path,
                           sizeof(path)) != XAIOS_OK ||
        remote_ensure_parent(path) != XAIOS_OK ||
        write_buffer_to_path(path, archive + cursor, data_size) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    cursor += data_size;
  }
  return XAIOS_OK;
}

xaios_status_t archive_list(const char *archive_path, char *output,
                            uint64_t output_capacity,
                            uint64_t *output_bytes) {
  char archive[XAIOS_XBFS_MAX_FILE_BYTES];
  uint64_t archive_size = 0;
  uint64_t cursor = 0;
  uint64_t magic_len = cstr_len(g_remote_login_archive_magic);
  char path[XAIOS_XBFS_PATH_MAX];
  if (archive_path == 0 || read_file_buffer(archive_path, archive,
                                            sizeof(archive), &archive_size) !=
                                         XAIOS_OK ||
      archive_size <= magic_len) {
    klog("remote-login: archive-list file read failed path=%s size=%lu magic_len=%lu\n",
         archive_path == 0 ? "(null)" : archive_path, archive_size, magic_len);
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < magic_len; ++i) {
    if (archive[i] != g_remote_login_archive_magic[i]) {
      klog("remote-login: archive-list bad magic at offset=%lu byte=%u expected=%u\n", i,
           (uint8_t)archive[i], (uint8_t)g_remote_login_archive_magic[i]);
      return XAIOS_ERR_INVALID;
    }
  }
  cursor = magic_len;
  while (cursor < archive_size) {
    while (cursor < archive_size &&
           (archive[cursor] == '\r' || archive[cursor] == '\n' ||
            archive[cursor] == '\0')) {
      ++cursor;
      if (cursor >= archive_size) {
        return XAIOS_OK;
      }
    }
    uint64_t line_start = cursor;
    while (cursor < archive_size && archive[cursor] != '\n') {
      ++cursor;
    }
    if (line_start >= archive_size || cursor > archive_size) {
      klog("remote-login: archive-list bad line bounds line_start=%lu cursor=%lu size=%lu\n",
           line_start, cursor, archive_size);
      return XAIOS_ERR_INVALID;
    }
    uint64_t line_size = cursor - line_start;
    if (line_size == 0U) {
      ++cursor;
      continue;
    }
    char line[XAIOS_XBFS_MAX_FILE_BYTES];
    if (line_size >= sizeof(line)) {
      klog("remote-login: archive-list line too long=%lu\n", line_size);
      return XAIOS_ERR_NO_MEMORY;
    }
    if (copy_cstr_range(line, sizeof(line), archive + line_start, line_size) !=
        XAIOS_OK) {
      klog("remote-login: archive-list failed to copy header line_size=%lu\n", line_size);
      return XAIOS_ERR_NO_MEMORY;
    }
    line[line_size] = '\0';
    if (cursor < archive_size) {
      ++cursor;
    }
    char kind = 0;
    uint64_t data_size = 0;
    uint64_t entry_path_len = 0;
    if (archive_parse_entry(line, line_size, &kind, &data_size, &entry_path_len,
                            path, sizeof(path)) != XAIOS_OK) {
      klog("remote-login: archive-list parse failed header='%s' line_size=%lu magic_len=%lu\n",
           line, line_size, magic_len);
      return XAIOS_ERR_INVALID;
    }
    output_append(output, output_capacity, output_bytes, path);
    if (kind == 'D' &&
        output_append_char(output, output_capacity, output_bytes, '/') != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (output_append_char(output, output_capacity, output_bytes, '\n') != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (kind == 'D') {
      continue;
    }
    if (cursor + data_size > archive_size) {
      klog("remote-login: archive-list invalid data_size=%lu cursor=%lu archive_size=%lu\n",
           data_size, cursor, archive_size);
      return XAIOS_ERR_INVALID;
    }
    cursor += data_size;
  }
  return XAIOS_OK;
}

xaios_status_t ustar_walk(const char *archive_path,
                          const char *destination, int extract,
                          char *output, uint64_t output_capacity,
                          uint64_t *output_bytes) {
  char *archive = (char *)kheap_alloc(XAIOS_XBFS_MAX_FILE_BYTES_V5, 16U);
  char *decoded = 0;
  uint64_t archive_size = 0U;
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (archive == 0) return XAIOS_ERR_NO_MEMORY;
  if (xaiboot_fs_read(archive_path, archive, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                      &archive_size) != XAIOS_OK)
    goto done;
  if (archive_size >= 2U && (uint8_t)archive[0] == UINT8_C(0x1f) &&
      (uint8_t)archive[1] == UINT8_C(0x8b)) {
    uint64_t decoded_size = 0U;
    decoded = (char *)kheap_alloc(XAIOS_XBFS_MAX_FILE_BYTES_V5, 16U);
    if (decoded == 0 ||
        gzip_decode((const uint8_t *)archive, archive_size, (uint8_t *)decoded,
                    XAIOS_XBFS_MAX_FILE_BYTES_V5, &decoded_size) != XAIOS_OK)
      goto done;
    kheap_free(archive);
    archive = decoded;
    decoded = 0;
    archive_size = decoded_size;
  }
  char extended_path[XAIOS_XBFS_PATH_MAX];
  extended_path[0] = '\0';
  for (uint64_t cursor = 0U; cursor + XAIOS_USTAR_BLOCK_SIZE <= archive_size;) {
    const char *header = archive + cursor;
    if (ustar_block_is_zero(header) != 0) {
      status = XAIOS_OK;
      goto done;
    }
    uint64_t stored_checksum = 0U;
    uint64_t size = 0U;
    if (ustar_parse_octal(header + 148U, 8U, &stored_checksum) != XAIOS_OK ||
        ustar_parse_octal(header + 124U, 12U, &size) != XAIOS_OK)
      goto done;
    uint64_t checksum = 0U;
    for (uint64_t i = 0U; i < XAIOS_USTAR_BLOCK_SIZE; ++i)
      checksum += (i >= 148U && i < 156U) ? (uint8_t)' ' : (uint8_t)header[i];
    if (checksum != stored_checksum) goto done;
    if (size > UINT64_MAX - 511U) goto done;
    uint64_t padded = (size + 511U) & ~UINT64_C(511);
    if (padded > archive_size - cursor - 512U)
      goto done;
    char type = header[156U] == '\0' ? '0' : header[156U];
    const char *payload = archive + cursor + XAIOS_USTAR_BLOCK_SIZE;
    if (type == 'x' || type == 'g') {
      if (type == 'x' &&
          pax_extract_path(payload, size, extended_path,
                           sizeof(extended_path)) != XAIOS_OK)
        goto done;
      cursor += XAIOS_USTAR_BLOCK_SIZE + padded;
      continue;
    }
    if (type == 'L') {
      uint64_t path_size = 0U;
      while (path_size < size && payload[path_size] != '\0' &&
             payload[path_size] != '\n') ++path_size;
      if (path_size == 0U || path_size + 1U > sizeof(extended_path)) goto done;
      for (uint64_t i = 0U; i < path_size; ++i)
        extended_path[i] = payload[i];
      extended_path[path_size] = '\0';
      cursor += XAIOS_USTAR_BLOCK_SIZE + padded;
      continue;
    }
    char name[XAIOS_XBFS_PATH_MAX];
    if (extended_path[0] != '\0') {
      if (copy_cstr(name, sizeof(name), extended_path) != XAIOS_OK) goto done;
      extended_path[0] = '\0';
    } else if (ustar_header_path(header, name, sizeof(name)) != XAIOS_OK) {
      goto done;
    }
    if (archive_path_is_safe(name) == 0) goto done;
    if (type == '0' || type == '5') {
      if (output != 0) {
        output_append(output, output_capacity, output_bytes, name);
        if (type == '5' && name[cstr_len(name) - 1U] != '/')
          output_append_char(output, output_capacity, output_bytes, '/');
        output_append_char(output, output_capacity, output_bytes, '\n');
      }
      if (extract != 0) {
        char target[XAIOS_XBFS_PATH_MAX];
        if (path_join(target, sizeof(target), destination, name) != XAIOS_OK)
          goto done;
        if (type == '5') {
          if (mkdir_resolved(target, 1) != XAIOS_OK) goto done;
        } else {
          if (remote_ensure_parent(target) != XAIOS_OK ||
              write_buffer_to_path(target, archive + cursor + 512U, size) !=
                  XAIOS_OK)
            goto done;
        }
      }
    } else {
      goto done;
    }
    cursor += XAIOS_USTAR_BLOCK_SIZE + padded;
  }
done:
  kheap_free(decoded);
  kheap_free(archive);
  return status;
}

#endif /* XAIOS_BOOT_TEST_APPS */
