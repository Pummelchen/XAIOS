/*
 * The file syscall family. See syscall_family.h.
 *
 * Lifted out of syscall_dispatch in syscall.c, whose blocks for these
 * numbers are reproduced here verbatim: same guards, same order, same
 * error reasons.
 */

#include <xaios/agent_protocol.h>
#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/boot_ui.h>
#include <xaios/child_channel.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/control_protocol.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/initramfs.h>
#include <xaios/ipv4.h>
#include <xaios/network_config.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/local_ports.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/net_device.h>
#include <xaios/network_stack.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/socket_buffer.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>

#include "syscall_internal.h"
#include "syscall_table.h"
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/user.h>
#include <xaios/vfs.h>
#include <xaios/vmm.h>
#include "syscall_family.h"

uint64_t syscall_file(uint64_t syscall, uint64_t arg0,
                                                      uint64_t arg1, uint64_t arg2) {
  if (syscall == XAIOS_SYSCALL_FS_OPEN) {
    char path[XAIOS_XBFS_PATH_MAX];
    if (syscall_table_copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-path");
    }
    if ((arg2 & XAIOS_XBFS_OPEN_WRITE) != 0 &&
        user_process_has_capability(XAIOS_CAP_FS_WRITE) != XAIOS_OK) {
      const xaios_user_process_t *process = user_current_process();
      uint64_t granted = process != 0 ? process->capability_mask : 0;
      (void)security_authorize_capability("fs.open.write", granted,
                                          XAIOS_CAP_FS_WRITE);
      return syscall_dispatch_reject(syscall, arg0, arg1, "missing-fs-write");
    }
    if (syscall_table_path_equal(path, "/etc/xaios_ssh_client_identity") &&
        user_process_has_capability(XAIOS_CAP_CREDENTIAL_READ) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "missing-credential-read");
    }
    if ((arg2 & XAIOS_XBFS_OPEN_WRITE) != 0 &&
        security_authorize_fs_write(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-open-write-denied");
    }
    if ((arg2 & XAIOS_XBFS_OPEN_WRITE) == 0 &&
        security_authorize_fs_read(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-open-read-denied");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    int64_t fd = vfs_open(path, (uint32_t)arg2, owner_id);
    if (fd < 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-open-denied");
    }
    return syscall_dispatch_complete((uint64_t)fd);
  }

  if (syscall == XAIOS_SYSCALL_FS_READ) {
    if (arg0 > UINT32_MAX || arg2 == 0U ||
        arg2 > XAIOS_SYSCALL_IO_MAX_BYTES ||
        vmm_validate_user_buffer(arg1, arg2, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-read-buffer");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    int64_t bytes = vfs_read((uint32_t)arg0, owner_id,
                             (void *)(uintptr_t)arg1, arg2);
    if (bytes < 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-read-denied");
    }
    return syscall_dispatch_complete((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_WRITE) {
    if (arg0 > UINT32_MAX || arg2 == 0U ||
        arg2 > XAIOS_SYSCALL_IO_MAX_BYTES ||
        vmm_validate_user_buffer(arg1, arg2, 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-write-buffer");
    }
    uint8_t *write_snapshot = (uint8_t *)kheap_alloc(arg2, 16U);
    if (write_snapshot == 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-write-no-memory");
    }
    syscall_dispatch_bytes_copy(write_snapshot, (const void *)(uintptr_t)arg1, arg2);
    if (security_reject_credential_material_buffer(
            (const char *)write_snapshot, arg2) != XAIOS_OK) {
      kheap_free(write_snapshot);
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-write-secret-denied");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    int64_t bytes =
        vfs_write((uint32_t)arg0, owner_id, write_snapshot, arg2);
    kheap_free(write_snapshot);
    if (bytes < 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-write-denied");
    }
    return syscall_dispatch_complete((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_PREAD ||
      syscall == XAIOS_SYSCALL_FS_PWRITE) {
    xaios_syscall_positional_io_request_t request;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-positional-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.fd > UINT32_MAX || request.size == 0U ||
        request.size > XAIOS_SYSCALL_IO_MAX_BYTES ||
        vmm_validate_user_buffer(
            request.buffer, request.size,
            syscall == XAIOS_SYSCALL_FS_PREAD ? XAIOS_VMM_WRITABLE : 0U) !=
            XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-positional-buffer");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    int64_t bytes;
    if (syscall == XAIOS_SYSCALL_FS_PREAD) {
      bytes = vfs_pread((uint32_t)request.fd, owner_id,
                        (void *)(uintptr_t)request.buffer, request.size,
                        request.offset);
    } else {
      uint8_t *write_snapshot =
          (uint8_t *)kheap_alloc(request.size, 16U);
      if (write_snapshot == 0) {
        return syscall_dispatch_reject(syscall, arg0, arg1,
                              "fs-positional-write-no-memory");
      }
      syscall_dispatch_bytes_copy(write_snapshot, (const void *)(uintptr_t)request.buffer,
                 request.size);
      if (security_reject_credential_material_buffer(
              (const char *)write_snapshot, request.size) != XAIOS_OK) {
        kheap_free(write_snapshot);
        return syscall_dispatch_reject(syscall, arg0, arg1,
                              "fs-positional-write-secret-denied");
      }
      bytes = vfs_pwrite((uint32_t)request.fd, owner_id, write_snapshot,
                         request.size, request.offset);
      kheap_free(write_snapshot);
    }
    if (bytes < 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            syscall == XAIOS_SYSCALL_FS_PREAD
                                ? "fs-pread-denied"
                                : "fs-pwrite-denied");
    }
    return syscall_dispatch_complete((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_FSYNC) {
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    if (arg0 > UINT32_MAX ||
        vfs_fsync((uint32_t)arg0, owner_id) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-fsync-denied");
    }
    return syscall_dispatch_complete(0U);
  }

  if (syscall == XAIOS_SYSCALL_FS_SEEK) {
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    if (arg0 > UINT32_MAX ||
        vfs_seek((uint32_t)arg0, owner_id, arg1) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-seek-denied");
    }
    return syscall_dispatch_complete(arg1);
  }

  if (syscall == XAIOS_SYSCALL_FS_CLOSE) {
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->owner_token : 0U;
    if (arg0 > UINT32_MAX ||
        vfs_close((uint32_t)arg0, owner_id) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-close-denied");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_STAT) {
    char path[XAIOS_XBFS_PATH_MAX];
    if (syscall_table_copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        vmm_validate_user_buffer(arg2, sizeof(xaios_xbfs_stat_t),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-stat");
    }
    xaios_vfs_stat_t vfs_value;
    if (vfs_stat(path, &vfs_value) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-stat-denied");
    }
    xaios_xbfs_stat_t *value = (xaios_xbfs_stat_t *)(uintptr_t)arg2;
    value->type = vfs_value.type;
    value->block_count = vfs_value.block_count;
    value->size = vfs_value.size;
    value->generation = vfs_value.generation;
    value->content_hash = vfs_value.content_hash;
    return syscall_dispatch_complete(sizeof(xaios_xbfs_stat_t));
  }

  if (syscall == XAIOS_SYSCALL_FS_MKDIR) {
    char path[XAIOS_XBFS_PATH_MAX];
    if (syscall_table_copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        security_authorize_fs_write(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-mkdir-denied");
    }
    if (vfs_mkdir(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-mkdir-failed");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_DELETE) {
    char path[XAIOS_XBFS_PATH_MAX];
    if (syscall_table_copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        security_authorize_fs_write(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-delete-denied");
    }
    if (vfs_delete(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-delete-failed");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_RENAME) {
    xaios_syscall_rename_request_t request;
    char old_path[XAIOS_XBFS_PATH_MAX];
    char new_path[XAIOS_XBFS_PATH_MAX];
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-rename-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (syscall_table_copy_user_string(request.old_path, request.old_path_len, old_path,
                         sizeof(old_path)) != XAIOS_OK ||
        syscall_table_copy_user_string(request.new_path, request.new_path_len, new_path,
                         sizeof(new_path)) != XAIOS_OK ||
        security_authorize_fs_write(old_path) != XAIOS_OK ||
        security_authorize_fs_write(new_path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-rename-denied");
    }
    if (vfs_rename(old_path, new_path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-rename-failed");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_LIST) {
    xaios_syscall_list_request_t request;
    char path[XAIOS_XBFS_PATH_MAX];
    uint64_t out_size = 0;
    if (syscall_table_copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        vmm_validate_user_buffer(arg2, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-fs-list-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg2, sizeof(request));
    if (request.buffer_size == 0 ||
        request.buffer_size > XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        security_authorize_fs_read(path) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-list-denied");
    }
    if (vfs_list(path, (char *)(uintptr_t)request.buffer,
                 request.buffer_size, &out_size) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "fs-list-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return syscall_dispatch_complete(out_size);
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
