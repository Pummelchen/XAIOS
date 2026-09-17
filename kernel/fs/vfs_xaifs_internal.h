/* Private interface shared by the model VFS sources.
 *
 * vfs_xaifs.c keeps the mount, the model context, the maintenance predicate,
 * the open/stat/statfs/list operations and the backend ops table;
 * vfs_xaifs_io.c owns the block and engine glue and the handle read/write
 * path; vfs_xaifs_catalog.c owns the catalog lookup, the staging lifecycle
 * and the signed self-test; vfs_xaifs_scrub.c owns the scrub/verify job and
 * its persisted record; vfs_xaifs_trim.c owns the trim job and its persisted
 * record. All of them need the model context layout, so the type lives here.
 * The context itself stays in vfs_xaifs.c and is reached through
 * vfs_xaifs_model(); every other source calls that under the model lock
 * exactly where it used the variable.
 */
#ifndef XAIOS_FS_VFS_XAIFS_INTERNAL_H
#define XAIOS_FS_VFS_XAIFS_INTERNAL_H

#include <xaios/block_device.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/vfs.h>
#include <xaios/vfs_xaifs.h>
#include <xaios/virtio_blk.h>

#include <xaios_engine/xai_fs.h>

#define MODEL_READER_SCRATCH_SIZE UINT64_C(65536)
#define MODEL_READER_MAX_SECTOR_SIZE UINT64_C(4096)
#define MODEL_VFS_MAX_HANDLES 64U
#define MODEL_PACKAGE_NAME_LENGTH 64U

typedef struct model_vfs_handle {
  uint32_t active;
  uint32_t writable;
  uint64_t package_index;
  uint64_t written_start;
  uint64_t written_end;
} model_vfs_handle_t;

typedef struct model_vfs_context {
  virtio_block_handle_t *handle;
  xaios_block_device_t *device;
  xaios_block_device_info_t device_info;
  xaios_xai_fs_t volume;
  xaios_spinlock_t lock;
  uint8_t bounce[MODEL_READER_MAX_SECTOR_SIZE];
  uint8_t scratch[MODEL_READER_SCRATCH_SIZE];
  model_vfs_handle_t handles[MODEL_VFS_MAX_HANDLES];
  uint32_t mounted;
  uint32_t owns_block_open;
  uint32_t read_only;
  /* The chunk record most recently looked up, and which index it is.
     Reading a chunk record is a read off the volume, and a run of small
     reads inside one chunk asked for the same record every time -- eight
     volume reads to serve eight windows out of RAM. Consecutive reads are
     overwhelmingly in the same chunk, so one entry catches almost all of it.
     Valid only while `chunk_memo_generation` matches the volume's. */
  xaios_xai_fs_chunk_t chunk_memo;
  uint64_t chunk_memo_index;
  uint64_t chunk_memo_generation;
  uint32_t chunk_memo_valid;
  char mount_path[XAIOS_VFS_PATH_MAX];
} model_vfs_context_t;

/* Defined in vfs_xaifs.c. Callers hold the context's lock for every field
   that is not read before the lock is taken. */
model_vfs_context_t *vfs_xaifs_model(void);

/* Defined in vfs_xaifs.c and shared with the trim, catalog and scrub halves. */
int catalog_maintenance_active(void);

/* Defined in vfs_xaifs_io.c and shared with the trim and catalog halves. */
xaios_status_t map_engine_status(xaios_engine_status_t status);

/* Defined in vfs_xaifs_io.c and shared with the scrub half, which builds the
   same writer for the quarantine path. */
xaios_engine_status_t vfs_xaifs_write_at(void *context, uint64_t offset,
                                         const void *source, size_t length);
xaios_engine_status_t vfs_xaifs_flush(void *context);

/* Defined in vfs_xaifs_io.c. The mount opens the engine with the reader and
   signature callbacks, and the backend ops table in vfs_xaifs.c names the
   handle operations. */
xaios_engine_status_t vfs_xaifs_read_at(void *context, uint64_t offset,
                                        void *destination, size_t length);
xaios_engine_status_t vfs_xaifs_verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]);
xaios_status_t vfs_xaifs_close(void *context, uint64_t handle);
int64_t vfs_xaifs_pread(void *context, uint64_t handle, void *buffer,
                        uint64_t length, uint64_t offset);
int64_t vfs_xaifs_pwrite(void *context, uint64_t handle, const void *buffer,
                         uint64_t length, uint64_t offset);
xaios_status_t vfs_xaifs_fsync(void *context, uint64_t handle);

/* Defined in vfs_xaifs_catalog.c; the open and stat paths look packages up
   through it. */
xaios_status_t vfs_xaifs_find_package(model_vfs_context_t *model,
                                      const char *path, uint64_t *index,
                                      xaios_xai_fs_package_t *package);

/* Defined in vfs_xaifs_trim.c and used by the maintenance predicate in
   vfs_xaifs.c and by the scrub half: scrub and trim exclude each other, and a
   mount resumes a persisted trim. */
uint32_t vfs_xaifs_trim_state(void);
void vfs_xaifs_trim_load(void);

/* Defined in vfs_xaifs_scrub.c and used by the mount and the maintenance
   predicate in vfs_xaifs.c. */
uint32_t vfs_xaifs_scrub_state(void);
void vfs_xaifs_scrub_load(void);

#endif /* XAIOS_FS_VFS_XAIFS_INTERNAL_H */
