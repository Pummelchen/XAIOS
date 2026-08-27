#ifndef XAIOS_UEFI_MIN_H
#define XAIOS_UEFI_MIN_H

#include <stdint.h>

#define EFIAPI
#define EFI_SUCCESS ((efi_status_t)0)
#define EFI_ERROR_BIT UINT64_C(0x8000000000000000)
#define EFI_BUFFER_TOO_SMALL ((efi_status_t)(EFI_ERROR_BIT | 5))
#define EFI_LOAD_ERROR ((efi_status_t)(EFI_ERROR_BIT | 1))
#define EFI_INVALID_PARAMETER ((efi_status_t)(EFI_ERROR_BIT | 2))
#define EFI_NOT_FOUND ((efi_status_t)(EFI_ERROR_BIT | 14))
#define EFI_DEVICE_ERROR ((efi_status_t)(EFI_ERROR_BIT | 7))
#define EFI_WRITE_PROTECTED ((efi_status_t)(EFI_ERROR_BIT | 8))
#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL 0x00000001U
#define EFI_FILE_MODE_READ UINT64_C(0x0000000000000001)
#define EFI_ALLOCATE_ANY_PAGES 0
#define EFI_ALLOCATE_MAX_ADDRESS 1
#define EFI_ALLOCATE_ADDRESS 2
/* Firmware that enforces W^X maps EfiLoaderData execute-never, so anything
   the loader intends to jump into has to be allocated as code. */
#define EFI_LOADER_CODE 1
#define EFI_LOADER_DATA 2
#define EFI_SIZE_TO_PAGES(size) (((size) + 0xfffULL) >> 12)

typedef uint16_t efi_char16_t;
typedef uint64_t efi_status_t;
typedef uint64_t efi_physical_address_t;
typedef void *efi_handle_t;

typedef struct efi_guid {
  uint32_t data1;
  uint16_t data2;
  uint16_t data3;
  uint8_t data4[8];
} efi_guid_t;

typedef struct efi_table_header {
  uint64_t signature;
  uint32_t revision;
  uint32_t header_size;
  uint32_t crc32;
  uint32_t reserved;
} efi_table_header_t;

typedef struct efi_simple_text_output_protocol efi_simple_text_output_protocol_t;
typedef struct efi_boot_services efi_boot_services_t;
typedef struct efi_runtime_services efi_runtime_services_t;
typedef struct efi_loaded_image_protocol efi_loaded_image_protocol_t;
typedef struct efi_simple_file_system_protocol efi_simple_file_system_protocol_t;
typedef struct efi_file_protocol efi_file_protocol_t;
typedef struct efi_block_io_protocol efi_block_io_protocol_t;
typedef struct efi_block_io_media efi_block_io_media_t;
typedef struct efi_rng_protocol efi_rng_protocol_t;
typedef struct efi_graphics_output_protocol efi_graphics_output_protocol_t;
typedef struct efi_graphics_output_protocol_mode efi_graphics_output_protocol_mode_t;
typedef struct efi_graphics_output_mode_information efi_graphics_output_mode_information_t;
typedef struct efi_system_table efi_system_table_t;
typedef struct efi_configuration_table efi_configuration_table_t;

#define EFI_LOCATE_BY_PROTOCOL 2

struct efi_simple_text_output_protocol {
  void *reset;
  efi_status_t(EFIAPI *output_string)(
      efi_simple_text_output_protocol_t *self,
      const efi_char16_t *string);
  void *test_string;
  void *query_mode;
  void *set_mode;
  efi_status_t(EFIAPI *set_attribute)(
      efi_simple_text_output_protocol_t *self, uint64_t attribute);
  efi_status_t(EFIAPI *clear_screen)(
      efi_simple_text_output_protocol_t *self);
  void *set_cursor_position;
  void *enable_cursor;
  void *mode;
};

struct efi_boot_services {
  efi_table_header_t hdr;
  void *raise_tpl;
  void *restore_tpl;
  efi_status_t(EFIAPI *allocate_pages)(int type, int memory_type,
                                       uint64_t pages,
                                       efi_physical_address_t *memory);
  efi_status_t(EFIAPI *free_pages)(efi_physical_address_t memory,
                                   uint64_t pages);
  efi_status_t(EFIAPI *get_memory_map)(uint64_t *memory_map_size,
                                       void *memory_map, uint64_t *map_key,
                                       uint64_t *descriptor_size,
                                       uint32_t *descriptor_version);
  efi_status_t(EFIAPI *allocate_pool)(int pool_type, uint64_t size,
                                      void **buffer);
  efi_status_t(EFIAPI *free_pool)(void *buffer);
  void *create_event;
  void *set_timer;
  void *wait_for_event;
  void *signal_event;
  void *close_event;
  void *check_event;
  void *install_protocol_interface;
  void *reinstall_protocol_interface;
  void *uninstall_protocol_interface;
  efi_status_t(EFIAPI *handle_protocol)(efi_handle_t handle,
                                        efi_guid_t *protocol,
                                        void **interface);
  void *reserved;
  void *register_protocol_notify;
  void *locate_handle;
  void *locate_device_path;
  void *install_configuration_table;
  void *load_image;
  void *start_image;
  void *exit;
  void *unload_image;
  efi_status_t(EFIAPI *exit_boot_services)(efi_handle_t image_handle,
                                           uint64_t map_key);
  void *get_next_monotonic_count;
  void *stall;
  void *set_watchdog_timer;
  void *connect_controller;
  void *disconnect_controller;
  efi_status_t(EFIAPI *open_protocol)(efi_handle_t handle,
                                      efi_guid_t *protocol,
                                      void **interface,
                                      efi_handle_t agent_handle,
                                      efi_handle_t controller_handle,
                                      uint32_t attributes);
  void *close_protocol;
  void *open_protocol_information;
  void *protocols_per_handle;
  efi_status_t(EFIAPI *locate_handle_buffer)(
      int search_type, efi_guid_t *protocol, void *search_key,
      uint64_t *handle_count, efi_handle_t **handles);
  void *locate_protocol;
  void *install_multiple_protocol_interfaces;
  void *uninstall_multiple_protocol_interfaces;
  void *calculate_crc32;
  void *copy_mem;
  void *set_mem;
  void *create_event_ex;
};

struct efi_loaded_image_protocol {
  uint32_t revision;
  efi_handle_t parent_handle;
  efi_system_table_t *system_table;
  efi_handle_t device_handle;
};

struct efi_simple_file_system_protocol {
  uint64_t revision;
  efi_status_t(EFIAPI *open_volume)(
      efi_simple_file_system_protocol_t *self,
      efi_file_protocol_t **root);
};

struct efi_file_protocol {
  uint64_t revision;
  efi_status_t(EFIAPI *open)(efi_file_protocol_t *self,
                             efi_file_protocol_t **new_handle,
                             const efi_char16_t *file_name,
                             uint64_t open_mode,
                             uint64_t attributes);
  efi_status_t(EFIAPI *close)(efi_file_protocol_t *self);
  void *delete_file;
  efi_status_t(EFIAPI *read)(efi_file_protocol_t *self,
                             uint64_t *buffer_size,
                             void *buffer);
};

struct efi_block_io_media {
  uint32_t media_id;
  uint8_t removable_media;
  uint8_t media_present;
  uint8_t logical_partition;
  uint8_t read_only;
  uint8_t write_caching;
  uint8_t pad[3];
  uint32_t block_size;
  uint32_t io_align;
  uint64_t last_block;
  uint64_t lowest_aligned_lba;
  uint32_t logical_blocks_per_physical_block;
  uint32_t optimal_transfer_length_granularity;
};

struct efi_block_io_protocol {
  uint64_t revision;
  efi_block_io_media_t *media;
  efi_status_t(EFIAPI *reset)(efi_block_io_protocol_t *self,
                              uint8_t extended_verification);
  efi_status_t(EFIAPI *read_blocks)(efi_block_io_protocol_t *self,
                                    uint32_t media_id, uint64_t lba,
                                    uint64_t buffer_size, void *buffer);
  efi_status_t(EFIAPI *write_blocks)(efi_block_io_protocol_t *self,
                                     uint32_t media_id, uint64_t lba,
                                     uint64_t buffer_size, const void *buffer);
  efi_status_t(EFIAPI *flush_blocks)(efi_block_io_protocol_t *self);
};

typedef efi_status_t(EFIAPI *efi_rng_get_info_t)(
    efi_rng_protocol_t *self, uint64_t *algorithm_list_size,
    efi_guid_t *algorithm_list);
typedef efi_status_t(EFIAPI *efi_rng_get_rng_t)(efi_rng_protocol_t *self,
                                                 efi_guid_t *algorithm,
                                                 uint64_t rng_value_length,
                                                 uint8_t *rng_value);

struct efi_rng_protocol {
  efi_rng_get_info_t get_info;
  efi_rng_get_rng_t get_rng;
};

struct efi_graphics_output_mode_information {
  uint32_t version;
  uint32_t horizontal_resolution;
  uint32_t vertical_resolution;
  uint32_t pixel_format;
  uint32_t pixel_information[4];
  uint32_t pixels_per_scan_line;
};

struct efi_graphics_output_protocol_mode {
  uint32_t max_mode;
  uint32_t mode;
  efi_graphics_output_mode_information_t *info;
  uint64_t size_of_info;
  efi_physical_address_t framebuffer_base;
  uint64_t framebuffer_size;
};

struct efi_graphics_output_protocol {
  efi_status_t(EFIAPI *query_mode)(
      efi_graphics_output_protocol_t *self, uint32_t mode_number,
      uint64_t *size_of_info,
      efi_graphics_output_mode_information_t **info);
  efi_status_t(EFIAPI *set_mode)(efi_graphics_output_protocol_t *self,
                                 uint32_t mode_number);
  void *blt;
  efi_graphics_output_protocol_mode_t *mode;
};

typedef efi_status_t(EFIAPI *efi_locate_protocol_t)(efi_guid_t *protocol,
                                                     void *registration,
                                                     void **interface);

struct efi_system_table {
  efi_table_header_t hdr;
  efi_char16_t *firmware_vendor;
  uint32_t firmware_revision;
  uint32_t _pad0;
  efi_handle_t console_in_handle;
  void *con_in;
  efi_handle_t console_out_handle;
  efi_simple_text_output_protocol_t *con_out;
  efi_handle_t standard_error_handle;
  efi_simple_text_output_protocol_t *std_err;
  efi_runtime_services_t *runtime_services;
  efi_boot_services_t *boot_services;
  uint64_t number_of_table_entries;
  efi_configuration_table_t *configuration_table;
};

struct efi_configuration_table {
  efi_guid_t vendor_guid;
  void *vendor_table;
};

#endif
