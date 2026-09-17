/* Declarations shared by the XAIOS UEFI loader translation units. */

#ifndef XAIOS_LOADER_COMMON_H
#define XAIOS_LOADER_COMMON_H

#include "boot_info.h"
#include "include/uefi_min.h"

#define EI_NIDENT 16
#define PT_LOAD 1
#define PT_DYNAMIC 2
/* Where this loader looks for its kernel.
 *
 * One boot medium carries both architectures, and the two kernels cannot both
 * be called kernel.elf. Each loader asks for its own name first and falls back
 * to the shared one, so a single-architecture image built the old way still
 * boots: the fallback is what those images have always contained. */
#if defined(XAIOS_UEFI_TARGET_X86_64)
#define XAIOS_KERNEL_PATH u"\\EFI\\XAIOS\\kernel-x86_64.elf"
#elif defined(__riscv)
#define XAIOS_KERNEL_PATH u"\\EFI\\XAIOS\\kernel-riscv64.elf"
#else
#define XAIOS_KERNEL_PATH u"\\EFI\\XAIOS\\kernel-aarch64.elf"
#endif
#define XAIOS_KERNEL_PATH_SHARED u"\\EFI\\XAIOS\\kernel.elf"
/* The initial filesystem is architecture-specific too -- it holds userspace
   ELFs -- so a medium carrying both needs two of them. Same primary/fallback
   shape as the kernel, so an image built the old way still boots. */
#if defined(XAIOS_UEFI_TARGET_X86_64)
#define XAIOS_INITFS_PATH u"\\EFI\\XAIOS\\initfs-x86_64.img"
#elif defined(__riscv)
#define XAIOS_INITFS_PATH u"\\EFI\\XAIOS\\initfs-riscv64.img"
#else
#define XAIOS_INITFS_PATH u"\\EFI\\XAIOS\\initfs-aarch64.img"
#endif
#define XAIOS_INITFS_PATH_SHARED u"\\EFI\\XAIOS\\initfs.img"
/* Matches EARLY_IDENTITY_SIZE in kernel/arch/aarch64/mmu.c. */
#define XAIOS_LOADER_MAX_KERNEL_ADDRESS UINT64_C(0x100000000)
#define DT_NULL 0
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
/* The only relocation either architecture's kernel emits: add the load bias to
   a stored address. Everything else would need a symbol table the kernel does
   not carry. */
#define R_AARCH64_RELATIVE 1027
#define R_X86_64_RELATIVE 8
#define PF_X 0x1U
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EM_X86_64 62
#define EM_AARCH64 183
#define EM_RISCV 243
#define ET_EXEC 2
#define ET_DYN 3
#define KERNEL_MAX_SIZE (16ULL * 1024ULL * 1024ULL)
/*
 * The initfs is loaded by the UEFI path before a block driver is available.
 * Keep this bound finite, but large enough for the complete XAIOS app set.
 */
#define BOOT_IMAGE_MAX_SIZE (32ULL * 1024ULL * 1024ULL)

#if defined(XAIOS_UEFI_TARGET_X86_64)
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: x86_64 UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid x86_64 ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_X86_64
#define XAIOS_LOADER_UART_BASE UINT64_C(0x000003f8)
#define XAIOS_LOADER_UART_KIND XAIOS_UART_16550_IO
#elif defined(__riscv)
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: RISC-V UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid RISC-V ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_RISCV
/* The 16550 the virt board puts at the bottom of its device range. The device
   tree says so too, and the kernel reads it from there; this is only what the
   loader itself prints through before the kernel exists. */
#define QEMU_VIRT_RISCV_UART0_BASE UINT64_C(0x10000000)
#define XAIOS_LOADER_UART_BASE QEMU_VIRT_RISCV_UART0_BASE
#define XAIOS_LOADER_UART_KIND XAIOS_UART_16550_MMIO
#else
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: AArch64 UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid AArch64 ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_AARCH64
#define QEMU_VIRT_PL011_UART0_BASE UINT64_C(0x09000000)
#define XAIOS_LOADER_UART_BASE QEMU_VIRT_PL011_UART0_BASE
#define XAIOS_LOADER_UART_KIND XAIOS_UART_PL011
#endif

#define ACPI_HEADER_SIZE UINT32_C(36)
#define ACPI_MAX_TABLE_SIZE UINT32_C(0x01000000)
#define EFI_TEXT_CYAN UINT64_C(3)
#define EFI_TEXT_MAGENTA UINT64_C(5)
#define EFI_TEXT_LIGHTGRAY UINT64_C(7)

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

typedef struct elf64_ehdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct elf64_dyn {
  uint64_t d_tag;
  uint64_t d_val;
} elf64_dyn_t;

typedef struct elf64_rela {
  uint64_t r_offset;
  uint64_t r_info;
  int64_t r_addend;
} elf64_rela_t;

typedef struct elf64_phdr {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} elf64_phdr_t;

typedef void (*kernel_entry_t)(const xaios_boot_info_t *boot_info);

static inline void *mem_copy(void *dst, const void *src, uint64_t size) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  for (uint64_t i = 0; i < size; ++i) {
    d[i] = s[i];
  }
  return dst;
}

static inline void *mem_set(void *dst, int value, uint64_t size) {
  unsigned char *d = (unsigned char *)dst;
  for (uint64_t i = 0; i < size; ++i) {
    d[i] = (unsigned char)value;
  }
  return dst;
}

static inline int is_error(efi_status_t status) {
  return (status & (1ULL << 63)) != 0;
}

#endif
