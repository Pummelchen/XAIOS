#!/usr/bin/env python3
"""Wrap a position-independent ELF executable in a PE/COFF container.

UEFI loads PE images, and LLVM has no RISC-V COFF backend -- `clang --target=
riscv64-unknown-windows` silently produces ELF, and lld-link cannot link it.
That is the whole reason this exists: on AArch64 and x86-64 the loader is
built straight to PE and none of this is needed.

The approach is the one the Linux EFI stub uses. The loader is linked as a
position-independent ELF whose only dynamic relocations are R_RISCV_RELATIVE,
and each of those becomes a PE base relocation of type DIR64, which has the
same meaning: add the load address to the eight bytes at this place. The one
difference that matters is where the value comes from. RELA keeps the addend
in the relocation entry and leaves the target word zero; PE has no addend and
adds the delta to whatever the target already holds. So the addend is written
into the target here, and ImageBase is zero, which makes the delta the load
address and the two schemes agree.

A PE with no relocations would be simpler and is a trap: EDK2 marks such an
image relocations-stripped and must load it at its ImageBase, failing outright
if that address is not free. An image that carries its relocations loads
anywhere.
"""
import argparse
import struct
import sys
from pathlib import Path

PAGE = 0x1000
FILE_ALIGN = 0x200
IMAGE_FILE_MACHINE_RISCV64 = 0x5064
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_MACHINE_AMD64 = 0x8664
SUBSYSTEM_EFI_APPLICATION = 10
R_RISCV_RELATIVE = 3
IMAGE_REL_BASED_DIR64 = 10

MACHINES = {
    "riscv64": IMAGE_FILE_MACHINE_RISCV64,
    "aarch64": IMAGE_FILE_MACHINE_ARM64,
    "x86_64": IMAGE_FILE_MACHINE_AMD64,
}


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


class Elf:
    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise SystemExit("not a little-endian 64-bit ELF")
        self.data = data
        self.entry, self.phoff, self.shoff = struct.unpack_from("<QQQ", data, 0x18)
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 0x36)
        self.shentsize, self.shnum, self.shstrndx = struct.unpack_from(
            "<HHH", data, 0x3A)

    def segments(self):
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            (p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
             p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", self.data, off)
            if p_type == 1:  # PT_LOAD
                yield p_flags, p_offset, p_vaddr, p_filesz, p_memsz

    def sections(self):
        names_off = struct.unpack_from(
            "<Q", self.data, self.shoff + self.shstrndx * self.shentsize + 0x18)[0]
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            (sh_name, sh_type, _flags, sh_addr, sh_offset, sh_size,
             _link, _info, _align, _entsize) = struct.unpack_from(
                 "<IIQQQQIIQQ", self.data, off)
            end = self.data.index(b"\0", names_off + sh_name)
            name = self.data[names_off + sh_name:end].decode()
            yield name, sh_type, sh_addr, sh_offset, sh_size

    def relative_relocations(self):
        """(target vaddr, addend) for every R_RISCV_RELATIVE entry."""
        for name, _type, _addr, offset, size in self.sections():
            if name != ".rela.dyn":
                continue
            for k in range(0, size, 24):
                r_offset, r_info, r_addend = struct.unpack_from(
                    "<QQq", self.data, offset + k)
                kind = r_info & 0xFFFFFFFF
                if kind != R_RISCV_RELATIVE:
                    raise SystemExit(
                        f"unsupported dynamic relocation type {kind}; only "
                        f"R_RISCV_RELATIVE can be expressed as a PE base "
                        f"relocation without a symbol table")
                yield r_offset, r_addend


def build(elf_path, out_path, machine):
    elf = Elf(Path(elf_path).read_bytes())

    # One PE section per loadable segment. RVAs are shifted by one page so the
    # PE headers have somewhere to live; the ELF is linked from zero.
    sections = []
    for flags, offset, vaddr, filesz, memsz in elf.segments():
        raw = bytearray(elf.data[offset:offset + filesz])
        if flags & 0x1:
            name, characteristics = b".text", 0x60000020
        elif flags & 0x2:
            name, characteristics = b".data", 0xC0000040
        else:
            name, characteristics = b".rodata", 0x40000040
        sections.append({
            "name": name, "rva": vaddr + PAGE, "vsize": memsz,
            "raw": raw, "flags": characteristics, "vaddr": vaddr,
        })

    # Materialise the RELA addends, which PE has no place to record.
    relocations = []
    for target, addend in elf.relative_relocations():
        for section in sections:
            start = section["vaddr"]
            if start <= target < start + len(section["raw"]):
                at = target - start
                section["raw"][at:at + 8] = struct.pack("<Q", addend)
                relocations.append(target + PAGE)
                break
        else:
            raise SystemExit(f"relocation at 0x{target:x} is outside every "
                             f"loadable segment")

    # Base relocation table, one block per page.
    blocks = {}
    for rva in sorted(relocations):
        blocks.setdefault(rva & ~(PAGE - 1), []).append(rva & (PAGE - 1))
    reloc = bytearray()
    for page, entries in sorted(blocks.items()):
        size = 8 + len(entries) * 2
        if size % 4:
            size += 2
        reloc += struct.pack("<II", page, size)
        for entry in entries:
            reloc += struct.pack("<H", (IMAGE_REL_BASED_DIR64 << 12) | entry)
        if len(entries) % 2:
            reloc += struct.pack("<H", 0)

    reloc_rva = align_up(
        max(s["rva"] + s["vsize"] for s in sections), PAGE)
    if reloc:
        sections.append({"name": b".reloc", "rva": reloc_rva,
                         "vsize": len(reloc), "raw": bytearray(reloc),
                         "flags": 0x42000040, "vaddr": None})

    # Distinct names. Two writable segments both called .data is legal and
    # confuses every tool that reads the result, this script's own debugging
    # included.
    seen = {}
    for section in sections:
        base = section["name"]
        seen[base] = seen.get(base, 0) + 1
        if seen[base] > 1:
            section["name"] = base + str(seen[base]).encode()

    header_size = align_up(0x40 + 0x18 + 0xF0 + 0x28 * len(sections),
                           FILE_ALIGN)
    if header_size > PAGE:
        raise SystemExit("PE headers do not fit in the page reserved for them")

    cursor = header_size
    for section in sections:
        section["file_offset"] = cursor
        section["raw_size"] = align_up(len(section["raw"]), FILE_ALIGN)
        cursor += section["raw_size"]

    size_of_image = align_up(
        max(s["rva"] + s["vsize"] for s in sections), PAGE)

    out = bytearray(header_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    pe = 0x40
    out[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", out, pe + 4,
                     MACHINES[machine], len(sections), 0, 0, 0, 0xF0,
                     0x0002 | 0x0020)  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    opt = pe + 24
    text = next((s for s in sections if s["name"] == b".text"), sections[0])
    struct.pack_into("<HBBIIIII", out, opt,
                     0x20B, 0, 0,
                     sum(s["raw_size"] for s in sections if s["flags"] & 0x20),
                     sum(s["raw_size"] for s in sections
                         if s["flags"] & 0x40 and not s["flags"] & 0x20),
                     0, elf.entry + PAGE, text["rva"])
    struct.pack_into("<QIIHHHHHHIIIIHH", out, opt + 24,
                     0,            # ImageBase: zero, so the delta is the load
                     PAGE, FILE_ALIGN,
                     0, 0, 0, 0, 0, 0, 0,
                     size_of_image, header_size, 0,
                     SUBSYSTEM_EFI_APPLICATION, 0)
    # Stack and heap reserve/commit are zero: UEFI applications run on the
    # firmware's stack, and these fields are advisory for them.
    struct.pack_into("<QQQQII", out, opt + 72,
                     0, 0, 0, 0, 0, 16)
    directories = opt + 112
    if reloc:
        struct.pack_into("<II", out, directories + 5 * 8, reloc_rva, len(reloc))

    table = opt + 0xF0
    for i, section in enumerate(sections):
        entry = table + i * 0x28
        out[entry:entry + 8] = section["name"].ljust(8, b"\0")
        struct.pack_into("<IIIIIIHHI", out, entry + 8,
                         section["vsize"], section["rva"],
                         section["raw_size"], section["file_offset"],
                         0, 0, 0, 0, section["flags"])

    for section in sections:
        out += bytes(section["raw"]).ljust(section["raw_size"], b"\0")

    Path(out_path).write_bytes(bytes(out))
    print(f"elf-to-efi: {out_path} machine={machine} sections={len(sections)} "
          f"relocations={len(relocations)} image_size=0x{size_of_image:x}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--machine", choices=sorted(MACHINES), required=True)
    parser.add_argument("elf")
    parser.add_argument("output")
    args = parser.parse_args()
    build(args.elf, args.output, args.machine)
    return 0


if __name__ == "__main__":
    sys.exit(main())
