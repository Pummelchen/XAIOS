#!/usr/bin/env python3
import pathlib
import struct
import sys


SECTOR_SIZE = 512
MAGIC = b"XAIOSROFS2"
VERSION = 2
MAX_FILES = 32
PATH_MAX = 64
HEADER_SECTOR = 1
HEADER_BYTES = 3584
# Sectors 3000 through 3185 are reserved for the kernel's persistence and
# MutableFS boot self-tests. Keep the immutable payload beyond that scratch
# range so repeated boots cannot overwrite executable data.
DATA_OFFSET = 2097152
FLAG_READ_ONLY = 1
ENTRY_FLAG_EXECUTABLE = 1
ENTRY_FLAG_MANIFEST = 2
ENTRY_TYPE_FILE = 1
CPU_AI_MAGIC = 0x4941494D
CPU_AI_VERSION = 1
CPU_AI_HEADER_BYTES = 80
CPU_AI_QUANTIZATION_SUPPORTED = 8
CPU_AI_FLAG_CPU_ONLY = 1
CPU_AI_TOKENIZER_BYTE_TABLE = 1
CPU_AI_RUNTIME_DETERMINISTIC = 1


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def fnv1a64_hash(content: bytes) -> int:
    value = 14695981039346656037
    for byte in content:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def create_cpu_ai_model() -> bytes:
    weights = bytes([0x5A, 0x03]) + bytes([0xAA, 0xBB, 0xCC, 0xDD]) + bytes(26)
    tokenizer = bytes(range(256))
    weights_offset = CPU_AI_HEADER_BYTES
    tokenizer_offset = weights_offset + len(weights)
    payload_hash = fnv1a64_hash(weights + tokenizer)
    manifest = struct.pack(
        "<IHHHHIIIQQQQQQBB6s",
        CPU_AI_MAGIC,
        CPU_AI_VERSION,
        CPU_AI_HEADER_BYTES,
        CPU_AI_QUANTIZATION_SUPPORTED,
        0,
        CPU_AI_FLAG_CPU_ONLY,
        CPU_AI_TOKENIZER_BYTE_TABLE,
        CPU_AI_RUNTIME_DETERMINISTIC,
        weights_offset,
        len(weights),
        tokenizer_offset,
        len(tokenizer),
        4096,
        payload_hash,
        0x5A,
        0x03,
        b"\0" * 6,
    )
    if len(manifest) != CPU_AI_HEADER_BYTES:
        raise SystemExit(f"bad CPU-AI model header size: {len(manifest)}")
    return manifest + weights + tokenizer


def write_entry(path: str, offset: int, size: int, flags: int, content_hash: int) -> bytes:
    encoded = path.encode("ascii")
    if len(encoded) >= PATH_MAX:
        raise SystemExit(f"path too long for initfs: {path}")
    return (
        encoded.ljust(PATH_MAX, b"\0")
        + struct.pack("<QQIIQ", offset, size, flags, ENTRY_TYPE_FILE, content_hash)
    )


def main() -> int:
    if len(sys.argv) < 7:
        print(
            "usage: create-initfs.py <image> <init-elf> <service-manager-elf> <worker-elf> <config> <service-descriptor> [<initfs-path>=<host-file> ...]",
            file=sys.stderr,
        )
        return 2

    image = pathlib.Path(sys.argv[1])
    init_elf = pathlib.Path(sys.argv[2]).read_bytes()
    service_manager_elf = pathlib.Path(sys.argv[3]).read_bytes()
    worker_elf = pathlib.Path(sys.argv[4]).read_bytes()
    config = pathlib.Path(sys.argv[5]).read_bytes()
    service_descriptor = pathlib.Path(sys.argv[6]).read_bytes()
    model_file = create_cpu_ai_model()
    files = [
        ("/init", init_elf, ENTRY_FLAG_EXECUTABLE),
        ("/bin/service-manager", service_manager_elf, ENTRY_FLAG_EXECUTABLE),
        ("/bin/xaios-worker", worker_elf, ENTRY_FLAG_EXECUTABLE),
        ("/etc/xaios-init.conf", config, ENTRY_FLAG_MANIFEST),
        ("/etc/services/source-index.svc", service_descriptor, 0),
        ("/models/cpu-ai-v1-fixture.xaiosmodel", model_file, 0),
    ]
    for spec in sys.argv[7:]:
        if "=" not in spec:
            raise SystemExit(f"bad extra initfs spec: {spec}")
        path, host_file = spec.split("=", 1)
        if not path.startswith("/"):
            raise SystemExit(f"initfs path must be absolute: {path}")
        flags = ENTRY_FLAG_EXECUTABLE if path.startswith("/bin/") else 0
        files.append((path, pathlib.Path(host_file).read_bytes(), flags))
    if len(files) > MAX_FILES:
        raise SystemExit("too many initfs files")

    offset = DATA_OFFSET
    entries = []
    payloads = []
    for path, content, flags in files:
        offset = align(offset, SECTOR_SIZE)
        entries.append(write_entry(path, offset, len(content), flags, fnv1a64_hash(content)))
        payloads.append((offset, content))
        offset += len(content)

    image_size = align(offset, SECTOR_SIZE)
    manifest_index = 3
    header = MAGIC.ljust(16, b"\0") + struct.pack(
        "<IIIIIIQQ",
        VERSION,
        HEADER_BYTES,
        SECTOR_SIZE,
        len(files),
        manifest_index,
        FLAG_READ_ONLY,
        DATA_OFFSET,
        image_size,
    )
    header += b"".join(entries)
    if len(header) > HEADER_BYTES:
        raise SystemExit("initfs directory exceeds reserved header")
    header = header.ljust(HEADER_BYTES, b"\0")
    with image.open("r+b") as f:
        f.seek(HEADER_SECTOR * SECTOR_SIZE)
        f.write(header)
        for payload_offset, content in payloads:
            f.seek(payload_offset)
            f.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
