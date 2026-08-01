# Getting Started with XAIOS

This guide covers setting up a development environment, building XAIOS, running it in QEMU, and writing your first userspace application.

## Prerequisites

### macOS (primary development platform)

```sh
brew install llvm lld qemu mtools python3
```

The build system auto-detects Homebrew LLVM/L LD paths. System clang on macOS is **not** sufficient — you need the Homebrew `llvm` package for AArch64 cross-compilation support.

### Linux (Ubuntu/Debian)

```sh
sudo apt-get update
sudo apt-get install -y clang lld qemu-system-arm qemu-efi-aarch64 mtools python3
```

## Building

From the repository root:

```sh
make bootstrap    # One-time toolchain verification
make image        # Build everything → build/xaios-aarch64.img
```

The build produces:
- `build/uefi/BOOTAA64.EFI` — UEFI bootloader
- `build/kernel/kernel.elf` — Kernel ELF binary
- `build/xaios-aarch64.img` — 64 MB FAT boot image
- `build/xaios-virtio-test.img` — VirtIO block device with initramfs
- `build/xaios-persistent.img` — Persistent mutable storage (4 MB)

## Running

### Interactive boot

```sh
make qemu         # or: make qemu-aarch64
```

This launches QEMU with serial output to the terminal. Press `Ctrl-A X` to quit.
The AArch64 launcher defaults to TCG, including on Apple Silicon. HVF is an
explicit experimental override (`XAIOS_QEMU_ACCEL=hvf`) because current
QEMU/HVF exception handling may abort instead of returning control to the guest.

### Automated smoke test

```sh
make qemu-smoke   # Boots and validates the AArch64 QEMU contract
```

The smoke test is the primary AArch64 QEMU validation: it boots the prototype,
executes its self-tests and userspace fixtures, and validates JSON telemetry.
It is correctness evidence, not production or hardware-performance evidence.

### Other test targets

| Target | What it tests |
|--------|--------------|
| `make qemu-process-gate` | Process lifecycle and scheduler |
| `make qemu-osctl-gate` | Control-plane telemetry |
| `make qemu-filesystem-gate` | Mutable filesystem operations |
| `make qemu-network-suite` | Network stack (UDP/TCP) |
| `make qemu-cpu-ai-suite` | CPU-only AI runtime |
| `make qemu-regression-suite` | Full regression suite |
| `make qemu-benchmark` | QEMU correctness telemetry collection |
| `make qemu-readiness-gate` | QEMU correctness-readiness validation |

## Writing a Userspace Application

### 1. Create the source file

Create `userspace/apps/myapp.c`:

```c
#include <xaios_user.h>

int main(void) {
    xaios_log("myapp: starting\n");

    // Use any XAIOS syscall
    u64 now = xaios_clock_nanos();
    xaios_log("myapp: clock_nanos = ");
    xaios_log_u64("", now, "\n");

    // Filesystem operations
    xaios_fs_mkdir("/state/myapp");
    xaios_write_file("/state/myapp/data.txt", "hello from myapp");

    char buf[256];
    int n = xaios_read_file("/state/myapp/data.txt", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        xaios_log("myapp: read back: ");
        xaios_log(buf);
        xaios_log("\n");
    }

    xaios_log("myapp: done\n");
    return 0;
}
```

### 2. Register the app in the build

Edit `scripts/build-image.sh`, line 23. Add your app name to `USER_APPS`:

```sh
USER_APPS="xaios-shell hello sysinfo systest smptest nettest lstm-xor sshtest mltest myapp"
```

### 3. Register the app in kmain

Edit `kernel/core/kmain.c`, add after the existing `run_user_app` calls (around line 308):

```c
run_user_app("/bin/myapp", 15, app_caps);
```

The `app_caps` bitmask includes all standard capabilities (LOG, EXIT, OSCTL, FS_READ, FS_WRITE, TIME, NET, SMP, CPU_AI, REMOTE_LOGIN, THREADS, ML, NET_SOCKET).

### 4. Add a smoke test marker (optional)

Edit `scripts/qemu-smoke.py`, add your expected output to the `TARGETS` list:

```python
"myapp: done",
```

### 5. Build and test

```sh
make image && make qemu-smoke
```

### Key constraints

- **No libc**: Use `xaios_user.h` functions only. `xaios_memzero()`, `xaios_strlen()`, `memcpy()`, `memset()` are available.
- **No dynamic allocation**: The userspace runtime has no `malloc`. Use stack buffers or fixed-size arrays.
- **Freestanding C99**: Standard C99 only. No POSIX headers, no standard library.
- **Single-threaded**: Each app runs as a single process. Use `xaios_thread_group_run()` for parallelism within CPU 0, or `xaios_smp_run()` to dispatch to secondary cores.
- **Exit cleanly**: Return 0 from `main()`. The runtime calls `xaios_exit()` automatically.

## Architecture Reference

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system architecture, boot flow, and memory layout.

## API Reference

See [API.md](API.md) for the complete syscall table, capability system, and data type definitions.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.
