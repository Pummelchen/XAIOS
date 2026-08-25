# Getting Started with XAIOS

This guide covers setting up a development environment, building XAIOS, running it in QEMU, and writing your first userspace application.

## Prerequisites

### macOS (primary development platform)

```sh
brew install llvm lld qemu mtools python3 xorriso
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

The normal image uses an in-place 0-100% boot display rather than scrolling
diagnostic output. At completion it prints the configured IPv4 address and the
verified SSH listener state. The default development image presents `xaios
login:` and accepts `admin` with password `xaios`; after authentication its
local `admin@xaios:<cwd>$` prompt supports Backspace, `Ctrl-C`, `Ctrl-L`,
logout, filesystem commands and interactive `nano`. This is a public
development credential, not a deployment credential. Set
`XAIOS_SSH_PASSWORD_AUTH=0` for a key-only development image. Release images
always keep serial login locked and require SSH public-key authentication. SSH
port 22 is not bound until a bounded external IPv4 DNS lookup succeeds. A
failure is reported with a numeric error and does not weaken the local-console
authentication policy.

Set `XAIOS_BOOT_VERBOSE=1` only when diagnosing boot failures. The image then
keeps the progress markers in the serial log instead of using the in-place boot
display; normal builds default to `0`.

`make qemu-smmu-gate` additionally needs the test-only `iommu-testdev` from
upstream QEMU commit `6ce361b02c825b4a12a9684c47342859ee967cb2`.
`tests/scripts/provision-qemu-smmu-testdev.sh` builds and verifies that exact revision;
set `XAIOS_QEMU_SMMU` to its `qemu-system-aarch64` output. Aggregate CI performs
this provision automatically and keeps the gate mandatory.

### Automated smoke test

```sh
make qemu-smoke   # Boots and validates the AArch64 QEMU contract
```

The smoke test is the primary AArch64 QEMU validation: it boots the prototype,
builds the explicit `XAIOS_BOOT_TEST_APPS=1` profile, executes its self-tests and
userspace fixtures, and validates JSON telemetry. A normal `make image` leaves
those diagnostics stopped until an administrator invokes their exact command
name over SSH. `make image-qemu-test` builds the fixture profile directly.
It is correctness evidence, not production or hardware-performance evidence.

### VMware Fusion on Apple Silicon

VMware Fusion on Apple Silicon has a qualified one-vCPU ARM64 guest profile.
Docker builds the reproducible Debian 13 ARM64 GRUB compatibility stage; XAIOS
uses PCI-discovered E1000E networking and AHCI SATA storage.

```sh
make vmware-fusion-image
make vmware-fusion-smoke
make vmware-fusion
```

The generated VM is bridged by default, receives a DHCP address, and creates a
writable SATA VMDK for MutableFS. `make vmware-fusion-smoke` uses a disposable
authorized key and validates SSH, SFTP, recovery, reboot, shutdown and repeat
boot. Fusion still lacks multi-vCPU qualification, VMXNET3, complete live
DNSSEC interoperability, and physical-performance evidence; it also cannot
validate x86_64 guests. See [`VMWARE-FUSION.md`](./VMWARE-FUSION.md).

### Other test targets

| Target | What it tests |
|--------|--------------|
| `make qemu-process-gate` | Process lifecycle and scheduler |
| `make qemu-osctl-gate` | Control-plane telemetry |
| `make qemu-filesystem-gate` | Mutable filesystem operations |
| `make qemu-network-suite` | Network stack (UDP/TCP) |
| `make qemu-freebsd-network-suite` | FreeBSD 15.1 OpenSSH/SFTP/UDP Unix-reference interoperability |
| `make qemu-docker-network-suite` | Debian 13 OpenSSH/SFTP/UDP/IPv6 interoperability plus MutableFS v3/v4-to-v5 migration and reboot persistence |
| `make qemu-local-console-gate` | Wrong/correct local login, stateful prompt, filesystem commands, command errors and logout |
| `make qemu-cpu-ai-suite` | CPU-only AI runtime |
| `make qemu-regression-suite` | Full regression suite |
| `make qemu-benchmark` | QEMU correctness telemetry collection |
| `make qemu-readiness-gate` | QEMU correctness-readiness validation |
| `make vmware-fusion-smoke` | Fusion one-vCPU boot, E1000E DHCP, AHCI MutableFS, SSH/SFTP, recovery, reboot, shutdown and repeat boot |

### Mac client interoperability

The freestanding guest SSH/SFTP and UDP services can be exercised through QEMU
host forwarding. The default development image accepts `admin` / `xaios` for
local and SSH password authentication; use it only on an isolated development
network. Package a public key or a replacement PBKDF2 record before exposing a
guest outside localhost.

The primary external Unix-reference check boots an official, checksum-pinned
FreeBSD 15.1 AArch64 VM beside XAIOS:

```sh
make qemu-freebsd-network-suite
```

The first run downloads approximately 600 MiB into `~/.cache/xaios/freebsd`.
It requires QEMU, `qemu-img`, `xz`, and an ISO creator (`hdiutil`, `xorrisofs`,
`genisoimage`, or `mkisofs`). The separate Linux cross-client check uses the
official Debian 13 Docker base and tests Ed25519 and password
acceptance/rejection, default-disabled and malformed
credential configurations, secure-entropy failure, persistent host identity,
SFTP offsets, channel sharing, rekey, simultaneous SSH sessions, reconnect
recycling, UDP echo, and direct malformed/reordered/retransmitted TCP traffic:

```sh
make qemu-docker-network-suite
```

Docker is required for this target. Generated reports, serial logs, and packet
captures are placed under `build/`.

For a manual key-only image:

```sh
mkdir -p build/local-ssh
ssh-keygen -t ed25519 -N '' -f build/local-ssh/admin
XAIOS_AUTHORIZED_KEYS_FILE=build/local-ssh/admin.pub make image
```

To replace the development password, generate a strict PBKDF2 record with
`scripts/create-sshd-user-config.py` and pass it through
`XAIOS_SSH_USERS_FILE` together with `XAIOS_SSH_PASSWORD_AUTH=1`.
`XAIOS_BUILD_MODE=release` rejects every password-enabled image. See
[`NETWORK-SSH-STATUS.md`](./NETWORK-SSH-STATUS.md) for the exact commands and
security boundary.

```sh
XAIOS_QEMU_HOSTFWD_UDP_PORT=2298 make qemu
```

The QEMU launchers forward host TCP port `7788` to guest SSH port `22` by
default. OpenSSH's standard explicit-port syntax is
`ssh -p 7788 admin@127.0.0.1`; `admin@127.0.0.1:7788` is not valid OpenSSH
destination syntax. Recent OpenSSH clients also accept
`ssh ssh://admin@127.0.0.1:7788`.

From a second terminal, use the repository launcher for a quiet OpenSSH session
with persistent host-key checking. It accepts a remote command after `--`:

```sh
platform/qemu/ssh-xaios-qemu.sh -- htop
platform/qemu/ssh-xaios-qemu.sh -- pong
```

`pong` requires a PTY. Use `W` and `S` to move, `P` to pause, `R` to reset the
continuous score, and `Q` to return to the shell.

Use SFTP against `127.0.0.1:7788` and send UDP to `127.0.0.1:2298`. Direct
IPv6/TCP testing uses QEMU's framed socket backend:

```sh
XAIOS_QEMU_HOSTFWD_PORT=none XAIOS_QEMU_NET_SOCKET_PORT=12345 make qemu
python3 tests/network/qemu-ipv6-tcp-client.py --port 12345
```

Run the forwarding and framed-socket QEMU configurations separately. See
[`NETWORK-SSH-STATUS.md`](./NETWORK-SSH-STATUS.md) for exact client commands,
validated behavior, and remaining protocol boundaries.

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
USER_APPS="xaios-shell xaiosctl hello sysinfo systest smptest nettest lstm-xor sshtest mltest posix-shell agenttest myapp"
```

### 3. Register an execution path

Normal images do not run applications during boot. To expose a diagnostic over
SSH, add its exact command name, initramfs path, and least-privilege capability
mask to `g_remote_apps` in `kernel/runtime/remote_login.c`. The command accepts
no arguments and the runtime reaps it after completion.

For a deterministic boot fixture only, add a `run_user_app` call inside the
`XAIOS_BOOT_TEST_APPS` block in `kernel/core/kmain.c`:

```c
run_user_app("/bin/myapp", 15, app_caps);
```

The `app_caps` bitmask includes all standard capabilities (LOG, EXIT, OSCTL, FS_READ, FS_WRITE, TIME, NET, SMP, CPU_AI, REMOTE_LOGIN, THREADS, ML, NET_SOCKET).

### 4. Add a smoke test marker (optional)

Edit `tests/scripts/qemu-smoke.py`, add your expected output to the `TARGETS` list:

```python
"myapp: done",
```

### 5. Build and test

```sh
make image
make qemu-smoke
```

### Hosted C99 applications

The default application path above remains freestanding. A statically linked
hosted ISO C99 application can instead be built with:

```sh
make libc
scripts/build-c99-app.sh --arch aarch64 --main args app.c build/app.elf
scripts/build-c99-app.sh --arch x86_64 --main void app.c build/app-x86.elf
make qemu-libc-gate
```

The hosted sysroot exposes ISO C99 rather than POSIX. Registering the resulting
ELF in an image and assigning its least-privilege capability mask remain
explicit image-policy steps.

### Freestanding application constraints

- **No implicit libc**: The default app path uses `xaios_user.h`; hosted libc is an explicit build choice.
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
