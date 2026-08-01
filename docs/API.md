# XAIOS Userspace API Reference

This document describes the system call interface available to XAIOS userspace programs. All calls are made via `svc #0` with the syscall number in `x8` and up to three arguments in `x0`–`x2`.

## Invocation

```c
#include <xaios_user.h>

u64 xaios_syscall3(u64 number, u64 arg0, u64 arg1, u64 arg2);
```

All wrapper functions below are built on this primitive.

## Core Services

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_LOG` | 1 | `xaios_log(text)` | Write a string to the kernel log (UART). |
| `XAIOS_SYSCALL_EXIT` | 2 | `xaios_exit(code)` | Terminate the current process. |
| `XAIOS_SYSCALL_OSCTL` | 3 | `xaios_osctl(command)` | Send a control-plane command (JSON telemetry query). |
| `XAIOS_SYSCALL_CLOCK_NANOS` | 20 | `xaios_clock_nanos()` | Return monotonic wall-clock nanoseconds since boot. |

## Filesystem

All filesystem operations target the mutable filesystem (`mutable_fs`). Paths are absolute, rooted at `/`.

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_FS_OPEN` | 11 | `xaios_fs_open(path, flags)` | Open a file. Flags: `XAIOS_MFS_OPEN_READ` (1), `XAIOS_MFS_OPEN_WRITE` (2), `XAIOS_MFS_OPEN_CREATE` (4), `XAIOS_MFS_OPEN_TRUNCATE` (8). Returns fd >= 0 on success. |
| `XAIOS_SYSCALL_FS_READ` | 12 | `xaios_fs_read(fd, buf, size)` | Read up to `size` bytes from `fd` into `buf`. Returns bytes read. |
| `XAIOS_SYSCALL_FS_WRITE` | 13 | `xaios_fs_write(fd, buf, size)` | Write `size` bytes from `buf` to `fd`. Returns bytes written. |
| `XAIOS_SYSCALL_FS_CLOSE` | 14 | `xaios_fs_close(fd)` | Close an open file descriptor. |
| `XAIOS_SYSCALL_FS_STAT` | 15 | `xaios_fs_stat(path, stat)` | Populate `xaios_mfs_stat_user_t` with file metadata. |
| `XAIOS_SYSCALL_FS_MKDIR` | 16 | `xaios_fs_mkdir(path)` | Create a directory. |
| `XAIOS_SYSCALL_FS_DELETE` | 17 | `xaios_fs_delete(path)` | Delete a file or empty directory. |
| `XAIOS_SYSCALL_FS_RENAME` | 18 | `xaios_fs_rename(old, new)` | Rename a file or directory. |
| `XAIOS_SYSCALL_FS_LIST` | 19 | `xaios_fs_list(path, buf, cap, out)` | List directory entries into `buf`. |

### Convenience wrappers

```c
int xaios_write_file(const char *path, const char *content);
int xaios_read_file(const char *path, char *buffer, u64 buffer_size);
```

### Stat structure

```c
typedef struct xaios_mfs_stat_user {
    u32 type;           // 1 = file, 2 = directory
    u32 block_count;    // blocks allocated
    u64 size;           // file size in bytes
    u64 generation;     // modification generation counter
    u64 content_hash;   // content hash
} xaios_mfs_stat_user_t;
```

## Networking

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_NET_UDP_ECHO` | 21 | `xaios_net_udp_echo(payload, size, echoed)` | Echo a UDP payload (self-test). |
| `XAIOS_SYSCALL_NET_TCP_CONNECT` | 22 | `xaios_net_tcp_connect(trips)` | TCP handshake self-test. |
| `XAIOS_SYSCALL_NET_EXTERNAL_SESSION` | 26 | `xaios_net_external_session(proto, port, ...)` | Open external host session (UDP=17, TCP=6). |
| `XAIOS_SYSCALL_NET_LISTEN` | 29 | `xaios_net_listen(port, sockfd)` | Listen on a TCP port. Returns socket fd. |
| `XAIOS_SYSCALL_NET_ACCEPT` | 30 | `xaios_net_accept(sockfd, newfd)` | Accept an incoming TCP connection. |
| `XAIOS_SYSCALL_NET_RECV` | 31 | `xaios_net_recv(sockfd, buf, size, bytes)` | Receive data from a socket. |
| `XAIOS_SYSCALL_NET_SEND` | 32 | `xaios_net_send(sockfd, buf, size, bytes)` | Send data on a socket. |
| `XAIOS_SYSCALL_NET_CLOSE` | 33 | `xaios_net_close(sockfd)` | Close a socket. |

## SMP and Threads

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_SMP_RUN` | 23 | `xaios_smp_run(workers, iters, ran, cksum)` | Dispatch work to secondary CPU cores. |
| `XAIOS_SYSCALL_THREAD_GROUP_RUN` | 27 | `xaios_thread_group_run(threads, iters, ran, cksum)` | Run a thread group on CPU 0. |

## AI / ML Runtime

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_CPU_AI_DECODE` | 24 | `xaios_cpu_ai_decode(input, in_size, out, out_size, out_len)` | Reserved production decode entrypoint. Returns an unsupported error until a real architecture passes its correctness gates. |
| `XAIOS_SYSCALL_ML_RUN` | 28 | `xaios_ml_run(model_kind, input, in_size, out, out_size, out_len)` | Run deterministic correctness fixtures. Kind 1 is `XAIOS_ML_MODEL_FIXTURE_DECODE`; kinds 2-6 are small math fixtures. These are not model inference. |

## Agent Protocol

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_AGENT_DISPATCH` | 34 | `xaios_agent_dispatch(request, response, payload, payload_size)` | Dispatch an agent protocol request subject to `XAIOS_CAP_AGENT`. |

## Remote Login / Shell

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_REMOTE_LOGIN` | 25 | `xaios_remote_login(user, cmd, out, cap, out_size)` | Execute a shell command as a user. Returns command output. |

### Supported shell commands

`pwd`, `ls` (with `-l`/`-a`), `cd`, `mkdir`, `touch`, `cat`, `cp`, `mv`, `rm`, `rmdir`, `stat`, `write`, `echo`, `grep`, `find`, `head`, `tail`, `sed`, `tar`, `cpio`, `nano`, `htop`, `status`, `sysinfo`, `help`, `exit`.

Pipe (`|`) and output redirection (`>`) are supported for chaining commands.

`nano` is a bounded text editor for mutable-filesystem paths:

```text
nano PATH
nano PATH --number
nano PATH --write TEXT
nano PATH --append TEXT
nano PATH --insert LINE TEXT
nano PATH --replace LINE TEXT
nano PATH --delete LINE
```

Text arguments decode `\n`, `\r`, `\t`, and `\\`. Files must fit within the
3,071-byte editor capacity; oversized input is rejected without truncation.
Edits are saved immediately by the modifying commands.

`htop` emits a sampled kernel CPU, memory, and process snapshot:

```text
htop [--active|--all] [--sample-ms 1..1000]
     [--cpu-start N] [--cpu-count N] [--no-cpus]
```

The default 100 ms interval reports `%CPU` from monotonic runtime deltas, not
dispatch counts. Per-CPU utilization uses each CPU's busy-time delta divided by
the common sample interval. Process utilization uses the process runtime delta;
it follows the conventional per-core scale, where one fully occupied CPU is
`100.0%` and a future process running on multiple CPUs may exceed 100%. `%MEM`
is the process's resident mapped pages divided by detected physical pages.
The system `MEM managed` percentage is allocator pressure over pages the current
NUMA allocator can manage; `physical_pages` separately reports detected
physical capacity, so pages beyond a platform allocator's current tracking
range are not misreported as used.

CPU rows are paged by runtime CPU ordinal. `cpu_shown`, `cpu_total`, and
`next_cpu_start` identify continuation pages, so the command has no 32/64-core
display mask or fixed monitoring-array limit. The output buffer determines the
number of rows in a page; subsequent invocations can retrieve every CPU exposed
by platform discovery. This removes limits from the monitoring and display path;
the current QEMU AArch64 SMP implementation separately admits at most 256 CPUs.
`--active` shows loaded, runnable, running, and waiting processes; `--all` also
includes exited and failed slots.

XAIOS does not yet expose a curses/TTY ABI, so these utilities use the supported
remote command interface rather than a full-screen terminal UI. Output tagged
`source=ssh-bridge` is a host-proxy compatibility view; native XAIOS output is
backed by kernel process and per-CPU accounting.

## Capabilities

Each process is launched with a capability bitmask. Syscalls are rejected if the required capability is not held.

| Capability | Bit | Grants access to |
|------------|----:|------------------|
| `XAIOS_CAP_LOG` | 1 | `log` syscall |
| `XAIOS_CAP_EXIT` | 2 | `exit` syscall |
| `XAIOS_CAP_OSCTL` | 4 | `osctl` syscall |
| `XAIOS_CAP_SERVICE_ROLLBACK` | 8 | `service_rollback` |
| `XAIOS_CAP_UPDATE` | 16 | `service_update` |
| `XAIOS_CAP_FS_READ` | 32 | `fs_open`, `fs_read`, `fs_close`, `fs_stat`, `fs_list`, `read_service_descriptor` |
| `XAIOS_CAP_SERVICE_CONTROL` | 64 | `service_start`, `service_stop`, `service_restart`, `service_status` |
| `XAIOS_CAP_ADMIN` | 128 | Administrative operations |
| `XAIOS_CAP_FS_WRITE` | 256 | `fs_write`, `fs_mkdir`, `fs_delete`, `fs_rename` |
| `XAIOS_CAP_TIME` | 512 | `clock_nanos` |
| `XAIOS_CAP_NET` | 1024 | Network self-test syscalls |
| `XAIOS_CAP_SMP` | 2048 | `smp_run` |
| `XAIOS_CAP_CPU_AI` | 4096 | `cpu_ai_decode` |
| `XAIOS_CAP_REMOTE_LOGIN` | 8192 | `remote_login` |
| `XAIOS_CAP_THREADS` | 16384 | `thread_group_run` |
| `XAIOS_CAP_ML` | 32768 | `ml_run` |
| `XAIOS_CAP_NET_SOCKET` | 65536 | Socket API (`listen`, `accept`, `recv`, `send`, `close`) |
| `XAIOS_CAP_AGENT` | 131072 | `agent_dispatch` |

## Data Types

```c
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
```

Request structures passed by pointer via syscall arguments:

- `xaios_rename_request_t` — old/new path pairs for rename
- `xaios_list_request_t` — buffer/size for directory listing
- `xaios_net_request_t` — network payload buffer
- `xaios_smp_request_t` — SMP worker parameters
- `xaios_cpu_ai_decode_request_t` — AI decode input/output buffers
- `xaios_remote_login_request_t` — user/command/output buffers
- `xaios_net_external_session_request_t` — external session parameters
- `xaios_thread_group_request_t` — thread group parameters
- `xaios_ml_run_request_t` — ML model kind and I/O buffers
- `xaios_socket_request_t` — socket fd, port, buffer, byte counts
- `xaios_agent_dispatch_request_t` — agent protocol request/response buffers
