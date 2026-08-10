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
| `XAIOS_SYSCALL_LOG` | 1 | `xaios_log(text)` | Write a string to the kernel log. Normal interactive boots keep diagnostic log traffic off the display; test profiles and fatal errors expose it on UART. |
| `XAIOS_SYSCALL_EXIT` | 2 | `xaios_exit(code)` | Terminate the current process. |
| `XAIOS_SYSCALL_OSCTL` | 3 | `xaios_osctl(command)` | Send a control-plane command (JSON telemetry query). |
| `XAIOS_SYSCALL_CLOCK_NANOS` | 20 | `xaios_clock_nanos()` | Return monotonic wall-clock nanoseconds since boot. |
| `XAIOS_SYSCALL_RANDOM` | 35 | `xaios_random(buffer, size)` | Fill up to 4096 bytes from the kernel's hardware-backed entropy source. Fails when secure entropy is unavailable. |
| `XAIOS_SYSCALL_FS_SEEK` | 36 | `xaios_fs_seek(fd, offset)` | Set an open mutable-file descriptor to an absolute byte offset. |
| `XAIOS_SYSCALL_CONTROL_QUERY` | 37 | `xaios_control_query(request, request_size, response, response_size, out_size)` | Submit a bounded `xaios.control.v1` operation. Read access requires `XAIOS_CAP_CONTROL_QUERY`; administrator operations additionally require `XAIOS_CAP_CONTROL_ADMIN`. |
| `XAIOS_SYSCALL_REMOTE_LOGIN_SESSION` | 38 | `xaios_remote_login_session(request)` | Execute in (lazily creating) or close a bounded per-connection shell session. Requires `XAIOS_CAP_REMOTE_LOGIN`. |
| `XAIOS_SYSCALL_FS_PREAD` | 39 | `xaios_fs_pread(fd, buffer, size, offset)` | Read at an unsigned 64-bit offset without changing the handle cursor. One call is limited to 65,536 bytes. |
| `XAIOS_SYSCALL_FS_PWRITE` | 40 | `xaios_fs_pwrite(fd, buffer, size, offset)` | Write at an unsigned 64-bit offset without changing the handle cursor. One call is limited to 65,536 bytes. |
| `XAIOS_SYSCALL_FS_FSYNC` | 41 | `xaios_fs_fsync(fd)` | Request backend durability for writes completed through the handle. |
| `XAIOS_SYSCALL_CONSOLE_READ` | 47 | `xaios_console_read(byte)` | Nonblocking read of one serial-console byte. Returns 0 when no byte is ready. Requires `XAIOS_CAP_CONSOLE`. |
| `XAIOS_SYSCALL_CONSOLE_WRITE` | 48 | `xaios_console_write(buffer, size)` | Write at most 4096 bytes directly to the serial console. Requires `XAIOS_CAP_CONSOLE`. |

## Filesystem

Filesystem operations route through the VFS. MutableFS is mounted at `/` for
small mutable state. When the dedicated model volume is present, ModelFS is
mounted at `/models`; active signed packages appear as
`/models/<64-hex-package-id>` and are immutable. Signed staging packages appear
under `/models/.staging` after authenticated `model register` allocates their
extents; they accept only bounded positional writes for their declared logical
size. Generic create, truncate, delete and rename remain unsupported. Lifecycle
mutation uses typed control operations. Paths are absolute and mount routing
uses the longest matching component.

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_FS_OPEN` | 11 | `xaios_fs_open(path, flags)` | Open a file. Flags: `XAIOS_MFS_OPEN_READ` (1), `XAIOS_MFS_OPEN_WRITE` (2), `XAIOS_MFS_OPEN_CREATE` (4), `XAIOS_MFS_OPEN_TRUNCATE` (8). Returns fd >= 0 on success. |
| `XAIOS_SYSCALL_FS_READ` | 12 | `xaios_fs_read(fd, buf, size)` | Read up to `size` bytes from `fd` into `buf`. Returns bytes read. One call is limited to 65,536 bytes. |
| `XAIOS_SYSCALL_FS_WRITE` | 13 | `xaios_fs_write(fd, buf, size)` | Write `size` bytes from `buf` to `fd`. Returns bytes written. One call is limited to 65,536 bytes. |
| `XAIOS_SYSCALL_FS_CLOSE` | 14 | `xaios_fs_close(fd)` | Durably close an open writable handle according to the mounted backend. |
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

`XAIOS_FS_TYPE_FILE` and `XAIOS_FS_TYPE_DIRECTORY` are the public stat type
constants. File sizes and positional offsets are unsigned 64-bit values.
MutableFS v4 supports 128 nodes, 64 open handles, paths up to 255 bytes,
128 KiB per file and 2 MiB of data extents. It atomically renames complete
non-empty directory trees after collision/path validation. The recursive shell
forms `rm -r`, `rm -R`, `rm -rf`, and `rm -fr` remove trees; the filesystem
delete syscall itself still removes one file or empty directory. Valid v2/v3
volumes are migrated to v4 during mount. These remain bounded state-filesystem
limits; the 64-bit API and separate ModelFS are used for large model packages.

## Networking

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_NET_UDP_ECHO` | 21 | `xaios_net_udp_echo(payload, size, echoed)` | Echo a UDP payload (self-test). |
| `XAIOS_SYSCALL_NET_TCP_CONNECT` | 22 | `xaios_net_tcp_connect(trips)` | TCP handshake self-test. |
| `XAIOS_SYSCALL_NET_EXTERNAL_SESSION` | 26 | `xaios_net_external_session(proto, port, ...)` | Open external host session (UDP=17, TCP=6). |
| `XAIOS_SYSCALL_NET_LISTEN` | 29 | `xaios_net_listen(port, sockfd)` / `xaios_net_bind_udp(port, sockfd)` | Create a TCP listener or bound UDP socket according to the request protocol. |
| `XAIOS_SYSCALL_NET_ACCEPT` | 30 | `xaios_net_accept(sockfd, newfd)` / `xaios_net_accept_addr(...)` | Accept an incoming TCP connection, optionally returning its peer address and port. |
| `XAIOS_SYSCALL_NET_RECV` | 31 | `xaios_net_recv(sockfd, buf, size, bytes)` / `xaios_net_recvfrom(...)` | Receive TCP stream data or a queued UDP datagram. One call is limited to 16,384 bytes. |
| `XAIOS_SYSCALL_NET_SEND` | 32 | `xaios_net_send(sockfd, buf, size, bytes)` / `xaios_net_sendto(...)` | Send TCP stream data or a UDP datagram. One call is limited to 16,384 bytes; the kernel snapshots the payload before use. |
| `XAIOS_SYSCALL_NET_CLOSE` | 33 | `xaios_net_close(sockfd)` | Close a socket. |
| `XAIOS_SYSCALL_NET_RESOLVE` | 46 | `xaios_net_resolve(hostname, ipv4)` | Poll or start a bounded asynchronous A-record lookup. Returns `XAIOS_ERR_BUSY` while pending and uses a TTL cache. |
| `XAIOS_SYSCALL_NET_LOCAL_IPV4` | 49 | `xaios_net_local_ipv4()` | Return the configured local IPv4 address in network byte order. |
| `XAIOS_SYSCALL_NET_CONNECT` | 50 | `xaios_net_connect(address, port, sockfd)` | Perform a bounded IPv4 TCP active open and return a connected stream socket. |

## SMP and Threads

| Syscall | Number | Wrapper | Description |
|---------|-------:|---------|-------------|
| `XAIOS_SYSCALL_SMP_RUN` | 23 | `xaios_smp_run(workers, iters, ran, cksum)` | Dispatch work to secondary CPU cores. |
| `XAIOS_SYSCALL_THREAD_GROUP_RUN` | 27 | `xaios_thread_group_run(threads, iters, ran, cksum)` | Run a bounded worker group concurrently across online CPUs. |
| `XAIOS_SYSCALL_THREAD_CREATE` | 42 | `xaios_thread_create(entry, argument, stack, stack_size, preferred_cpu, thread_id)` | Create an EL0 thread using caller-owned stack memory and an optional runtime CPU ordinal. |
| `XAIOS_SYSCALL_THREAD_JOIN` | 43 | `xaios_thread_join(thread_id, timeout_ns, result)` | Wait for a thread and retrieve its 64-bit result, with a bounded timeout. |
| `XAIOS_SYSCALL_THREAD_CANCEL` | 44 | `xaios_thread_cancel(thread_id)` | Request cancellation of a live thread. |
| `XAIOS_SYSCALL_THREAD_EXIT` | 45 | return trampoline | Exit the current thread and publish its result through the userspace return trampoline. |

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
| `XAIOS_SYSCALL_REMOTE_LOGIN_SESSION` | 38 | `xaios_remote_login_session_open/execute/close(...)` | Manage a session with an independent current directory and parser state. At most 16 kernel session contexts exist. |

### Supported shell commands

`pwd`, `ls` (with `-l`/`-a`), `cd`, `mkdir`, `touch`, `cat`, `less`,
`cp`, `mv`, `rm`, `rmdir`, `stat`, `write`, `echo`, `grep`, `find`, `head`,
`tail`, `sed`, `tar`, `zip`, `unzip`, fixture-only `cpio`, outbound `ssh` and
`scp`, `nano`, `htop`, `pong`, `xaiosctl`, `status`, `hello`, `sysinfo`, `systest`,
`smptest`, `nettest`, `lstm-xor`, `mltest`, `posix-shell`, `agenttest`, `help`,
and `exit`. Exact options and storage/archive limits are specified in
[`UNIX-COMPATIBILITY.md`](./UNIX-COMPATIBILITY.md).

`xaiosctl` is the structured administrative entrypoint. The SSH
daemon recognizes only the exact `xaiosctl` command prefix and calls the shared
client library. It also recognizes the fixed diagnostic names listed above,
loads the matching initramfs ELF in a separate transient address space with a
command-specific capability mask, captures its application log output, and
reclaims its pages and process slot after exit. Diagnostic commands accept no
arguments; arbitrary paths and executable launch are rejected. Authenticated
Ed25519 keys map to observer, operator or administrator roles, and the kernel
rechecks capability and requested role for every control operation. Legacy
`status` remains a compatibility command that directs callers to measured
`xaiosctl status` output. `sysinfo` invokes the legacy diagnostic ELF on demand;
operators should use `xaiosctl hardware` for structured discovered state.

An SSH `shell` request requires a PTY and starts a stateful line-edited shell.
Each connection has an independent cwd and `admin@xaios:<cwd>$` prompt;
Backspace, `Ctrl-C`, `clear`, `exit`, `logout`, and `quit` have interactive
semantics. Unknown commands print `xaios: NAME: command not found` and return a
nonzero SSH exit status. Exec requests remain one-command operations.

Remote shell and SFTP access deny the private host key, password database,
legacy authorized-key source and `/state/control` subtree. This path guard
applies even to administrators. See [`XAIOSCTL.md`](./XAIOSCTL.md) for the
command and role matrix.

The service-manager `osctl status` action is also a legacy test/control marker.
It reports measured process, service-transition and AI-cell counters without
claiming a host platform; operators should use `xaiosctl status`.

Pipe (`|`) and output redirection (`>`) are supported for chaining commands.

On a PTY, `less [-N] FILE` is an alternate-screen pager with line and page
movement, start/end navigation, forward search, resize handling, and terminal
restoration. Non-PTY use emits bounded file content for automation. Outbound
`ssh`/`scp` are implemented in the persistent SSH userspace service and use the
`XAIOS_SYSCALL_NET_CONNECT` active-open boundary; they are not kernel shell
implementations.

`nano` is a bounded text editor for mutable-filesystem paths. On an SSH PTY or
the authenticated local console, `nano PATH` opens an alternate-screen editor
with terminal-size rendering, arrow movement, scrolling, Backspace/Delete,
Enter, `Ctrl-A`, `Ctrl-E`, `Ctrl-O` save, and `Ctrl-X` exit with a dirty-buffer
confirmation. Protected credential and control paths are denied. For scripts
and non-PTY exec requests the immediate command forms remain available:

```text
nano PATH
nano PATH --number
nano PATH --write TEXT
nano PATH --append TEXT
nano PATH --insert LINE TEXT
nano PATH --replace LINE TEXT
nano PATH --delete LINE
```

Text arguments decode `\n`, `\r`, `\t`, and `\\`. Interactive editing is
limited to 32 KiB. Immediate command-mode edits use a smaller 3,071-byte work
buffer. Oversized input is rejected without truncation, and modifying
command-mode operations save immediately.

`htop` emits a sampled kernel CPU, memory, and process snapshot:

```text
htop [--active|--all] [--sample-ms 1..1000]
     [--cpu-start N] [--cpu-count N] [--no-cpus]
     [--color|--plain] [--columns 40..240] [--rows 12..100]
     [--sort cpu|mem|time|pid|state|syscalls|command|parent]
     [--reverse] [--tree] [--filter TEXT] [--process-start N] [--selected N]
```

Bare `htop` defaults to all process slots, all detected CPUs, and a 250 ms
sample interval. `--active` limits the process table to active slots, while
`--all`, `--sample-ms`, and the CPU-range options remain available for explicit
automation. The sample reports `%CPU` from monotonic runtime deltas, not
dispatch counts. Per-CPU utilization uses each CPU's busy-time delta divided by
the common sample interval. Process utilization uses the process runtime delta;
it follows the conventional per-core scale, where one fully occupied CPU is
`100.0%` and a future process running on multiple CPUs may exceed 100%. `%MEM`
is the process's resident mapped pages divided by detected physical pages.
The sampler waits through its complete interval on the architectural timer and
excludes that idle interval from the calling process's runtime, so opening
`htop` does not manufacture a 100% housekeeping-core reading.
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
The ANSI header follows Debian htop's column-major scaling model: up to eight
CPUs remain in one left-hand column with Tasks, Load average and Uptime in the
right-hand column; 9-16 CPUs use two columns, 17-32 use four, 33-64 use eight,
and larger visible pages may use sixteen when the terminal is wide enough.
Memory and swap follow the left CPU group. When more than one CPU column is
needed, the three status rows move below the CPU grid beside Memory and Swap.
Narrow terminals reduce the number of columns rather than allowing meters to
overlap. Unlike Debian htop's stock default above 128 CPUs, XAIOS retains
ordinal paging so every runtime CPU remains inspectable.
`--active` shows loaded, runnable, running, and waiting processes; `--all` also
includes exited and failed slots.

The native SSH daemon validates `pty-req` and `window-change` dimensions. An
exact `htop` command on a PTY channel automatically selects the guest-generated
live ANSI monitor, uses the reported terminal size, and refreshes every 250 ms
by default. It includes colored CPU,
managed-memory and zero-capacity swap meters, task and uptime state,
scheduler-backed 1/5/15-minute fixed-point load averages, process
selection, process/CPU paging, sorting, filtering and an in-terminal help view.
CPU, `Mem`, and `Swp` labels use a shared width derived from the largest runtime
CPU ID, keeping every opening meter bracket in one column on many-core systems.
Memory and swap remain within the left meter column beneath the first CPU group;
their capacity values are right-aligned there when terminal width permits. The
footer uses distinct htop-style key and command color segments.
Resize requests trigger a new bounded frame. Each PTY channel owns independent
view state and refreshes only after its previous output has drained. Interactive
sessions use the terminal alternate-screen buffer and restore the original
screen on exit, so live redraws do not accumulate in normal scrollback.

Interactive keys include arrows or `j`/`k`, Page Up/Page Down, `P`/`M`/`T`/`N`/
`S`/`C` sorting, `F6` sort cycling, `I` reverse order, `F3` or `/` filtering,
`F4` filter clearing, `F5` or `t` process-tree view, `a` active/all tasks,
`1` CPU-meter visibility, `[`/`]` CPU pages, `+`/`-` refresh speed, `r` refresh,
`F1` help, and `F10`, `q` or Control-C to quit. Refresh delay is bounded to
250..5000 ms; each frame uses a short 10 ms accounting sample. Independently,
all periodic and input-triggered screen rendering is capped internally at 60
frames per second using monotonic time. Changes arriving inside that interval
are coalesced into the next permitted frame.

`--plain` explicitly disables ANSI and interaction. Non-PTY invocations remain
one-shot plain snapshots for scripts. Generic process kill and priority changes
are intentionally absent because XAIOS does not yet expose a safe general
process-control ABI. Output tagged `source=ssh-bridge` is a host-proxy
compatibility view; native SSH output is generated inside XAIOS and is backed by
kernel process and per-CPU accounting.

### Pong

`pong` starts a native alternate-screen terminal game on an authenticated local
console or SSH PTY. It requires an interactive terminal; non-PTY execution
returns an explicit error. Each local or SSH session owns its own match state.

| Key | Action |
|---|---|
| `W` / `S` | Move the human paddle up or down. |
| `P` or Space | Pause or resume. |
| `R` | Reset both counters and ball speed. |
| `Q` or Control-C | Quit and restore the previous screen and prompt. |

The right paddle uses a bounded predictive controller with reaction delay,
movement-rate limits and deterministic aiming variation. Play never stops at a
score threshold. Human and computer win counters saturate rather than wrapping.
After each human point, current ball speed is multiplied by 1.01; after each
computer point it is multiplied by 0.99. The effective scale is clamped to
40%-300% so an unlimited match cannot underflow into a stationary ball or
overflow its fixed-point arithmetic. The initial 100% horizontal speed crosses
the current court in approximately six seconds. Physics use monotonic fixed-
point time and do not require floating point. SSH resize events rescale the
court and live state. Rendering is bounded to 40x12 through 240x100 terminals
and refreshes at no more than 30 frames per second after prior channel output
has drained.

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
| `XAIOS_CAP_RANDOM` | 262144 | `random` |
| `XAIOS_CAP_CONTROL_QUERY` | 524288 | Bounded read operations in `control_query` |
| `XAIOS_CAP_CONTROL_ADMIN` | 1048576 | Permit administrator control operations when the request's authenticated role also authorizes them |
| `XAIOS_CAP_STORAGE_READ` | 2097152 | Storage device, partition and filesystem inspection plus read-only checks |
| `XAIOS_CAP_STORAGE_MOUNT` | 4194304 | ModelFS mount and unmount |
| `XAIOS_CAP_STORAGE_FORMAT` | 8388608 | ModelFS format planning and confirmed format |
| `XAIOS_CAP_STORAGE_PARTITION` | 16777216 | GPT planning, mutation and repair |
| `XAIOS_CAP_STORAGE_REPAIR` | 33554432 | ModelFS repair and online scrub lifecycle |
| `XAIOS_CAP_STORAGE_RESIZE` | 67108864 | Grow-only ModelFS resize |
| `XAIOS_CAP_STORAGE_TRIM` | 134217728 | Free-space trim/discard lifecycle |
| `XAIOS_CAP_MODEL_STAGE` | 268435456 | ModelFS registration, staging cleanup and package verification |
| `XAIOS_CAP_MODEL_ACTIVATE` | 536870912 | Verified package activation |
| `XAIOS_CAP_CONSOLE` | 1073741824 | Direct serial-console input/output; reserved for the persistent console owner |

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
- `xaios_remote_login_session_request_t` — open/execute/close operation,
  session ID and bounded user/command/output buffers
- `xaios_net_external_session_request_t` — external session parameters
- `xaios_thread_group_request_t` — thread group parameters
- `xaios_ml_run_request_t` — ML model kind and I/O buffers
- `xaios_socket_request_t` — socket fd, port, buffer, byte counts, address
  pointers, and protocol (`XAIOS_NET_PROTOCOL_TCP` or
  `XAIOS_NET_PROTOCOL_UDP`)
- `xaios_agent_dispatch_request_t` — agent protocol request/response buffers
- `xaios_control_query_request_t` — bounded control request/response buffers

## Structured Control Protocol

`xaios.control.v1` uses a 48-byte request header and 40-byte response header,
with magic, version, operation, flags, request ID, role, node, timeout, status,
payload type and 64-bit payload length fields. Requests are limited to 512
bytes and responses to 8,192 bytes. Operations 1-49 cover measured queries,
configuration/authentication/audit, ModelFS registration/verification/
activation/cleanup, block/GPT/filesystem lifecycle, persisted scrub and safe
trim/discard administration.

The kernel validates request framing and user buffers, derives the maximum role
from the caller's capability mask, and rejects privilege elevation, role
mismatch or unknown nodes. Mutations also require a nonzero operation ID and
are persisted with payload-redacted audit metadata. See
[`CONTROL-PROTOCOL.md`](./CONTROL-PROTOCOL.md) for the frozen ABI and
[`XAIOSCTL.md`](./XAIOSCTL.md) for command/output semantics.
