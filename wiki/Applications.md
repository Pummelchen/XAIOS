# Applications

This page inventories executable images and dedicated interactive applications
shipped with XAIOS. Standalone programs are started through the kernel loader
with explicit capabilities; arbitrary host binaries and FreeBSD/Linux binaries
do not execute in XAIOS.

Shell built-in commands such as `ls`, `ssh`, and `scp` are documented separately
in [[Commands|Commands]].

## Boot and service applications

| Path | Purpose | Normal startup |
|---|---|---|
| `/init` | First userspace process. Establishes the initial service lifecycle and returns status to the kernel. | Started once during boot. |
| `/bin/service-manager` | Exercises and owns the bounded service-manager protocol used for managed workers. | Started during boot. |
| `/bin/xaios-worker` | Joinable worker process used for scheduler, CPU-assignment, and service-lifecycle work. | Started by the service manager; count follows the boot profile. |
| `/bin/sshd` | Persistent SSH/SFTP server, authenticated PTY transport, outbound SSH/SCP client host, and userspace adapter for the kernel command dispatcher. | Started only after networking and the configured external IPv4/DNS readiness check succeeds. |

## Administrative applications

| Path | Purpose |
|---|---|
| `/bin/xaiosctl` | Administrative client for the versioned `xaios.control.v1` protocol. It exposes status, health, hardware, metrics, logs, configuration, identity, audit, storage, and ModelFS rendering/authorization paths. The interactive shell exposes a bounded compatibility command family. |
| `/bin/xapt` | Signed application and system updater. It refreshes a monotonic architecture-specific catalog, installs or upgrades individual applications without rebooting, and streams an OS image to the inactive A/B slot. |
| `/bin/xaios-shell` | Scripted acceptance application for built-in remote-login commands and archives; it is not the persistent interactive shell process. Standalone applications are covered by the SSH gates. |

## Repository applications

Applications in the signed repository are not built into the boot image. `xapt`
downloads them into a staging area, verifies their manifest and payload, then
atomically activates them in `/apps`.

The current production catalog does not advertise optional applications. New
applications will appear in `xapt list` only after a real application binary
and its signed package metadata have been published for the running
architecture. Package-manager tests use an explicitly test-only fixture that
is never part of the production application catalog.

## Interactive terminal applications

These are applications rather than shell built-ins. Each is shipped as a
dedicated ELF image. Shared terminal engines are owned under
`userspace/apps/terminal`; the local-console and SSH PTY hosts link those app
modules only as transport adapters. No editor, monitor, or game logic is built
into the kernel.

| Path | Interactive transport | Purpose |
|---|---|---|
| `/bin/nano` | Dedicated ELF plus shared app-owned PTY module | Full-screen editor with cursor movement, insertion/deletion, save, search, and exit. The editing buffer is limited to 32 KiB. |
| `/bin/htop` | Dedicated ELF using the typed runtime-snapshot control operation | Full-screen sampled process monitor with color, alternate-screen in-place refresh, runtime-sized CPU meters, sorting, filtering, tree view, keyboard navigation, and a 60 FPS rendering cap. |
| `/bin/pong` | Dedicated ELF plus shared app-owned PTY module | 60 FPS terminal Pong. `W`/`S` control the left paddle, the computer controls the right, and session win/loss counts adjust ball speed by one percent per round. |

## Diagnostic applications

These executables are not started on a normal boot. An authenticated exact-name
remote command can launch an allowlisted diagnostic as a transient process;
the kernel reports its exit status and reclaims it. The dedicated
`XAIOS_BOOT_TEST_APPS=1` image profile may run them during deterministic QEMU
acceptance.

| Path | Purpose |
|---|---|
| `/bin/hello` | Minimal userspace toolchain, ELF loader, logging, and exit integration check. |
| `/bin/helloworldc99` | Hosted ISO C99 demonstration built against the XAIOS libc. It prints `Hello, World!` through `stdio` and is available on demand as `helloworldc99`. |
| `/bin/sysinfo` | Legacy compatibility diagnostic that directs administrators to `xaiosctl status` and `xaiosctl hardware`. |
| `/bin/systest` | Syscall, descriptor-width validation, and MutableFS create/read/stat/list/rename/delete suite. |
| `/bin/smptest` | SMP scheduler visibility, worker groups, and EL0 thread create/join/validation test. |
| `/bin/nettest` | App-callable UDP/TCP, external session, and asynchronous DNS/cache telemetry test. |
| `/bin/lstm-xor` | Deterministic CPU-only LSTM/XOR fixture. It also verifies that production model decode fails closed; it is not real-model inference. |
| `/bin/sshtest` | Scripted SSH-compatible command, filesystem, archive, process, and error-surface acceptance suite. |
| `/bin/mltest` | Deterministic CPU ML dispatcher test for XOR, sum, parity, and fixed-point matrix multiplication fixtures. |
| `/bin/posix-shell` | Scripted FreeBSD/POSIX-like shell-subset compatibility suite for redirects, pipelines, filters, and filesystem operations. |
| `/bin/agenttest` | Bounded agent protocol dispatch test for ping, source-index, Git status, build, denial, and validation cases. |

Two applications exist only in the explicit failure-fixture image and are not
shipped in the normal image:

| Path | Purpose |
|---|---|
| `/bin/app-fail` | Returns status 42 to verify ordinary application-failure reporting and reaping. |
| `/bin/app-crash` | Deliberately reads an unmapped user address to verify user-mode fault containment, status 128 reporting, reaping, and continued SSH command service. |

## Execution boundaries

- Diagnostic names are exact allowlist entries; paths, arguments, and arbitrary
  executable launch are rejected by the remote application dispatcher.
- Built-in shell parsing and most file/archive command handlers currently run in
  the kernel remote-login subsystem. Their audited migration candidates are
  listed in [[Commands|Commands]].
- SSH transport and outbound SSH/SCP protocol code run in `/bin/sshd`, not in
  the kernel. A fault there cannot corrupt kernel state, but it can stop that
  SSH service until lifecycle recovery restarts it.
- Standard output from a transient hosted-libc application is bounded and
  returned to the invoking SSH session as well as written to the serial console.
- Interactive terminal applications have dedicated `/bin/*` ELF images. SSH
  and local-console PTY adapters consume app-owned modules for terminal
  transport; non-interactive command execution is dispatched through the ELF
  entrypoint. The kernel exposes only generic process, filesystem, console, and
  paged runtime-snapshot primitives.
- A nonzero transient application reports its exit status and is reaped. A
  synchronous user-mode fault on AArch64 or x86-64 is converted to exit status 128,
  returns through the normal transient-process boundary, and leaves
  the kernel, SSH service, and other applications running. Kernel-mode faults
  remain fatal by design.
- Normal boot does not pre-run `hello`, `sysinfo`, `lstm-xor`, or the other
  diagnostics.
- Installed repository applications are loaded on demand with the capabilities
  declared in their signed manifest. They are never started merely by install.

For command syntax see [[Commands|Commands]], for package administration see
[[xapt Package Updates|Xapt-Package-Updates]], and for lifecycle verification
see [[Testing XAIOS|Testing-XAIOS]].
