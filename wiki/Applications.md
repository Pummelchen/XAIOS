# Applications

This page inventories executable images and dedicated interactive applications
shipped with XAIOS. Standalone programs are started through the kernel loader
with explicit capabilities; arbitrary host binaries and FreeBSD/Linux binaries
do not execute in XAIOS.

Session syntax such as `cd` and the invocation syntax for dedicated applications
are documented separately in [[Commands|Commands]].

## Boot and service applications

`/bin` is the boot image mounted read-only into the VFS, so `ls /bin`
lists the shipped executables and `ls -l` reports their sizes. Writes,
renames, and deletions under it are rejected; mutable data belongs under
`/state`, `/apps`, and `/tmp`.

| Path | Purpose | Normal startup |
|---|---|---|
| `/init` | First userspace process. Establishes the initial service lifecycle and returns status to the kernel. | Started once during boot. |
| `/bin/service-manager` | Exercises and owns the bounded service-manager protocol used for managed workers. | Started during boot. |
| `/bin/xaios-worker` | Joinable worker process used for scheduler, CPU-assignment, and service-lifecycle work. | Started by the service manager; count follows the boot profile. |
| `/bin/xaios-setup` | First-boot setup. Offers running from the boot medium or installing onto a disk, then takes the account password, an optional six digit console PIN, and the machine's name. It cannot write `/etc` -- no userspace process can -- so it leaves what it collected under `/state` and the kernel installs it. | Started before `sshd`, and only when the machine has no account, so an image that packages credentials never reaches it. |
| `/bin/sshd` | Persistent SSH/SFTP server, authenticated PTY transport, forwarding endpoint, and userspace adapter for the kernel command dispatcher. Its loop blocks in the kernel (`xaios_wait_events`) until there is console input, a packet or connection on one of its sockets, or output from a child, so an idle server is idle: a few percent of one core under emulation, where it used to hold a whole core. | Started only after networking and the bounded external IPv4 TCP readiness check succeeds. |

## Administrative applications

| Path | Purpose |
|---|---|
| `/bin/xaiosctl` | Administrative client for the versioned `xaios.control.v1` protocol. It exposes status, health, hardware, metrics, logs, configuration, identity, audit, storage, and signed xaiFS lifecycle, scrub, trim, and offline trusted-replica repair paths. The interactive shell exposes a bounded compatibility command family. |
| `/bin/xapt` | Signed application and system updater. It refreshes a monotonic architecture-specific catalog, installs or upgrades individual applications without rebooting, and streams an OS image to the inactive A/B slot. |
| `/bin/xaios-shell` | Scripted acceptance application for built-in remote-login commands and archives; it is not the persistent interactive shell process. Standalone applications are covered by the SSH gates. |

## Network client applications

| Path | Purpose |
|---|---|
| `/bin/ssh` | Dedicated outbound SSH/SCP process. It supports password, Ed25519 identity-file and forwarded-agent authentication, encrypted OpenSSH keys, IPv4/IPv6, DNS A/AAAA, PTY/exec sessions, recursive SFTP-backed copies, and one password-authenticated `-J user@host[:port]` hop with independent target authentication. The parent SSH service exchanges terminal data through bounded asynchronous child-channel IPC. |

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
| `/bin/xtop` | Dedicated ELF using the typed runtime-snapshot control operation | Full-screen sampled process monitor in mactop's layout, run as one child process of the session that streams frames over a child channel -- keys go the other way -- sending only the cells that changed, positioned with cursor moves, so an unchanged screen costs nothing and a change is on the screen within sixteen milliseconds -- the [screen framework](Screen-Framework.md), which every full-screen program gets through the session and into whose cells `xtop` draws directly; between samples it waits in the kernel (`xaios_wait_events`) for a key or the next sample rather than polling, so the monitor itself costs a few percent of one core under emulation and less on hardware; `-`/`+` set the sampling cadence from 5 s down to 16 ms; the console draws only the cells that changed too, with three layouts (`L`): gauges and cores, platform and AI runtime, and history charts; the Platform panel says what each architecture has (NEON/SVE, AVX2/AVX-512/VNNI/AMX, or the RISC-V vector extension and Sstc), the AI runtime panel stands where mactop shows the neural engine, and Network & Disk shows rates from the kernel's counters. In the layout: a blue field, green-ruled panels with their names set into the rules, tall solid CPU and memory gauges with the figure centred, per-core meters beside the system figures, a green header bar over the process list, and the keys and refresh interval in the bottom rule; alternate-screen in-place refresh, sorting, filtering, tree view, keyboard navigation, and a 60 FPS rendering cap. An expected non-zero exit -- the hosted C99 probes exit 23 and abort on purpose -- is recorded as an exit, not a failure, so a fresh machine reports none. It draws with UTF-8 box and block glyphs and 256-colour escapes, and renders the same on the local framebuffer console as in an SSH client: the console's terminal has a full printable-ASCII font plus the box, block and dash glyphs the monitor uses, parses extended colour sequences, and reports its real cell geometry so the monitor lays itself out against the whole screen. `make qemu-console-xtop-gate` reads the framebuffer back out of QEMU as pixels, decodes them through the kernel's own font tables, and compares the frame with one taken over SSH at the same size. Named `xtop` rather than `htop`: it is XAIOS's own monitor reading XAIOS's own runtime snapshot, and a Unix name would have implied a compatibility this does not claim. |
| `/bin/pong` | Dedicated ELF plus shared app-owned PTY module | 60 FPS terminal Pong. `W`/`S` control the left paddle, the computer controls the right, and session win/loss counts adjust ball speed by one percent per round. |

## Utility applications

The following commands are independent ELF applications. The shell passes a
normalized session working directory and bounded raw argument string to each
process. A parser fault, malformed archive, or ordinary nonzero exit is
contained by the transient-process boundary rather than executing in the
kernel.

| Path | Supported core behavior |
|---|---|
| `/bin/ls` | `ls [-a] [-l] [PATH]`; list files or directories. `l`, `la`, and `ll` dispatch to this binary. |
| `/bin/mkdir` | `mkdir [-p] DIR...`; create directories and optional parents. |
| `/bin/touch` | `touch FILE...`; create or truncate regular files. |
| `/bin/cp` | `cp [-R|-r] SOURCE... DEST`; copy files or bounded directory trees. |
| `/bin/mv` | `mv SOURCE DEST`; rename or move within xaibootFS. |
| `/bin/rm` | `rm [-r] [-f] PATH...`; remove files or trees. |
| `/bin/rmdir` | `rmdir DIR...`; remove empty directories. |
| `/bin/stat` | `stat PATH`; show type, size, blocks, generation, and content hash. |
| `/bin/cat` | `cat [-n] FILE...`; concatenate files with optional line numbers. |
| `/bin/head` | `head [-n N] FILE`; print the first lines, defaulting to 10. |
| `/bin/tail` | `tail [-n N] FILE`; print the last lines, defaulting to 10. |
| `/bin/less` | `less [-N] FILE`; non-PTY rendering through the ELF and app-owned alternate-screen paging in an SSH PTY. |
| `/bin/grep` | `grep [-incvFHh] PATTERN FILE...`; bounded basic or fixed-string search. |
| `/bin/find` | `find [PATH] [-name PATTERN]`; recursively enumerate matching paths. |
| `/bin/sed` | `sed 's/OLD/NEW/[g]' FILE`; bounded literal replacement and write-back. |
| `/bin/write` | `write FILE TEXT...`; replace a file with the supplied text. |
| `/bin/tar` | Create POSIX ustar archives and list/extract ustar, PAX-path, GNU-long-name, or single-member gzip input. |
| `/bin/cpio` | Create, list, and extract portable `newc` archives. |
| `/bin/zip` | Create standards-readable stored ZIP archives. |
| `/bin/unzip` | List or extract stored and Deflate ZIP entries. |
| `/bin/ps` | Render the typed kernel process snapshot. |
| `/bin/df` | Render typed xaibootFS and xaiFS capacity records. |
| `/bin/du` | Report bounded recursive block usage with summary and human-readable options. |

Archive extraction rejects absolute and traversal paths, corrupt checksums,
encrypted ZIP, ZIP64, links, device nodes, and unsupported required features.
xaibootFS limits regular files to 256 KiB, so these utilities are intended for
configuration and small exchange archives rather than model payloads.

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
| `/bin/systest` | Syscall, descriptor-width validation, and xaibootFS create/read/stat/list/rename/delete suite. |
| `/bin/smptest` | SMP scheduler visibility, worker groups, and EL0 thread create/join/validation test. |
| `/bin/perfbench` | Measures what XAIOS costs to use: syscall latency at one, four and eight threads, socket bind/close through the serialised network path, and thread create/join. Reports nanoseconds per operation and asserts nothing. Built only when `XAIOS_STRESS_TEST=1`. |
| `/bin/smpstress` | Sustained multi-core load. Pins threads across the cores until a deadline, then checks a contended counter against tallies each thread kept privately and each thread's word against the neighbours sharing its cache line. Built only when `XAIOS_STRESS_TEST=1`, because it soaks rather than returns. |
| `/bin/nettest` | App-callable UDP/TCP, external session, and asynchronous DNS/cache telemetry test. |
| `/bin/lstm-xor` | Deterministic CPU-only LSTM/XOR fixture. It also verifies that production model decode fails closed; it is not real-model inference. |
| `/bin/sshtest` | Scripted SSH-compatible command, filesystem, archive, process, and error-surface acceptance suite. |
| `/bin/mltest` | Deterministic CPU ML dispatcher test for XOR, sum, parity, and fixed-point matrix multiplication fixtures. |
| `/bin/posix-shell` | Scripted FreeBSD/POSIX-like shell-subset compatibility suite for redirects, pipelines, filters, and filesystem operations. |
| `/bin/agenttest` | Bounded agent protocol dispatch test for ping, source-index, Git status, build, denial, and validation cases. |
| `/bin/clustertest` | Carries a sealed cluster frame to a peer over TCP and opens the reply, then refuses that frame a second time. Says so and exits cleanly when no peer is reachable, which is the ordinary case: most boots are not part of a cluster. |

Two applications exist only in the explicit failure-fixture image and are not
shipped in the normal image:

| Path | Purpose |
|---|---|
| `/bin/app-fail` | Returns status 42 to verify ordinary application-failure reporting and reaping. |
| `/bin/app-crash` | Deliberately reads an unmapped user address to verify user-mode fault containment, status 128 reporting, reaping, and continued SSH command service. |

## Execution boundaries

- Diagnostic names are exact allowlist entries; paths, arguments, and arbitrary
  executable launch are rejected by the remote application dispatcher.
- Shell state, command composition, authorization, and privileged mechanisms
  remain kernel-owned. File, text, archive, and observability parsing runs in
  the independent utility applications listed above.
- Inbound SSH/SFTP transport runs in `/bin/sshd`; outbound SSH/SCP protocol code
  runs in transient `/bin/ssh`. Neither runs in the kernel, and an outbound
  client fault is contained without terminating the inbound service.
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
