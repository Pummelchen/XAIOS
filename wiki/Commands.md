# Commands

XAIOS provides a bounded FreeBSD-style command surface for authenticated local
and SSH PTY sessions. This page lists command syntax, not executable images.
Most commands are currently kernel command handlers, while outbound `ssh` and
`scp` run in the userspace SSH service. Dedicated binaries are applications and
are listed only in [[Applications|Applications]].

## Current ownership

| Current owner | Commands or responsibility | Fault boundary |
|---|---|---|
| Kernel session layer | `cd`, `pwd`, `help`, `exit`, `quit`, `logout`, aliases, redirection, and pipelines | Maintains per-session state and command composition. |
| Kernel file/archive handlers | `ls`, `mkdir`, `touch`, `cp`, `mv`, `rm`, `rmdir`, `stat`, `cat`, `head`, `tail`, `less`, `grep`, `find`, `sed`, `write`, `tar`, `cpio`, `zip`, `unzip`, `df`, `du`, and `ps` | Validated operations, but parser/formatting defects are still in the kernel fault domain. |
| `/bin/sshd` userspace service | Outbound `ssh` and `scp` protocol clients and inbound SSH/SFTP transport | A fault cannot panic the kernel, but can interrupt the SSH service. |
| Kernel operations layer | `status`, power, service, process, network, clock, recovery, update, configuration, and support commands | Capability checks and privileged mechanisms remain authoritative in the kernel. |

## Migration assessment

The target is to move non-privileged parsing, archive handling, formatting, and
protocol-client code to independent ELF applications without adding a syscall.
The existing 50-syscall ABI already supplies filesystem, console, process
snapshot, clock, networking, and control operations. The shell can continue to
launch allowlisted binaries through its current kernel-mediated process loader.

| Priority | Candidate | Planned boundary |
|---|---|---|
| 1 | `ssh`, `scp` | Split the outbound clients from `/bin/sshd` into `/bin/ssh` and `/bin/scp`; keep only inbound SSH/SFTP service code in `sshd`. This prevents an outbound-client fault from taking down active inbound sessions. |
| 2 | File and text utilities | Move `ls`, `mkdir`, `touch`, `cp`, `mv`, `rm`, `rmdir`, `stat`, `cat`, `head`, `tail`, `less`, `grep`, `find`, `sed`, and `write` into independently loaded applications using existing filesystem and console syscalls. Pass the normalized session CWD as launch metadata and preserve bounded pipelines/redirection in the shell. |
| 3 | Archive utilities | Move `tar`, `cpio`, `zip`, and `unzip` after shared userspace path-validation and streaming archive libraries are available. Malformed external archives then remain outside the kernel fault domain. |
| 4 | Observability utilities | Move `ps`, `df`, and `du` to typed snapshot/filesystem APIs. Route administrative display commands through `/bin/xaiosctl` while keeping authorization and state changes in kernel mechanisms. |
| Keep resident | Session syntax | Keep `cd`, `pwd`, `help`, `exit`, `quit`, `logout`, aliases, `echo`, pipelines, and redirection in the session layer because they mutate or compose shell state rather than represent independent programs. |
| Keep privileged | Kernel mechanisms | Keep process termination, service lifecycle, power, network configuration, storage, recovery, and update authorization in capability-checked kernel APIs; only their CLI parsing and rendering should move out. |

When a command becomes a dedicated binary, it moves to
[[Applications|Applications]] and is removed from this catalog. The migration
must preserve command behavior and add a crash-isolation test before the old
kernel handler is deleted.

## Navigation and files

| Command | Supported core behavior |
|---|---|
| `pwd` | Print the session working directory. |
| `cd [DIR]` | Change directory; no argument selects `/`; relative, absolute, `.` and `..` paths are normalized. |
| `ls [-a] [-l] [PATH]` | List a directory; options may be combined. `l`, `la`, and `ll` are aliases. |
| `mkdir [-p] DIR...` | Create one or more directories; `-p` creates missing parents. |
| `touch FILE` | Create or truncate a regular file. |
| `cp [-R|-r] SOURCE... DEST` | Copy one or more files; recursively copy directories. |
| `mv SOURCE DEST` | Rename or move within MutableFS. |
| `rm [-r] [-f] PATH...` | Delete files; recursive mode removes trees. |
| `rmdir DIR...` | Remove empty directories. |
| `stat PATH` | Show type, size, block count, generation, and content hash. |

## Text and search

| Command | Supported core behavior |
|---|---|
| `cat [-n] FILE...` | Concatenate files, optionally numbering lines. |
| `head [-n N] FILE` | Print the first N lines; default 10. |
| `tail [-n N] FILE` | Print the last N lines; default 10. |
| `less [-N] FILE` | Alternate-screen pager with scrolling, search, and line numbers for regular files up to 128 KiB. |
| `grep [-incvFHh] PATTERN FILE...` | Bounded basic search with anchors, `.`, `*`, escaping, inversion, case, numbering, count, fixed-string, and filename controls. |
| `find [PATH] [-name PATTERN]` | Recursively list entries; `-name` supports the shell's bounded filename pattern matcher. |
| `sed 's/OLD/NEW/[g]' FILE` | Replace the first or all matching literal spans per line, write the result back, and print it. This is intentionally smaller than full `sed`. |
| `echo [TEXT...]` | Print text. `>` and `>>` redirect output to a file. |
| `write FILE TEXT...` | Write text directly to a file. |
| `COMMAND | COMMAND` | Connect supported producer/filter commands through the bounded in-memory pipeline. |

## Archives and transfer formats

| Command | Supported core behavior |
|---|---|
| `tar -cf ARCHIVE PATH...` | Create a POSIX ustar archive; recursive directory content is included. |
| `tar -tf ARCHIVE` | List an archive. |
| `tar -xf ARCHIVE [-C DIR]` | Extract ustar/PAX paths and GNU long-name inputs; one gzip member is accepted for extraction. |
| `cpio -o ... -O ARCHIVE` | Create the bounded XAIOS cpio exchange form. |
| `cpio -it -I ARCHIVE` | List entries. |
| `cpio -i -I ARCHIVE [-D DIR]` | Extract entries. |
| `zip [-r] ARCHIVE PATH...` | Create a standards-readable stored ZIP archive. |
| `unzip [-l] ARCHIVE [-d DIR]` | List or extract stored/Deflate ZIP entries. |

Archive extraction rejects absolute/traversal paths, corrupt checksums, unknown
required features, encrypted ZIP, ZIP64, links, and device nodes. MutableFS
limits regular files to 128 KiB, so these tools target configuration and small
exchange archives, not model packages.

## System and interactive tools

| Command | Supported core behavior |
|---|---|
| `df` | Show mounted MutableFS/ModelFS usage known to the guest. |
| `du [-s] [PATH]` | Report bounded recursive usage; `-s` prints a summary. |
| `ps` | Show the kernel process snapshot, state, CPU assignment, memory, runtime, and syscall counters. |
| `status` | Render the bounded administrative status view; detailed operations use the `xaiosctl` application family. |

## Outbound network clients

| Command | Supported core behavior |
|---|---|
| `ssh [-p PORT] user@host [command]` | IPv4/DNS-A SSH client with password authentication, Ed25519 host-key TOFU, persistent known-host verification, PTY or one command. |
| `scp [-r] [-P PORT] SOURCE DESTINATION` | Copy files or bounded directory trees between XAIOS and compatible XAIOS, FreeBSD, or OpenSSH servers. Exactly one endpoint may be remote. |

The clients do not implement public-key client authentication, IPv6 active
opens, forwarding, agents, jump hosts, or hybrid post-quantum key exchange.

## Operations and diagnostics

| Command | Supported core behavior |
|---|---|
| `shutdown` / `reboot` | Persist lifecycle intent, flush logs and block devices, then power off or reset through the architecture backend. |
| `power status` | Show running/quiescing and boot-ready state. |
| `service list|status|start|stop|restart` | Inspect or control the bounded kernel service registry with capability checks. |
| `kill PID` | Terminate and reclaim a non-running transient process; PID 1/2 and the current process are protected. |
| `ifconfig` | Show the active VirtIO interface, IPv4 address, netmask, MTU, and MAC. |
| `route`, `arp`, `ndp`, `netstat` | Show bounded routing, neighbor, packet, flow, drop, and resolver state. |
| `ping IP`, `ping status` | Start a validated asynchronous ICMP echo and inspect its result/RTT. |
| `nslookup NAME` | Start or read an asynchronous DNS A-record lookup. |
| `date`, `date -s EPOCH` | Show epoch/source or set a validated UTC epoch in seconds. |
| `ntp sync [IP]`, `ntp status` | Start a bounded SNTP exchange or inspect source, attempts, stratum, RTT, timeout, and error state. |
| `limits` | Show normal/warning/critical pressure plus memory, heap, process, filesystem, and CPU capacity. |
| `recovery status|enter|clear` | Inspect unclean boots or manage the persistent rescue marker. |
| `update status|rollback` | Inspect the signed update transaction or invoke its authorized rollback path. |
| `config export|import PATH` | Round-trip canonical configuration through the validated transactional admin path. |
| `support` | Emit a redacted build/lifecycle/clock/resource/network/log bundle suitable for host-side capture. |

Power, lifecycle, and recovery details are in
[[Operations and Recovery|Operations-and-Recovery]].

## Session control and errors

`help` prints the available surface. `exit`, `quit`, and `logout` end the
session. Unknown commands return `command not found`; invalid options, missing
paths, unsupported archive features, authentication failures, and application
exit failures return a nonzero status with command-specific text. Per-session
working directories are isolated across concurrent SSH connections.

Executable diagnostics and interactive terminal applications are intentionally
documented on [[Applications|Applications]], not duplicated here.
Interoperability coverage is in
[[Testing XAIOS|Testing-XAIOS]].
