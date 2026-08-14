# Commands

XAIOS provides a bounded FreeBSD-style command surface for authenticated local
and SSH PTY sessions. This page lists session syntax and service or kernel
operations. Every dedicated executable, including file, text, archive, and
observability utilities, is listed in [[Applications|Applications]].

## Current ownership

| Current owner | Commands or responsibility | Fault boundary |
|---|---|---|
| Kernel session layer | `cd`, `pwd`, `help`, `exit`, `quit`, `logout`, aliases, redirection, and pipelines | Maintains per-session state and command composition. |
| Independent utility ELFs | File, text, archive, and observability tools documented in [[Applications|Applications]] | Each invocation has a bounded address space, least-privilege capabilities, exit status, and fault containment. |
| `/bin/sshd` plus transient `/bin/ssh` | Inbound SSH/SFTP transport plus dedicated outbound `ssh` and `scp` protocol execution | The client uses asynchronous child-channel IPC; a client fault is contained without terminating the inbound service. |
| Kernel operations layer | `status`, power, service, process, network, clock, recovery, update, configuration, and support commands | Capability checks and privileged mechanisms remain authoritative in the kernel. |

## Session navigation and composition

| Command | Supported core behavior |
|---|---|
| `pwd` | Print the session working directory. |
| `cd [DIR]` | Change directory; no argument selects `/`; relative, absolute, `.` and `..` paths are normalized. |
| `l`, `la`, `ll` | Session aliases that dispatch the standalone `/bin/ls` application. |
| `echo [TEXT...]` | Print text. `>` and `>>` redirect output to a file. |
| `COMMAND | COMMAND` | Connect supported producer/filter commands through the bounded in-memory pipeline. |
| `status` | Render the bounded administrative status view; detailed operations use the `xaiosctl` application family. |

## Outbound network clients

| Command | Supported core behavior |
|---|---|
| `ssh [-A] [-i KEY] [-p PORT] [-J user@host[:port]] user@host [command]` | Dedicated SSH application with password, Ed25519 identity-file or forwarded-agent authentication; encrypted OpenSSH keys, IPv4/IPv6 and DNS A/AAAA are supported. One password-authenticated ProxyJump hop can carry a separately password- or identity-authenticated target through `direct-tcpip`. |
| `scp [-r] [-A] [-i KEY] [-P PORT] SOURCE DESTINATION` | Dedicated SFTP-backed copy application for files or bounded directory trees between XAIOS and compatible XAIOS, FreeBSD, or OpenSSH servers. Exactly one endpoint may be remote. |

The clients run outside the persistent SSH service through bounded asynchronous child-channel IPC, so a client fault does not terminate the inbound server.
The inbound server implements hybrid `mlkem768x25519-sha256`, `direct-tcpip`
jump-host forwarding and agent forwarding. The native outbound client supports
one `-J user@host[:port]` hop; multi-hop `-J`, `ProxyCommand`, `-J` with agent
authentication, and the complete OpenSSH algorithm matrix are not implemented.

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

All executable utilities, diagnostics, and interactive terminal applications
are intentionally documented on [[Applications|Applications]], not duplicated
here.
Interoperability coverage is in
[[Testing XAIOS|Testing-XAIOS]].
