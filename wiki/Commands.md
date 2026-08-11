# Commands

XAIOS provides a bounded FreeBSD-style command surface for authenticated local
and SSH PTY sessions. These commands are implemented by the XAIOS shell/SSH
subsystem; they are not standalone ELF applications. Executable applications
are listed in [[Applications|Applications]].

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
| `nano FILE` | Full-screen editor with cursor movement, insertion/deletion, save, search, and exit; editing buffer is 32 KiB. |
| `htop` | Full-screen sampled process monitor. Defaults to color, alternate-screen in-place refresh, up to 60 refreshes/second, CPU meters sized from runtime CPU count, process sorting/filtering/tree controls, and keyboard navigation. Options remain available for test automation. |
| `pong` | 60 FPS terminal Pong: `W`/`S` control the left paddle, the computer controls the right, and persistent-session win/loss counts adjust ball speed by one percent per round. |

## Outbound network clients

| Command | Supported core behavior |
|---|---|
| `ssh [-p PORT] user@host [command]` | IPv4/DNS-A SSH client with password authentication, Ed25519 host-key TOFU, persistent known-host verification, PTY or one command. |
| `scp [-r] [-P PORT] SOURCE DESTINATION` | Copy files or bounded directory trees between XAIOS and compatible XAIOS, FreeBSD, or OpenSSH servers. Exactly one endpoint may be remote. |

The clients do not implement public-key client authentication, IPv6 active
opens, forwarding, agents, jump hosts, or hybrid post-quantum key exchange.

## Session control and errors

`help` prints the available surface. `exit`, `quit`, and `logout` end the
session. Unknown commands return `command not found`; invalid options, missing
paths, unsupported archive features, authentication failures, and application
exit failures return a nonzero status with command-specific text. Per-session
working directories are isolated across concurrent SSH connections.

Commands that are executable diagnostics (`hello`, `sysinfo`, `systest`, and
others) are intentionally documented on [[Applications|Applications]], not
duplicated here. Interoperability coverage is in
[[Testing XAIOS|Testing-XAIOS]].
