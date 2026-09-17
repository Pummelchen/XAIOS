"""Archive, editor and host-observation commands for the XAIOS SSH bridge.

The tar/cpio codec, the ``nano`` line editor and the ``xtop`` sampler live
here. They are the tools the remote command dispatcher in the entry point
calls into; they read and write the shared ``VIRTUAL_FS`` from
``xaios_ssh_bridge_core`` and create no state of their own.
"""

import os
import resource
import sys
import time

from xaios_ssh_bridge_core import (
    VIRTUAL_FS,
    _join_path,
    _normalize_path,
)


_XAIOS_ARCHIVE_MAGIC = "XAIOSARCHIVE\n"


def _archive_push_entry(entries, kind, path, data):
    path_length = len(path)
    data_size = len(data)
    entries.append(f"{kind} {path_length} {data_size} {path}\n")
    if data_size > 0:
        entries.append(data)
    entries.append("\n")


def _collect_archive_entries(source, archive_name, entries):
    info = VIRTUAL_FS.stat(source)
    if info is None:
        return False
    if info["type"] == "dir":
        _archive_push_entry(entries, "D", archive_name, "")
        for child in VIRTUAL_FS._children(source):
            child_source = _join_path(source, child)
            child_archive = f"{archive_name}/{child}" if archive_name != "/" else child
            if not _collect_archive_entries(child_source, child_archive, entries):
                return False
        return True
    if info["type"] == "file":
        data = VIRTUAL_FS.read(source)
        if data is None:
            data = ""
        _archive_push_entry(entries, "F", archive_name, data)
        return True
    return False


def _archive_parse_entries(archive_text):
    if not archive_text.startswith(_XAIOS_ARCHIVE_MAGIC):
        return None
    cursor = len(_XAIOS_ARCHIVE_MAGIC)
    out = []
    while cursor < len(archive_text):
        while cursor < len(archive_text) and archive_text[cursor] in "\r\n":
            cursor += 1
        if cursor >= len(archive_text):
            break
        newline = archive_text.find("\n", cursor)
        if newline < 0:
            return None
        header = archive_text[cursor:newline]
        cursor = newline + 1
        parts = header.split(" ", 3)
        if len(parts) != 4:
            return None
        kind, path_len_text, data_size_text, path = parts
        try:
            path_len = int(path_len_text, 10)
            data_size = int(data_size_text, 10)
        except ValueError:
            return None
        if len(path) != path_len:
            return None
        if kind == "D":
            out.append((kind, path, ""))
            continue
        if kind != "F":
            return None
        data_end = cursor + data_size
        if data_end > len(archive_text):
            return None
        data = archive_text[cursor:data_end]
        out.append((kind, path, data))
        cursor = data_end
        if cursor < len(archive_text) and archive_text[cursor] == "\n":
            cursor += 1
    return out


def _archive_list(archive_path):
    content = VIRTUAL_FS.read(archive_path)
    if content is None:
        return None
    entries = _archive_parse_entries(content)
    if entries is None:
        return None
    lines = []
    for kind, path, _ in entries:
        if kind == "D":
            lines.append(f"{path}/")
        else:
            lines.append(path)
    return "\n".join(lines) + ("\n" if lines else "")


def _archive_extract(archive_path, destination):
    content = VIRTUAL_FS.read(archive_path)
    if content is None:
        return False, "archive not found"
    entries = _archive_parse_entries(content)
    if entries is None:
        return False, "invalid archive"
    for kind, entry_path, data in entries:
        if entry_path.startswith("/"):
            return False, "invalid archive path"
        absolute = _normalize_path(destination, entry_path)
        if kind == "D":
            if not VIRTUAL_FS.mkdir(absolute):
                return False, "cannot create directory"
            continue
        if kind != "F":
            return False, "invalid archive kind"
        if not VIRTUAL_FS.write(absolute, data):
            return False, "cannot write file"
    return True, ""


def _handle_tar_command(args, cwd):
    if not args:
        return 1, "tar: missing options\n"
    mode = args[0]
    if mode not in ("-cf", "-xf", "-tf"):
        return 1, "tar: unsupported option\n"
    if len(args) < 2:
        return 1, "tar: missing archive\n"
    archive = _normalize_path(cwd, args[1])

    if mode == "-tf":
        if len(args) != 2:
            return 1, "tar: too many arguments\n"
        listing = _archive_list(archive)
        if listing is None:
            return 1, f"xaios-ssh: tar: cannot access '{archive}': No such file\n"
        return 0, listing

    if mode == "-xf":
        destination = cwd
        i = 2
        while i < len(args):
            if args[i] != "-C":
                return 1, "tar: unsupported option\n"
            if i + 1 >= len(args):
                return 1, "tar: missing destination\n"
            destination = args[i + 1]
            i += 2
        destination = _normalize_path(cwd, destination)
        if VIRTUAL_FS._exists_dir(destination) is False:
            return 1, f"xaios-ssh: tar: cannot access '{destination}': No such file\n"
        ok, reason = _archive_extract(archive, destination)
        if not ok:
            return 1, f"tar: {reason}\n"
        return 0, ""

    # -cf
    if len(args) < 3:
        return 1, "tar: missing files\n"
    entries = [_XAIOS_ARCHIVE_MAGIC]
    for source_arg in args[2:]:
        source = _normalize_path(cwd, source_arg)
        source_base = os.path.basename(source)
        if not _collect_archive_entries(source, source_base, entries):
            return 1, f"xaios-ssh: tar: cannot access '{source_arg}': No such file\n"
    if not VIRTUAL_FS.write(archive, "".join(entries)):
        return 1, "tar: cannot write archive\n"
    return 0, ""


def _handle_cpio_command(args, cwd):
    if not args:
        return 1, "cpio: missing options\n"
    mode = args[0]
    if not mode.startswith("-") or ("o" not in mode and "i" not in mode):
        return 1, "cpio: unsupported option\n"
    create = "o" in mode
    extract = "i" in mode
    if create == extract:
        return 1, "cpio: unsupported option\n"

    if create:
        if len(args) < 2:
            return 1, "cpio: missing archive\n"
        archive = None
        i = 1
        entries = [_XAIOS_ARCHIVE_MAGIC]
        source_count = 0
        while i < len(args):
            if args[i] == "-O":
                if i + 1 >= len(args):
                    return 1, "cpio: missing archive\n"
                archive = _normalize_path(cwd, args[i + 1])
                i += 2
                continue
            if args[i].startswith("-"):
                return 1, "cpio: unsupported option\n"
            source = _normalize_path(cwd, args[i])
            source_base = os.path.basename(source)
            if not _collect_archive_entries(source, source_base, entries):
                return 1, f"xaios-ssh: cpio: cannot access '{args[i]}': No such file\n"
            source_count += 1
            i += 1
        if archive is None:
            return 1, "cpio: missing archive\n"
        if source_count == 0:
            return 1, "cpio: missing source\n"
        if not VIRTUAL_FS.write(archive, "".join(entries)):
            return 1, "cpio: cannot write archive\n"
        return 0, ""

    # extract mode
    if len(args) != 3 or args[1] != "-I":
        return 1, "cpio: expected -I archive\n"
    archive = _normalize_path(cwd, args[2])
    ok, reason = _archive_extract(archive, cwd)
    if not ok:
        return 1, f"cpio: {reason}\n"
    return 0, ""


def _nano_decode(text):
    decoded = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\"}
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            escaped = text[index + 1]
            if escaped in escapes:
                decoded.append(escapes[escaped])
                index += 2
                continue
        decoded.append(text[index])
        index += 1
    return "".join(decoded)


def _nano_line_bounds(content, line_number):
    if line_number < 1:
        return None
    current = 1
    start = 0
    while True:
        if current == line_number:
            end = content.find("\n", start)
            if end < 0:
                end = len(content)
                return start, end, end
            return start, end, end + 1
        newline = content.find("\n", start)
        if newline < 0:
            return None
        start = newline + 1
        current += 1


def _handle_nano_command(args, cwd):
    usage = (
        "nano PATH [--number|--write TEXT|--append TEXT|--insert LINE TEXT|"
        "--replace LINE TEXT|--delete LINE]\n"
        "TEXT escapes: \\n \\r \\t \\\\\n"
    )
    if not args or args[0] == "--help":
        return 0, usage

    path = _normalize_path(cwd, args[0])
    info = VIRTUAL_FS.stat(path)
    if info is not None and info["type"] != "file":
        return 1, "nano: path is not a file\n"
    content = VIRTUAL_FS.read(path) if info is not None else ""

    if len(args) == 1:
        suffix = "\n" if info is not None else " [ New File ]\n"
        body = content
        if body and not body.endswith("\n"):
            body += "\n"
        return 0, f"nano: {path}{suffix}{body}"

    action = args[1]
    if action == "--number":
        if len(args) != 2:
            return 1, "nano: too many arguments\n"
        lines = content.splitlines()
        if not lines:
            lines = [""]
        return 0, "".join(f"{index}  {line}\n" for index, line in enumerate(lines, 1))

    if action in ("--write", "--append"):
        text = _nano_decode(" ".join(args[2:]))
        edited = text if action == "--write" else content + text
    elif action in ("--insert", "--replace", "--delete"):
        if len(args) < 3:
            return 1, "nano: invalid line number\n"
        try:
            line_number = int(args[2])
        except ValueError:
            return 1, "nano: invalid line number\n"
        bounds = _nano_line_bounds(content, line_number)
        if bounds is None:
            return 1, "nano: invalid line number\n"
        start, _, next_line = bounds
        if action == "--delete":
            if len(args) != 3:
                return 1, "nano: delete takes only a line number\n"
            edited = content[:start] + content[next_line:]
        else:
            if len(args) < 4:
                return 1, "nano: missing text\n"
            text = _nano_decode(" ".join(args[3:]))
            suffix = start if action == "--insert" else next_line
            edited = content[:start] + text + "\n" + content[suffix:]
    else:
        return 1, "nano: unsupported option; use nano --help\n"

    if len(edited.encode("utf-8")) > 3071:
        return 1, "nano: text exceeds editor capacity\n"
    if not VIRTUAL_FS.write(path, edited):
        return 1, "nano: save failed\n"
    return 0, f"nano: saved {path} bytes={len(edited.encode('utf-8'))}\n"


def _handle_xtop_command(args):
    show_all = True
    show_cpus = True
    cpu_start = 0
    cpu_requested = None
    sample_ms = 250
    index = 0
    while index < len(args):
        option = args[index]
        index += 1
        if option == "--all":
            show_all = True
        elif option == "--active":
            show_all = False
        elif option == "--no-cpus":
            show_cpus = False
        elif option == "--help":
            return 0, (
                "xtop [--active|--all] [--sample-ms 1..1000] "
                "[--cpu-start N] [--cpu-count N] [--no-cpus]\n"
            )
        elif option in ("--sample-ms", "--cpu-start", "--cpu-count"):
            if index >= len(args):
                return 1, f"xtop: missing value for {option}\n"
            try:
                value = int(args[index], 10)
            except ValueError:
                return 1, f"xtop: invalid {option}\n"
            index += 1
            if option == "--sample-ms":
                if value < 1 or value > 1000:
                    return 1, "xtop: --sample-ms must be 1..1000\n"
                sample_ms = value
            elif option == "--cpu-start":
                if value < 0:
                    return 1, "xtop: invalid --cpu-start\n"
                cpu_start = value
            else:
                if value < 1:
                    return 1, "xtop: invalid --cpu-count\n"
                cpu_requested = value
        else:
            return 1, "xtop: unsupported option; use xtop --help\n"

    cpu_total = os.cpu_count() or 1
    if cpu_start > cpu_total:
        return 1, "xtop: --cpu-start exceeds online CPU count\n"
    cpu_shown = cpu_total - cpu_start
    if cpu_requested is not None:
        cpu_shown = min(cpu_shown, cpu_requested)
    if not show_cpus:
        cpu_shown = 0

    wall_before = time.monotonic_ns()
    process_before = time.process_time_ns()
    time.sleep(sample_ms / 1000.0)
    wall_after = time.monotonic_ns()
    process_after = time.process_time_ns()
    elapsed = max(1, wall_after - wall_before)
    process_delta = max(0, process_after - process_before)
    process_cpu = 100.0 * process_delta / elapsed
    system_cpu = process_cpu / cpu_total

    physical_pages = os.sysconf("SC_PHYS_PAGES")
    page_size = os.sysconf("SC_PAGE_SIZE")
    total_bytes = physical_pages * page_size
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        rss_bytes = rss
    else:
        rss_bytes = rss * 1024
    memory_percent = 100.0 * rss_bytes / total_bytes if total_bytes else 0.0

    lines = [
        f"XAIOS xtop source=ssh-bridge sample_ms={sample_ms} cpus={cpu_total} "
        "tasks_active=1 failed=0",
        f"CPU all={system_cpu:.1f}% MEM bridge={memory_percent:.1f}% "
        f"bytes={rss_bytes}/{total_bytes}",
    ]
    if show_cpus:
        lines.append("CPU CPU% BUSY_MS IDLE_MS ACTIVE ROLE")
        for offset in range(cpu_shown):
            cpu_id = cpu_start + offset
            cpu_percent = process_cpu if cpu_id == 0 else 0.0
            busy_ms = int(process_delta / 1_000_000) if cpu_id == 0 else 0
            idle_ms = max(0, sample_ms - busy_ms)
            active = 2 if cpu_id == 0 else 0
            lines.append(
                f"{cpu_id} {cpu_percent:.1f}% {busy_ms} {idle_ms} "
                f"{active} host-proxy"
            )
        paging = f"cpu_shown={cpu_shown} cpu_total={cpu_total}"
        if cpu_start + cpu_shown < cpu_total:
            paging += f" next_cpu_start={cpu_start + cpu_shown}"
        lines.append(paging)

    lines.append("PID PPID S CPU% MEM% TIME_MS RES_KIB CPU SYSCALLS COMMAND")
    lines.append(
        f"2 1 running {process_cpu:.1f}% {memory_percent:.1f}% "
        f"{int(process_after / 1_000_000)} {rss_bytes // 1024} 0 0 "
        "/bin/xaios-ssh-bridge"
    )
    process_total = 1
    if show_all:
        lines.append("1 0 exited 0.0% 0.0% 0 0 0 0 /init")
        process_total += 1
    lines.append(f"process_shown={process_total} process_total={process_total}")
    return 0, "\n".join(lines) + "\n"
