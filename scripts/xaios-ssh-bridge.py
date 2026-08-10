#!/usr/bin/env python3
import argparse
import fnmatch
import os
import posixpath
import resource
import shlex
import socket
import sys
import threading
import time
from pathlib import Path

try:
    import paramiko
except ImportError as exc:
    raise SystemExit(
        "missing dependency: paramiko. Run scripts/run-xaios-ssh-bridge.sh "
        "so the isolated build/xaios-ssh-venv environment is created."
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOST_KEY = ROOT / "build" / "xaios-ssh" / "host_rsa.key"


def _normalize_tokens(command):
    command = command.strip()
    if command == "":
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _join_path(base, child):
    if base == "/":
        return f"/{child}"
    return f"{base}/{child}"


def _normalize_path(cwd, target):
    if target == "":
        target = "."
    if not target.startswith("/"):
        target = f"{cwd}/{target}" if cwd != "/" else f"/{target}"
    normalized = posixpath.normpath(target)
    if normalized == ".":
        normalized = "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


class VirtualFS:
    def __init__(self):
        self.dirs = {"/", "/bin", "/etc", "/models", "/state"}
        self.files = {}

    @staticmethod
    def _normalize(cwd, target):
        return _normalize_path(cwd, target)

    def _parent(self, path):
        if path == "/":
            return "/"
        parent = posixpath.dirname(path)
        return parent if parent != "" else "/"

    def _children(self, path):
        entries = []
        prefix = "/" if path == "/" else f"{path}/"
        for directory in self.dirs:
            if directory == path:
                continue
            if directory.startswith(prefix):
                rest = directory[len(prefix):]
                if rest and "/" not in rest:
                    entries.append(rest)
        for file_path in self.files:
            if file_path.startswith(prefix):
                rest = file_path[len(prefix):]
                if rest and "/" not in rest:
                    entries.append(rest)
        entries.sort()
        return entries

    def _is_dir(self, path):
        return path in self.dirs

    def _is_file(self, path):
        return path in self.files

    def _exists_dir(self, path):
        return path in self.dirs

    def _exists_file(self, path):
        return path in self.files

    def _ensure_parent(self, path):
        return self._exists_dir(self._parent(path))

    def stat(self, path):
        path = self._normalize("/", path)
        if path in self.dirs:
            return {"type": "dir", "size": 0}
        if path in self.files:
            return {"type": "file", "size": len(self.files[path])}
        return None

    def ls(self, path):
        normalized = self._normalize("/", path)
        if not self._exists_dir(normalized):
            return None
        return self._children(normalized)

    def mkdir(self, path):
        path = self._normalize("/", path)
        if self._exists_dir(path) or self._exists_file(path):
            return False
        if not self._ensure_parent(path):
            return False
        self.dirs.add(path)
        return True

    def touch(self, path):
        path = self._normalize("/", path)
        if not self._ensure_parent(path):
            return False
        if self._exists_dir(path):
            return False
        self.files.setdefault(path, "")
        return True

    def write(self, path, payload):
        path = self._normalize("/", path)
        if not self._ensure_parent(path) and path != "/":
            return False
        if self._exists_dir(path):
            return False
        self.files[path] = payload
        return True

    def read(self, path):
        path = self._normalize("/", path)
        return self.files.get(path)

    def mv(self, src, dst):
        src = self._normalize("/", src)
        dst = self._normalize("/", dst)
        if not (self._exists_file(src) or self._exists_dir(src)):
            return False
        if self._exists_file(dst) or self._exists_dir(dst):
            return False
        if not self._ensure_parent(dst):
            return False
        if self._is_file(src):
            self.files[dst] = self.files.pop(src)
            return True
        self.dirs.remove(src)
        self.dirs.add(dst)
        return True

    def rm(self, path, allow_dir=False):
        path = self._normalize("/", path)
        if path == "/":
            return False
        if allow_dir:
            if not self._exists_dir(path):
                return False
            if self._children(path):
                return False
            self.dirs.remove(path)
            return True
        if self._exists_file(path):
            del self.files[path]
            return True
        return False

    def _copy_dir_tree(self, src, dst):
        self.dirs.add(dst)
        for child_name in sorted(self._children(src)):
            child_src = _join_path(src, child_name)
            child_dst = _join_path(dst, child_name)
            if self._is_dir(child_src):
                self._copy_dir_tree(child_src, child_dst)
            elif self._is_file(child_src):
                self.files[child_dst] = self.files[child_src]

    def cp(self, src, dst):
        src = self._normalize("/", src)
        dst = self._normalize("/", dst)
        if not (self._is_file(src) or self._is_dir(src)):
            return False
        if not self._exists_dir(self._parent(dst)):
            return False
        if self._exists_file(dst) or self._exists_dir(dst):
            return False
        if self._is_file(src):
            self.files[dst] = self.files[src]
            return True
        self._copy_dir_tree(src, dst)
        return True

    def find(self, start, pattern=None):
        start = self._normalize("/", start)
        if not self._exists_dir(start):
            return None
        matcher = (lambda name: True) if pattern == "" or pattern is None else (
            lambda name: fnmatch.fnmatch(name, pattern)
        )
        root_base = start.rsplit("/", 1)[-1]
        if root_base == "":
            root_base = "/"
        output = []
        if matcher(root_base):
            output.append(start if start != "" else "/")

        def walk(path):
            for name in self._children(path):
                child = _join_path(path, name)
                if self._is_dir(child):
                    if matcher(name):
                        output.append(child)
                    walk(child)
                elif matcher(name):
                    output.append(child)

        walk(start)
        return output


VIRTUAL_FS = VirtualFS()


def _write(channel, text):
    if not text:
        return
    channel.send(text.encode("utf-8"))


def _write_text(channel, text):
    if not text:
        return
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\n", "\r\n")
    channel.sendall(normalized.encode("utf-8"))


def _send_line(channel, text=""):
    channel.sendall((text + "\r\n").encode("utf-8"))


def _render_ls_listing(entries, directory, long_form=False):
    if not entries:
        return "\n"
    if not long_form:
        return "\n".join(entries) + "\n"
    lines = []
    for entry in entries:
        path = _join_path(directory, entry)
        info = VIRTUAL_FS.stat(path)
        if info is None:
            continue
        type_char = "d" if info["type"] == "dir" else "-"
        lines.append(f"{type_char} {info['size']} {entry}")
    return "\n".join(lines) + "\n"


def _grep_file(pattern, path):
    content = VIRTUAL_FS.read(path)
    if content is None:
        return None
    lines = []
    for line in content.splitlines():
        if pattern in line:
            lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


def _read_file_lines(path):
    content = VIRTUAL_FS.read(path)
    if content is None:
        return None
    return content


def _handle_head_tail(path, lines, is_head):
    data = _read_file_lines(path)
    if data is None:
        return None
    split = data.splitlines(True)
    if is_head:
        return "".join(split[:lines])
    return "".join(split[-lines:] if lines > 0 else [])


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


def _handle_htop_command(args):
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
                "htop [--active|--all] [--sample-ms 1..1000] "
                "[--cpu-start N] [--cpu-count N] [--no-cpus]\n"
            )
        elif option in ("--sample-ms", "--cpu-start", "--cpu-count"):
            if index >= len(args):
                return 1, f"htop: missing value for {option}\n"
            try:
                value = int(args[index], 10)
            except ValueError:
                return 1, f"htop: invalid {option}\n"
            index += 1
            if option == "--sample-ms":
                if value < 1 or value > 1000:
                    return 1, "htop: --sample-ms must be 1..1000\n"
                sample_ms = value
            elif option == "--cpu-start":
                if value < 0:
                    return 1, "htop: invalid --cpu-start\n"
                cpu_start = value
            else:
                if value < 1:
                    return 1, "htop: invalid --cpu-count\n"
                cpu_requested = value
        else:
            return 1, "htop: unsupported option; use htop --help\n"

    cpu_total = os.cpu_count() or 1
    if cpu_start > cpu_total:
        return 1, "htop: --cpu-start exceeds online CPU count\n"
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
        f"XAIOS htop source=ssh-bridge sample_ms={sample_ms} cpus={cpu_total} "
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


def xaios_remote_command(command, cwd="/"):
    tokens = _normalize_tokens(command)
    if not tokens:
        return 0, ""

    cmd = tokens[0]
    args = tokens[1:]

    if cmd == "help":
        return (
            0,
            "XAIOS SSH commands: pwd ls cd mkdir touch cp grep find head tail echo "
            "l la ll tar cpio cat mv rm rmdir stat write nano htop status sysinfo "
            "exit quit logout help\n",
        )

    if cmd == "pwd":
        return 0, f"{cwd}\n"
    if cmd == "status":
        return 0, "legacy status command; use xaiosctl status on the freestanding XAIOS guest\n"
    if cmd == "sysinfo":
        return 0, "legacy sysinfo command; use xaiosctl hardware on the freestanding XAIOS guest\n"

    if cmd == "ls":
        show_hidden = False
        long_form = False
        target = cwd
        end_of_options = False
        i = 0
        while i < len(args):
            arg = args[i]
            if end_of_options is False and arg == "--":
                end_of_options = True
                i += 1
                continue

            if arg.startswith("-") and arg != "-" and end_of_options is False:
                if arg == "-a":
                    show_hidden = True
                elif arg == "-l":
                    long_form = True
                elif arg in ("-la", "-al"):
                    show_hidden = True
                    long_form = True
                else:
                    return 1, f"xaios-ssh: ls: invalid option '{arg}'\n"
                i += 1
                continue
            if target != cwd:
                return 1, "ls: too many arguments\n"
            target = _normalize_path(cwd, arg)
            i += 1

        listing = VIRTUAL_FS.ls(target)
        if listing is None:
            return 1, (
                f"xaios-ssh: ls: cannot access '{target}': "
                "No such file or directory\n"
            )
        if not show_hidden:
            listing = [entry for entry in listing if not entry.startswith(".")]
        return 0, _render_ls_listing(listing, target, long_form)

    if cmd in ("l", "ll", "la"):
        alias = "-la" if cmd != "ll" else "-l"
        if cmd == "la":
            alias = "-la"
        base = f"ls {alias}"
        if args:
            return xaios_remote_command(f"{base} {' '.join(args)}", cwd)
        return xaios_remote_command(base, cwd)

    if cmd == "cd":
        if len(args) > 1:
            return 1, "cd: too many arguments\n"
        target = "/" if len(args) == 0 else _normalize_path(cwd, args[0])
        if not VIRTUAL_FS.stat(target):
            return 1, f"xaios-ssh: cd: no such file or directory: {target}\n"
        if VIRTUAL_FS.stat(target)["type"] != "dir":
            return 1, f"xaios-ssh: cd: not a directory: {target}\n"
        return 0, target

    if cmd == "mkdir":
        if len(args) == 0:
            return 1, "mkdir: missing path\n"
        if len(args) > 1:
            return 1, "mkdir: too many arguments\n"
        target = _normalize_path(cwd, args[0])
        if not VIRTUAL_FS.mkdir(target):
            return 1, f"xaios-ssh: mkdir: failed for '{target}'\n"
        return 0, ""

    if cmd == "touch":
        if len(args) == 0:
            return 1, "touch: missing path\n"
        if len(args) > 1:
            return 1, "touch: too many arguments\n"
        target = _normalize_path(cwd, args[0])
        if not VIRTUAL_FS.touch(target):
            return 1, f"xaios-ssh: touch: failed for '{target}'\n"
        return 0, ""

    if cmd == "cat":
        if len(args) == 0:
            return 1, "cat: missing path\n"
        if len(args) > 1:
            return 1, "cat: too many arguments\n"
        target = _normalize_path(cwd, args[0])
        content = _read_file_lines(target)
        if content is None:
            return 1, f"xaios-ssh: cat: cannot open '{target}': No such file\n"
        return 0, content

    if cmd == "write":
        if len(args) == 0:
            return 1, "write: missing path\n"
        path = _normalize_path(cwd, args[0])
        payload = " ".join(args[1:])
        if not VIRTUAL_FS.write(path, payload):
            return 1, f"xaios-ssh: write: failed for '{path}'\n"
        return 0, ""

    if cmd == "nano":
        return _handle_nano_command(args, cwd)

    if cmd == "htop":
        return _handle_htop_command(args)

    if cmd == "cp":
        if len(args) < 2:
            return 1, "cp: missing source or destination\n"
        if len(args) > 2:
            return 1, "cp: too many arguments\n"
        src = _normalize_path(cwd, args[0])
        dst = _normalize_path(cwd, args[1])
        if not VIRTUAL_FS.cp(src, dst):
            return 1, f"xaios-ssh: cp: failed to copy '{src}'\n"
        return 0, ""

    if cmd == "grep":
        if len(args) < 2:
            return 1, "grep: missing pattern or file\n"
        if len(args) > 2:
            return 1, "grep: too many arguments\n"
        pattern = args[0]
        target = _normalize_path(cwd, args[1])
        matches = _grep_file(pattern, target)
        if matches is None:
            return 1, f"xaios-ssh: grep: cannot open '{target}'\n"
        return 0, matches

    if cmd == "find":
        if len(args) == 0:
            path = "."
            rest = []
        else:
            path = args[0]
            rest = args[1:] if len(args) > 1 else []
        if path.startswith("-"):
            path = "."
            rest = args
        pattern = ""
        i = 0
        while i < len(rest):
            token = rest[i]
            if token == "-name":
                if i + 1 >= len(rest):
                    return 1, "find: missing -name argument\n"
                pattern = rest[i + 1]
                i += 2
                continue
            if token.startswith("-"):
                return 1, f"xaios-ssh: find: unsupported option '{token}'\n"
            return 1, "find: too many path arguments\n"
        target = _normalize_path(cwd, path)
        result = VIRTUAL_FS.find(target, pattern if pattern else "")
        if result is None:
            return 1, f"xaios-ssh: find: cannot access '{target}': No such file\n"
        return 0, "\n".join(result) + ("\n" if result else "")

    if cmd == "head" or cmd == "tail":
        is_head = cmd == "head"
        if len(args) == 0:
            return 1, f"{cmd}: missing operand\n"
        lines = 10
        index = 0
        if args[0] == "-n":
            if len(args) < 3:
                return 1, f"{cmd}: invalid -n usage\n"
            try:
                lines = int(args[1])
                if lines <= 0:
                    raise ValueError
            except ValueError:
                return 1, f"{cmd}: invalid -n argument '{args[1]}'\n"
            index = 2
        elif args[0].startswith("-n") and len(args[0]) > 2:
            try:
                lines = int(args[0][2:])
                if lines <= 0:
                    raise ValueError
            except ValueError:
                return 1, f"{cmd}: invalid -n argument '{args[0]}'\n"
            index = 1
        if index >= len(args):
            return 1, f"{cmd}: missing file\n"
        if len(args) > index + 1:
            return 1, f"{cmd}: too many arguments\n"
        target = _normalize_path(cwd, args[index])
        output = _handle_head_tail(target, lines, is_head)
        if output is None:
            return 1, f"xaios-ssh: {cmd}: cannot open '{target}'\n"
        return 0, output

    if cmd == "echo":
        return 0, " ".join(args) + "\n"

    if cmd == "tar":
        return _handle_tar_command(args, cwd)
    if cmd == "cpio":
        return _handle_cpio_command(args, cwd)

    if cmd == "mv":
        if len(args) != 2:
            return 1, "mv: missing operand\n"
        src = _normalize_path(cwd, args[0])
        dst = _normalize_path(cwd, args[1])
        if not VIRTUAL_FS.mv(src, dst):
            return 1, f"xaios-ssh: mv: failed to move '{src}'\n"
        return 0, ""

    if cmd == "rm":
        if len(args) != 1:
            return 1, "rm: missing path or too many arguments\n"
        target = _normalize_path(cwd, args[0])
        if not VIRTUAL_FS.rm(target, allow_dir=False):
            return 1, f"xaios-ssh: rm: failed for '{target}'\n"
        return 0, ""

    if cmd == "rmdir":
        if len(args) != 1:
            return 1, "rmdir: missing operand or too many arguments\n"
        target = _normalize_path(cwd, args[0])
        if not VIRTUAL_FS.rm(target, allow_dir=True):
            return 1, f"xaios-ssh: rmdir: failed for '{target}'\n"
        return 0, ""

    if cmd == "stat":
        if len(args) != 1:
            return 1, "stat: missing path\n" if len(args) == 0 else "stat: too many arguments\n"
        target = _normalize_path(cwd, args[0])
        info = VIRTUAL_FS.stat(target)
        if info is None:
            return 1, f"xaios-ssh: stat: cannot access '{target}': No such file\n"
        return 0, (
            f"path={target}\n"
            f"type={info['type']}\n"
            f"size={info['size']}\n"
        )

    if cmd in ("exit", "quit", "logout"):
        return 0, ""

    return 127, f"xaios-ssh: command not allowlisted: {command}\n"


class XaiosSshServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.command = None
        self.shell_requested = False
        self.cwd = "/"

    def get_banner(self):
        return ("XAIOS remote login\r\n", "en-US")

    def get_allowed_auths(self, username):
        return "none,publickey"

    def check_auth_none(self, username):
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "admin"
            else paramiko.AUTH_FAILED
        )

    def check_auth_publickey(self, username, key):
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "admin"
            else paramiko.AUTH_FAILED
        )

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested = True
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        if isinstance(command, bytes):
            command = command.decode("utf-8", "replace")
        self.command = command
        self.event.set()
        return True


def ensure_host_key(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(str(path))
    os.chmod(path, 0o600)
    return key


def run_exec(channel, command):
    status, output = xaios_remote_command(command, cwd="/")
    _write_text(channel, output)
    channel.send_exit_status(status)
    channel.shutdown_write()
    time.sleep(0.02)


def run_shell(channel, server):
    def prompt():
        return f"xaios:{server.cwd} $ "

    _send_line(channel, "XAIOS remote shell")
    _send_line(channel, "Type help for commands.")
    buffer = ""
    while True:
        _write_text(channel, prompt())
        while "\n" not in buffer and "\r" not in buffer:
            data = channel.recv(1024)
            if not data:
                channel.close()
                return
            text = data.decode("utf-8", "replace")
            for ch in text:
                code = ord(ch)
                if ch == "\x03":
                    _write_text(channel, "^C\r\n")
                    buffer = ""
                elif ch in ("\b", "\x7f"):
                    buffer = buffer[:-1]
                    _write_text(channel, "\b \b")
                elif ch == "\t":
                    continue
                elif ch == "\r" or ch == "\n":
                    _write_text(channel, "\r\n")
                    break
                elif code >= 0x20 and code != 0x7F:
                    if ch.isprintable():
                        buffer += ch
                        _write_text(channel, ch)
                elif code == 0x1B:
                    continue
            if text.endswith("\n") or text.endswith("\r"):
                break
        line = buffer.replace("\r", "\n", 1).split("\n", 1)[0]
        if "\n" in buffer.replace("\r", "\n", 1):
            buffer = buffer.replace("\r", "\n", 1).split("\n", 1)[1]
        else:
            buffer = ""
        command = " ".join(line.split())
        if command == "":
            continue
        if command in ("exit", "quit", "logout"):
            _send_line(channel, "logout")
            channel.send_exit_status(0)
            channel.close()
            return

        status, output = xaios_remote_command(command, cwd=server.cwd)
        if (command == "cd" or command.startswith("cd ")) and status == 0 and output:
            server.cwd = output.strip()
            output = ""
        if output:
            _write_text(channel, output)
        if status != 0 and output == "":
            _write_text(
                channel,
                f"xaios-ssh: command '{command}' exited with status {status}\r\n",
            )


def handle_client(client, address, host_key):
    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-XAIOS_ssh_bridge"
    transport.add_server_key(host_key)
    server = XaiosSshServer()
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return
        if not server.event.wait(20):
            channel.close()
            return
        if server.command is not None:
            run_exec(channel, server.command)
        elif server.shell_requested:
            run_shell(channel, server)
        else:
            channel.close()
    except Exception as exc:
        print(f"xaios-ssh-bridge: connection {address} failed: {exc}", file=sys.stderr)
    finally:
        transport.close()


def serve(host, port, host_key_path):
    host_key = ensure_host_key(host_key_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(16)
    print(f"xaios-ssh-bridge: listening on {host}:{port} user=admin")
    print("xaios-ssh-bridge: OpenSSH command: ssh -p 2222 admin@localhost")
    while True:
        client, address = sock.accept()
        thread = threading.Thread(
            target=handle_client, args=(client, address, host_key), daemon=True
        )
        thread.start()


def main():
    parser = argparse.ArgumentParser(description="XAIOS OpenSSH-compatible bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host-key", type=Path, default=DEFAULT_HOST_KEY)
    args = parser.parse_args()
    serve(args.host, args.port, args.host_key)


if __name__ == "__main__":
    main()
