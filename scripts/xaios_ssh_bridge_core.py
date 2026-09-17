"""Shared filesystem model and session primitives for the XAIOS SSH bridge.

This module is the bridge's private foundation. It owns the single
``VIRTUAL_FS`` instance, the path and token normalisation the command
dispatcher relies on, and the small channel writers shared by the exec and
shell paths. Both ``xaios_ssh_bridge_tools`` and the ``xaios-ssh-bridge.py``
entry point import from here, so the state is created exactly once and every
caller sees the same filesystem.
"""

import fnmatch
import posixpath
import shlex


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
