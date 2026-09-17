#!/usr/bin/env python3
import argparse
import os
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

from xaios_ssh_bridge_core import (
    VIRTUAL_FS,
    _grep_file,
    _handle_head_tail,
    _normalize_path,
    _normalize_tokens,
    _read_file_lines,
    _render_ls_listing,
    _send_line,
    _write_text,
)
from xaios_ssh_bridge_tools import (
    _handle_cpio_command,
    _handle_nano_command,
    _handle_tar_command,
    _handle_xtop_command,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOST_KEY = ROOT / "build" / "xaios-ssh" / "host_rsa.key"


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
            "l la ll tar cpio cat mv rm rmdir stat write nano xtop status sysinfo "
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

    if cmd == "xtop":
        return _handle_xtop_command(args)

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
