#!/usr/bin/env python3
"""Run bidirectional SSH/SFTP/SCP checks between XAIOS and real FreeBSD."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys


# The helper modules live beside this gate. The directory is added explicitly
# rather than assumed from how the script was started, because repository
# checks import this file as a module.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from qemu_gate_lib import smoke_timeout  # noqa: E402
from qemu_freebsd_bidirectional_env import (  # noqa: E402,F401
    BUILD,
    CLIENT_FAIL,
    CLIENT_PASS,
    CROSS_OUTBOUND_TIMEOUT,
    DOCKER_IMAGE,
    FREEBSD_RELEASE,
    HOST_ARCHITECTURES,
    IMAGES,
    NATIVE_OUTBOUND_TIMEOUT,
    ROOT,
    SERVER_READY,
    XAIOS_MACHINES,
    XAIOS_READY,
    create_seed_iso,
    default_outbound_timeout,
    download,
    freebsd_architecture,
    prepare_freebsd_image,
    run_checked,
    sha256,
    stop_process,
    wait_for_marker,
    xaios_process,
)
from qemu_freebsd_bidirectional_payload import (  # noqa: E402,F401
    freebsd_script,
    user_data,
)


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    architecture = os.environ.get("XAIOS_QEMU_NETWORK_ARCH", "aarch64")
    if architecture not in XAIOS_MACHINES:
        raise SystemExit("error: XAIOS_QEMU_NETWORK_ARCH must be one of "
                         + ", ".join(sorted(XAIOS_MACHINES)))
    client_architecture = freebsd_architecture()
    required = ("docker", "qemu-img", "xz", "ssh-keygen", "ssh", "ssh-agent", "ssh-add")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"error: missing required tools: {', '.join(missing)}")

    BUILD.mkdir(parents=True, exist_ok=True)
    work = BUILD / f"qemu-freebsd-bidirectional-{architecture}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    key_dir = work / "keys"
    key_dir.mkdir(mode=0o700)
    for name in ("authorized", "unauthorized", "agent"):
        run_checked(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"xaios-freebsd-{name}",
                "-f",
                str(key_dir / name),
            ],
            30,
        )
    client_passphrase = "XAIOS-client-test-passphrase"
    run_checked(
        [
            "ssh-keygen", "-q", "-t", "ed25519", "-a", "1",
            "-N", client_passphrase,
            "-C", "xaios-outbound-client", "-f", str(key_dir / "outbound")
        ],
        30,
    )
    client_passphrase_file = work / "identity-passphrase"
    client_passphrase_file.write_text(client_passphrase + "\n", encoding="ascii")
    client_passphrase_file.chmod(0o600)
    server_password = "Xf" + secrets.token_hex(16)
    password_file = work / "freebsd-password"
    password_file.write_text(server_password + "\n", encoding="ascii")
    password_file.chmod(0o600)

    xaios_authorized_keys = work / "xaios-authorized-keys"
    xaios_authorized_keys.write_text(
        (key_dir / "authorized.pub").read_text(encoding="ascii")
        + (key_dir / "outbound.pub").read_text(encoding="ascii"),
        encoding="ascii",
    )
    xaios_authorized_keys.chmod(0o600)

    base_image, image_sha256, archive_identity = prepare_freebsd_image(
        client_architecture)
    seed_dir = work / "cidata"
    seed_dir.mkdir()
    (seed_dir / "meta-data").write_text(
        "instance-id: xaios-freebsd-bidirectional\n"
        "local-hostname: xaios-freebsd-server\n",
        encoding="ascii",
    )
    (seed_dir / "user-data").write_text(
        user_data(
            (key_dir / "authorized").read_text(encoding="ascii"),
            (key_dir / "unauthorized").read_text(encoding="ascii"),
            (key_dir / "outbound.pub").read_text(encoding="ascii")
            + (key_dir / "authorized.pub").read_text(encoding="ascii")
            + (key_dir / "agent.pub").read_text(encoding="ascii"),
            server_password,
            architecture,
        ),
        encoding="ascii",
    )
    seed_iso = work / "cidata.iso"
    iso_tool = create_seed_iso(seed_dir, seed_iso)

    run_checked(
        [
            "docker",
            "build",
            "--pull",
            "--file",
            "tests/network/Dockerfile.freebsd-qemu",
            "--tag",
            DOCKER_IMAGE,
            ".",
        ],
        900,
    )

    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(xaios_authorized_keys)
    build_env["XAIOS_SSH_CLIENT_IDENTITY_FILE"] = str(key_dir / "outbound")
    build_env.pop("XAIOS_SSH_USERS_FILE", None)
    build_env["XAIOS_SSH_PASSWORD_AUTH"] = "0"
    # Keep kernel logging on the serial console for the whole run. The guest
    # already reports why a filesystem write failed, but a non-verbose build
    # silences klog once boot finishes, so the captured evidence stopped at the
    # login prompt and every failure here had to be re-diagnosed blind.
    build_env.setdefault("XAIOS_BOOT_VERBOSE", "1")
    for command in XAIOS_MACHINES[architecture]["build"]:
        run_checked(command, smoke_timeout(architecture, 360),
                    {**build_env, **XAIOS_MACHINES[architecture]["env"]})

    xaios_ssh_port = reserve_port(socket.SOCK_STREAM)
    xaios_udp_port = reserve_port(socket.SOCK_DGRAM)
    freebsd_ssh_port = reserve_port(socket.SOCK_STREAM)
    xaios_log = BUILD / f"qemu-freebsd-bidirectional-xaios-{architecture}.log"
    freebsd_log = BUILD / f"qemu-freebsd-docker-{architecture}.log"
    xaios_env = build_env.copy()
    machine = XAIOS_MACHINES[architecture]
    xaios_env.update({
        machine["ssh_port"]: str(xaios_ssh_port),
        machine["udp_port"]: str(xaios_udp_port),
    })
    xaios_log.unlink(missing_ok=True)
    if machine["log"] is not None:
        # This board's runner writes the console to a file of its own, and
        # this suite watches the console for readiness and for evidence.
        xaios_env[machine["log"]] = str(xaios_log)
        xaios_log_file = open(os.devnull, "wb")
    else:
        xaios_log_file = xaios_log.open("wb")
    xaios = xaios_process(architecture, xaios_env, xaios_log_file)
    container_name = f"xaios-freebsd-{architecture}-{os.getpid()}"
    freebsd: subprocess.Popen[bytes] | None = None
    freebsd_log_file = None
    try:
        wait_for_marker(xaios_log, (XAIOS_READY,),
                        smoke_timeout(architecture, 240))
        freebsd_log_file = freebsd_log.open("wb")
        command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--add-host",
            "host.docker.internal:host-gateway",
            "--publish",
            f"{freebsd_ssh_port}:2222/tcp",
            "--volume",
            f"{base_image}:/images/freebsd.qcow2:ro",
            "--volume",
            f"{seed_iso}:/seed/cidata.iso:ro",
            "--volume",
            f"{work}:/work",
            "--env",
            f"XAIOS_FREEBSD_ARCH={client_architecture}",
            "--env",
            f"XAIOS_RELAY_SSH_PORT={xaios_ssh_port}",
            "--env",
            f"XAIOS_RELAY_UDP_PORT={xaios_udp_port}",
            DOCKER_IMAGE,
        ]
        print("+", " ".join(command), flush=True)
        freebsd = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=freebsd_log_file,
            stderr=subprocess.STDOUT,
        )
        server_marker = wait_for_marker(
            freebsd_log,
            (SERVER_READY, CLIENT_FAIL),
            float(os.environ.get("XAIOS_FREEBSD_TIMEOUT", "1200")),
        )
        if server_marker != SERVER_READY:
            raise RuntimeError("FreeBSD server provisioning failed")
        # ProxyJump reuses this path in a child command without shell quoting.
        jump_config = Path("/tmp") / f"xaios-jump-{os.getpid()}-{architecture}.conf"
        jump_config.write_text(
            "Host xaios-jump\n"
            "  HostName 127.0.0.1\n"
            f"  Port {xaios_ssh_port}\n"
            "  User admin\n"
            f'  IdentityFile "{key_dir / "authorized"}"\n'
            "  IdentitiesOnly yes\n"
            "  StrictHostKeyChecking no\n"
            "  UserKnownHostsFile /dev/null\n"
            "Host freebsd-via-xaios\n"
            "  HostName 10.0.2.2\n"
            f"  Port {freebsd_ssh_port}\n"
            "  User xaios\n"
            f'  IdentityFile "{key_dir / "authorized"}"\n'
            "  IdentitiesOnly yes\n"
            "  StrictHostKeyChecking no\n"
            "  UserKnownHostsFile /dev/null\n"
            "  ProxyJump xaios-jump\n",
            encoding="ascii",
        )
        jump = subprocess.run(
            ["ssh", "-F", str(jump_config), "freebsd-via-xaios",
             "printf", "xaios-jump-host-ok"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        jump_config.unlink(missing_ok=True)
        if jump.returncode != 0 or jump.stdout != "xaios-jump-host-ok":
            raise RuntimeError(
                "XAIOS direct-tcpip jump-host test failed\n"
                + jump.stdout + jump.stderr
            )
        run_checked(
            [
                sys.executable,
                str(ROOT / "tests" / "network" / "xaios-outbound-client.py"),
                "--xaios-port",
                str(xaios_ssh_port),
                "--xaios-key",
                str(key_dir / "authorized"),
                "--target-port",
                str(freebsd_ssh_port),
                "--jump-port",
                str(freebsd_ssh_port),
                "--password-file",
                str(password_file),
                "--identity-passphrase-file",
                str(client_passphrase_file),
                "--transcript",
                str(work / "xaios-outbound-client.log"),
                "--timeout",
                os.environ.get(
                    "XAIOS_OUTBOUND_TIMEOUT",
                    default_outbound_timeout(architecture),
                ),
            ],
            900,
        )
        agent_start = subprocess.run(
            ["ssh-agent", "-s"], check=True, capture_output=True, text=True,
            timeout=30,
        )
        agent_env = os.environ.copy()
        for name in ("SSH_AUTH_SOCK", "SSH_AGENT_PID"):
            match = re.search(rf"{name}=([^;]+);", agent_start.stdout)
            if match is None:
                raise RuntimeError(f"ssh-agent did not report {name}")
            agent_env[name] = match.group(1)
        try:
            run_checked(["ssh-add", str(key_dir / "agent")], 30, agent_env)
            agent_command = [
                "ssh", "-A", "-o", "IdentitiesOnly=yes",
                "-o", "PreferredAuthentications=publickey",
                "-o", "PubkeyAuthentication=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-i", str(key_dir / "authorized"), "-p",
                str(xaios_ssh_port), "admin@127.0.0.1",
                f"ssh -A -p {freebsd_ssh_port} xaios@10.0.2.2 "
                "printf xaios-agent-forwarding-ok",
            ]
            try:
                agent = subprocess.run(
                    agent_command, cwd=ROOT, env=agent_env, check=False,
                    capture_output=True, text=True, timeout=60,
                )
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout or ""
                stderr = error.stderr or ""
                if isinstance(stdout, bytes):
                    stdout = stdout.decode(errors="replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode(errors="replace")
                raise RuntimeError(
                    "XAIOS OpenSSH agent-forwarding test timed out\n"
                    + stdout + stderr
                ) from error
            if (agent.returncode != 0 or
                    "xaios-agent-forwarding-ok" not in agent.stdout):
                raise RuntimeError(
                    "XAIOS OpenSSH agent-forwarding test failed\n"
                    + agent.stdout + agent.stderr
                )
        finally:
            subprocess.run(["ssh-agent", "-k"], env=agent_env, check=False,
                           capture_output=True, timeout=30)
        marker = wait_for_marker(
            freebsd_log,
            (CLIENT_PASS, CLIENT_FAIL),
            float(os.environ.get("XAIOS_FREEBSD_TIMEOUT", "1200")),
        )
        if marker != CLIENT_PASS:
            tail = "\n".join(freebsd_log.read_text(errors="replace").splitlines()[-120:])
            raise RuntimeError(f"FreeBSD client suite failed\n{tail}")
        if xaios.poll() is not None:
            raise RuntimeError(f"XAIOS exited unexpectedly: {xaios.returncode}")
        if freebsd.poll() is not None:
            raise RuntimeError(f"FreeBSD container exited unexpectedly: {freebsd.returncode}")

        report = {
            "schema": "xaios.qemu.freebsd_bidirectional.v1",
            "status": "pass",
            "xaios_architecture": architecture,
            "freebsd_release": FREEBSD_RELEASE,
            "freebsd_architecture": (
                "arm64" if client_architecture == "aarch64" else "amd64"
            ),
            "freebsd_architecture_note":
                "the FreeBSD end runs on whichever architecture is native to "
                "this host, which is not necessarily XAIOS's. What is under "
                "test is XAIOS answering and dialling a third-party stack in "
                "both directions; OpenSSH on FreeBSD does not behave "
                "differently per instruction set, and emulating a foreign "
                "FreeBSD would measure FreeBSD's port rather than this one.",
            "freebsd_image": IMAGES[client_architecture]["name"],
            "freebsd_archive_sha256": archive_identity,
            "freebsd_image_sha256": image_sha256,
            "freebsd_runtime": "QEMU TCG inside Debian 13 Docker",
            "seed_tool": iso_tool,
            "checks": {
        "freebsd_to_xaios_ssh": "passed",
        "freebsd_to_xaios_mlkem768x25519": "passed",
                "freebsd_to_xaios_pty": "passed",
                "freebsd_to_xaios_unauthorized_key_rejection": "passed",
                "freebsd_to_xaios_sftp": "passed",
                "freebsd_to_xaios_scp": "passed",
                "xaios_direct_tcpip_jump_host": "passed",
                "xaios_openssh_agent_forwarding": "passed",
                "freebsd_to_xaios_udp": "passed",
                "xaios_to_freebsd_ssh": "passed",
                "xaios_to_freebsd_ipv6_ssh": "passed",
                "xaios_to_freebsd_encrypted_ed25519_key": "passed",
                "xaios_to_freebsd_wrong_password_rejection": "passed",
                "xaios_to_freebsd_scp_file": "passed",
                "xaios_to_freebsd_scp_recursive_upload": "passed",
                "xaios_to_freebsd_scp_recursive_download": "passed",
                "xaios_freebsd_known_host_persistence": "passed",
                "xaios_outbound_proxyjump_invalid_spec_rejection": "passed",
                "xaios_outbound_proxyjump_to_xaios": "passed",
            },
        }
        report_path = BUILD / f"qemu-freebsd-bidirectional-{architecture}.json"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"PASS: FreeBSD bidirectional suite ({report_path})")
        return 0
    finally:
        if freebsd is not None and freebsd.poll() is None:
            subprocess.run(
                ["docker", "stop", "--time", "10", container_name],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            try:
                freebsd.wait(timeout=15)
            except subprocess.TimeoutExpired:
                freebsd.kill()
                freebsd.wait(timeout=5)
        if freebsd_log_file is not None:
            freebsd_log_file.close()
        stop_process(xaios)
        xaios_log_file.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
