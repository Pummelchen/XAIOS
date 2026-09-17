#!/usr/bin/env python3
"""Run the Linux/OpenSSH cross-client gate from Debian 13 against XAIOS."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from qemu_docker_network_harness import (
    ARTIFACT_SUFFIX, BUILD, CLIENT_TIMEOUT_SECONDS, IMAGE, ROOT, SSH_READY_MARKER,
    TARGET_ARCH, build_image, create_xaiboot_fs_fixture, docker_command,
    ed25519_raw_fingerprint, prepare_docker_client, prepare_xaiboot_fs_v5_scale,
    require_rejected_build, run_checked, start_qemu_ready, stop_qemu,
    verify_xaiboot_fs_v5_scale_after_reboot, wait_for_log_quiescence,
)
from qemu_docker_network_xtop import scan_host_key, verify_native_xtop_pty


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    version = prepare_docker_client()

    BUILD.mkdir(parents=True, exist_ok=True)
    key_dir = BUILD / "qemu-network-keys"
    if key_dir.exists():
        shutil.rmtree(key_dir)
    key_dir.mkdir(mode=0o700)
    for name in ("authorized", "unauthorized", "observer", "operator"):
        run_checked(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"xaios-{name}-fixture",
                "-f",
                str(key_dir / name),
            ],
            30,
        )
    (key_dir / "operator.fingerprint").write_text(
        ed25519_raw_fingerprint(key_dir / "operator.pub") + "\n",
        encoding="ascii",
    )
    (key_dir / "config-high.conf").write_text(
        "schema=xaios.config.v1\n"
        "ssh.max_connections=32\n"
        "ssh.max_channels_per_connection=2\n"
        "ssh.max_auth_attempts=5\n"
        "ssh.command_rate_per_minute=120\n"
        "ssh.password_auth=development\n",
        encoding="ascii",
    )
    (key_dir / "config-low.conf").write_text(
        "schema=xaios.config.v1\n"
        "ssh.max_connections=32\n"
        "ssh.max_channels_per_connection=2\n"
        "ssh.max_auth_attempts=5\n"
        "ssh.command_rate_per_minute=2\n"
        "ssh.password_auth=development\n",
        encoding="ascii",
    )
    (key_dir / "config-invalid.conf").write_text(
        "schema=xaios.config.v1\n"
        "ssh.max_connections=33\n"
        "ssh.max_channels_per_connection=2\n"
        "ssh.max_auth_attempts=5\n"
        "ssh.command_rate_per_minute=120\n"
        "ssh.password_auth=development\n",
        encoding="ascii",
    )
    password_file = key_dir / "password"
    password_file.write_text("admin\n", encoding="ascii")
    password_file.chmod(0o600)
    users_file = key_dir / "sshd-users"
    run_checked(
        [
            sys.executable,
            "scripts/create-sshd-user-config.py",
            "--password-file",
            str(password_file),
            "--output",
            str(users_file),
            "--iterations",
            "100000",
        ],
        30,
    )
    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    build_env["XAIOS_SSH_USERS_FILE"] = str(users_file)
    build_env["XAIOS_SSH_PASSWORD_AUTH"] = "1"
    build_env["XAIOS_FAILURE_TEST_APP"] = "1"
    build_env["XAIOS_BOOT_VERBOSE"] = "1"
    missing_opt_in_env = build_env.copy()
    missing_opt_in_env.pop("XAIOS_SSH_PASSWORD_AUTH")
    require_rejected_build(
        missing_opt_in_env,
        "password credentials require XAIOS_SSH_PASSWORD_AUTH=1",
    )
    release_env = build_env.copy()
    release_env["XAIOS_BUILD_MODE"] = "release"
    # The rule is now narrower and the message with it: a release image may
    # carry the password code, because setup needs it to make an account, but
    # must not package a credential every copy of the download would share.
    require_rejected_build(
        release_env, "a release image must not package a password credential"
    )
    build_image(180, build_env)

    results: dict[str, object] = {
        "architecture": TARGET_ARCH,
        "debian_version": version,
        "image": IMAGE,
    }

    for source_version in (3, 4):
        migration_path = BUILD / (
            f"qemu-mutable-fs-v{source_version}-migration{ARTIFACT_SUFFIX}.img"
        )
        migration_payload = create_xaiboot_fs_fixture(migration_path, source_version)
        migration_port = reserve_port(socket.SOCK_STREAM)
        migration_qemu, migration_log, _, _ = start_qemu_ready(
            f"qemu-mutable-fs-v{source_version}-migration" + ARTIFACT_SUFFIX,
            {"XAIOS_QEMU_HOSTFWD_PORT": str(migration_port)},
            SSH_READY_MARKER,
            persistent_path=migration_path,
            reset_persistent=False,
        )
        try:
            migrated = subprocess.run(
                docker_command(
                    key_dir,
                    "ssh",
                    "-i", "/keys/authorized",
                    "-o", "IdentitiesOnly=yes",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "PasswordAuthentication=no",
                    "-p", str(migration_port),
                    "admin@host.docker.internal",
                    "cat /tmp/migration.txt",
                ),
                cwd=ROOT,
                capture_output=True,
                timeout=60,
            )
            if migrated.returncode != 0 or migrated.stdout != migration_payload:
                raise RuntimeError(
                    f"xaibootFS v{source_version} migration did not preserve "
                    "file data: "
                    + (migrated.stdout + migrated.stderr).decode(errors="replace")
                )
        finally:
            stop_qemu(migration_qemu)
            migration_log.close()
        with migration_path.open("rb") as fixture:
            fixture.seek(3072 * 512 + 8)
            migrated_version = int.from_bytes(fixture.read(4), "little")
        if migrated_version != 5:
            raise RuntimeError(
                f"xaibootFS v{source_version} migration did not publish v5 "
                f"metadata: {migrated_version}"
            )
        migration_path.unlink(missing_ok=True)
        results[f"xaiboot_fs_v{source_version}_to_v5_migration"] = "passed"

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    packet_capture = BUILD / f"qemu-docker-network-suite{ARTIFACT_SUFFIX}.pcap"
    packet_capture.unlink(missing_ok=True)
    qemu, log_file, log_path, persistent_path = start_qemu_ready(
        "qemu-docker-network-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port),
            "XAIOS_QEMU_HOSTFWD_UDP_PORT": str(udp_port),
            "XAIOS_QEMU_NET_DUMP": str(packet_capture),
        },
        SSH_READY_MARKER,
    )
    try:
        initial_host_key = scan_host_key(key_dir, ssh_port)
        run_checked(
            docker_command(
                key_dir,
                "/usr/local/bin/xaios-network-client-suite",
                "host.docker.internal",
                str(ssh_port),
                str(udp_port),
                TARGET_ARCH,
            ),
            CLIENT_TIMEOUT_SECONDS,
        )
        verify_native_xtop_pty(key_dir, ssh_port)
        run_checked(
            docker_command(
                key_dir,
                "/usr/local/bin/xaios-phase2-client-suite",
                "host.docker.internal",
                str(ssh_port),
            ),
            CLIENT_TIMEOUT_SECONDS,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv4_ssh_sftp_udp"] = "passed"
        results["standalone_utility_apps"] = "passed"
        results["archive_interoperability"] = "passed"
        results["xaiosctl_control_surface"] = "passed"
        results["sftp_file_directory_operations"] = "passed"
        results["ssh_rekey"] = "passed"
        results["ssh_shared_transport_channels"] = "passed"
        results["native_xtop_pty_ansi"] = "passed"
        results["native_xtop_shell_restore"] = "passed"
        results["native_xtop_non_pty_plain"] = "passed"
        results["native_xtop_invalid_option_rejected"] = "passed"
        results["native_pong_pty"] = "passed"
        results["native_transient_apps_on_demand"] = "passed"
        results["native_user_fault_isolation"] = "passed"
        results["ssh_port"] = ssh_port
        results["udp_port"] = udp_port
        results["packet_capture"] = str(packet_capture)
        rotated_host_key = scan_host_key(key_dir, ssh_port)
        if initial_host_key == rotated_host_key:
            raise RuntimeError("SSH host-key rotation did not change the public key")
        results["public_key_auth"] = "passed"
        results["phase2_admin_control"] = "passed"
        results["role_authorization"] = "passed"
        results["config_transaction_rollback"] = "passed"
        results["key_revocation"] = "passed"
        results["host_key_rotation"] = "passed"
        results["sensitive_state_remote_denial"] = "passed"
        results["log_secret_redaction"] = "passed"
        results["password_build_profiles"] = "passed"
        results["xaiboot_fs_v5_scale"] = prepare_xaiboot_fs_v5_scale(
            key_dir, ssh_port
        )
    finally:
        if qemu.poll() is None:
            wait_for_log_quiescence(log_path)
        stop_qemu(qemu)
        log_file.close()

    reboot_qemu, reboot_log_file, reboot_log_path, _ = start_qemu_ready(
        "qemu-docker-network-reboot",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port)},
        SSH_READY_MARKER,
        persistent_path=persistent_path,
        reset_persistent=False,
    )
    try:
        second_host_key = scan_host_key(key_dir, ssh_port)
        if rotated_host_key != second_host_key:
            raise RuntimeError("rotated SSH host key changed across persistent reboot")
        run_checked(
            docker_command(
                key_dir,
                "ssh",
                "-i",
                "/keys/authorized",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                str(ssh_port),
                "admin@host.docker.internal",
                "echo host-key-persisted",
            ),
            60,
        )
        observer_config = subprocess.run(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/observer",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PasswordAuthentication=no",
                "-p", str(ssh_port),
                "admin@host.docker.internal",
                "xaiosctl config show --json",
            ),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout
        config_data = json.loads(observer_config)["data"]
        if config_data["command_rate_per_minute"] != 120:
            raise RuntimeError("applied config did not persist across reboot")
        revoked_attempt = subprocess.run(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/operator",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PasswordAuthentication=no",
                "-o", "BatchMode=yes",
                "-p", str(ssh_port),
                "admin@host.docker.internal",
                "xaiosctl status --json",
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if revoked_attempt.returncode == 0:
            raise RuntimeError("revoked operator key became valid after reboot")
        verify_xaiboot_fs_v5_scale_after_reboot(
            key_dir, ssh_port, results["xaiboot_fs_v5_scale"]
        )
        results["host_key_persistence"] = "passed"
        results["admin_state_persistence"] = "passed"
        results["xaiboot_fs_v5_reboot_persistence"] = "passed"
    finally:
        stop_qemu(reboot_qemu)
        reboot_log_file.close()
        persistent_path.unlink(missing_ok=True)

    socket_port = reserve_port(socket.SOCK_STREAM)
    ipv6_ssh_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, ipv6_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-ipv6-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(ipv6_ssh_port),
            "XAIOS_QEMU_NET_SOCKET_HOST": "0.0.0.0",
            "XAIOS_QEMU_NET_SOCKET_PORT": str(socket_port),
        },
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "python3",
                "/usr/local/bin/xaios-ipv6-tcp-client",
                "--host",
                "host.docker.internal",
                "--port",
                str(socket_port),
                "--timeout",
                "30",
            ),
            60,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"IPv6 QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv6_tcp"] = "passed"
        results["tcp_invalid_reset_rejection"] = "passed"
        results["socket_port"] = socket_port
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    no_rng_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, no_rng_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-no-rng-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(no_rng_port),
            "XAIOS_QEMU_RNG": "none",
        },
        "SSH server: not running error=2001",
    )
    try:
        banner = b""
        try:
            with socket.create_connection(
                ("127.0.0.1", no_rng_port), timeout=5
            ) as client:
                client.settimeout(3)
                banner = client.recv(128)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            pass
        if banner.startswith(b"SSH-"):
            raise RuntimeError("sshd exposed an SSH banner without secure entropy")
        results["entropy_fail_closed"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    key_only_env = os.environ.copy()
    key_only_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    key_only_env["XAIOS_BOOT_VERBOSE"] = "1"
    key_only_env.pop("XAIOS_SSH_USERS_FILE", None)
    key_only_env["XAIOS_SSH_PASSWORD_AUTH"] = "0"
    build_image(180, key_only_env)
    key_only_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, key_only_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-key-only-suite",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(key_only_port)},
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/authorized",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(key_only_port),
                "admin@host.docker.internal",
                "echo key-only-auth-ok",
            ),
            60,
        )
        password_attempt = subprocess.run(
            docker_command(
                key_dir,
                "sshpass", "-p", "admin",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-p", str(key_only_port),
                "admin@host.docker.internal",
                "true",
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if password_attempt.returncode == 0:
            raise RuntimeError("default image accepted an unprovisioned password")
        results["password_default_disabled"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    invalid_users = key_dir / "invalid-sshd-users"
    invalid_users.write_text("admin:plaintext:admin\n", encoding="ascii")
    invalid_env = key_only_env.copy()
    invalid_env["XAIOS_SSH_USERS_FILE"] = str(invalid_users)
    invalid_env["XAIOS_SSH_PASSWORD_AUTH"] = "1"
    build_image(180, invalid_env)
    invalid_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, invalid_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-invalid-users-suite",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(invalid_port)},
        "SSH server: not running error=2202",
    )
    try:
        banner = b""
        try:
            with socket.create_connection(("127.0.0.1", invalid_port), timeout=5) as client:
                client.settimeout(3)
                banner = client.recv(128)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            pass
        if banner.startswith(b"SSH-"):
            raise RuntimeError("sshd exposed a banner with malformed credentials")
        results["malformed_credentials_fail_closed"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    report_path = BUILD / f"qemu-docker-network-suite{ARTIFACT_SUFFIX}.json"
    report_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(key_dir)
    print(f"PASS: Docker network suite report: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
