#!/usr/bin/env python3
"""Exercise resumable xaiFS SFTP against one real XAIOS QEMU guest.

The machine-facing plumbing lives in `qemu_model_sftp_gate_lib.py` and the
package manifest and registration helpers in
`qemu_model_sftp_package_lib.py`; this file keeps the command line, the
scenario order and the report.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

from qemu_model_sftp_gate_lib import (
    ARCH,
    BUILD,
    MODEL_CHUNK_SIZE,
    ROOT,
    SUFFIX,
    qemu_boot_environment,
    reserve_port,
    run_parallel_sftp,
    run_sftp,
    run_ssh,
    run_ssh_json,
    smoke_timeout,
    start_qemu_ready,
    stop_process,
    wait_for_ssh,
    write_fixture,
)
from qemu_model_sftp_package_lib import (
    dynamic_manifest,
    register_command,
    staging_path,
)


def main() -> int:
    for tool in ("docker", "ssh-keygen", "ssh-keyscan", "sftp"):
        if shutil.which(tool) is None:
            raise SystemExit(f"error: required client tool not found: {tool}")

    subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"],
        cwd=ROOT,
        check=True,
        timeout=30,
    )
    subprocess.run(
        [
            "docker",
            "build",
            "--file",
            "tests/network/Dockerfile.debian13",
            "--tag",
            "xaios-debian13-network-client:13",
            ".",
        ],
        cwd=ROOT,
        check=True,
        timeout=300,
    )
    debian_version = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "xaios-debian13-network-client:13",
            "sh",
            "-c",
            ". /etc/os-release; printf '%s' \"$VERSION_ID\"",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        timeout=30,
    ).stdout
    if not debian_version.startswith("13"):
        raise RuntimeError(f"expected Debian 13 client, got {debian_version!r}")

    BUILD.mkdir(parents=True, exist_ok=True)
    gate_dir = BUILD / f"qemu-model-sftp{SUFFIX}"
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(mode=0o700)
    key = gate_dir / "admin"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "xaios-model-sftp-gate",
            "-f",
            str(key),
        ],
        cwd=ROOT,
        check=True,
        timeout=30,
    )

    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key.with_suffix(".pub"))
    build_commands = {
        "aarch64": [["make", "image-qemu-test"]],
        "x86_64": [["make", "image-x86_64-qemu-test"]],
        "riscv64": [["./scripts/build-riscv64.sh"],
                    ["./scripts/build-riscv64-image.sh"]],
    }[ARCH]
    for command in build_commands:
        subprocess.run(command, cwd=ROOT, env=build_env, check=True,
                       timeout=smoke_timeout(ARCH, 180))

    source = gate_dir / "model.package"
    partial = gate_dir / "model.partial"
    downloaded = gate_dir / "model.downloaded"
    active_download = gate_dir / "model.active-download"
    write_fixture(source)
    with source.open("rb") as stream:
        partial.write_bytes(stream.read(2 * 1024 * 1024))
    remote_path = staging_path(source)
    source_arg = source.relative_to(ROOT)
    partial_arg = partial.relative_to(ROOT)
    downloaded_arg = downloaded.relative_to(ROOT)
    active_download_arg = active_download.relative_to(ROOT)

    mac_source = gate_dir / "dynamic-macos.package"
    debian_source = gate_dir / "dynamic-debian.package"
    cleanup_source = gate_dir / "dynamic-cleanup.package"
    reuse_source = gate_dir / "dynamic-reuse.package"
    mac_download = gate_dir / "dynamic-macos.download"
    debian_download = gate_dir / "dynamic-debian.download"
    # Each concurrent transfer crosses a verification-chunk boundary without
    # turning TCG throughput into the acceptance criterion.
    write_fixture(mac_source, MODEL_CHUNK_SIZE + 64 * 1024, 17)
    write_fixture(debian_source, MODEL_CHUNK_SIZE + 128 * 1024, 23)
    write_fixture(cleanup_source, 4 * 1024 * 1024 + 64 * 1024, 29)
    write_fixture(reuse_source, cleanup_source.stat().st_size, 31)
    cleanup_partial = gate_dir / "dynamic-cleanup.partial"
    with cleanup_source.open("rb") as stream:
        cleanup_partial.write_bytes(stream.read(1024 * 1024))
    mac_manifest = dynamic_manifest(mac_source, "macos", 7)
    debian_manifest = dynamic_manifest(debian_source, "debian", 13)
    cleanup_manifest = dynamic_manifest(cleanup_source, "cleanup", 19)
    reuse_manifest = dynamic_manifest(reuse_source, "reuse", 23)

    port = reserve_port()
    persistent = gate_dir / "persistent.img"
    log_path = BUILD / f"qemu-model-sftp-gate{SUFFIX}.log"
    models_volume = gate_dir / "models.img"
    shutil.copyfile(BUILD / ("xaios-x86-xaifs.img" if ARCH == "x86_64"
                             else "xaios-xaifs.img"), models_volume)
    qemu_env = qemu_boot_environment(
        ARCH, os.environ.copy(),
        accel="tcg", smp=4, hostfwd_port=port, persistent=persistent,
        state_dir=gate_dir / "state", model_discard="unmap",
        # Its own copy of the model volume, not the one in build/.
        #
        # This gate uploads models, registers them and deletes them, so the
        # volume it finishes with is not the signed fixture it started from --
        # and without this it was writing into build/xaios-xaifs.img, which
        # every other gate mounts read-only expecting exactly that fixture.
        # The next smoke run then failed on the xaiFS self-test marker, on a
        # different architecture, for a reason nothing in it had caused.
        xai_fs=models_volume,
        # The console is redirected into log_path, and the RISC-V runner
        # writes it to a file of its own unless told otherwise.
        serial_to_stdout=True)
    qemu, log_file = start_qemu_ready(log_path, qemu_env)
    try:
        wait_for_ssh(port, qemu, float(smoke_timeout(ARCH, 120)))
        first = run_sftp(
            key,
            port,
            f"put {partial_arg} {remote_path}\nls -l {remote_path}\n",
        )
        if not re.search(r"(?:^|\s)2097152(?:\s|$)", first):
            raise RuntimeError(
                f"staging prefix was not committed at 2 MiB: {first!r}"
            )

        devices = run_ssh_json(
            key, port, "xaiosctl storage device list --json"
        )
        model_devices = [
            device
            for device in devices.get("devices", [])
            if device.get("identifier") == "/dev/vblk4"
        ]
        if len(model_devices) != 1:
            raise RuntimeError(
                f"storage inventory does not identify xaiFS device: {devices!r}"
            )
        model_device = run_ssh_json(
            key, port, "xaiosctl storage device show /dev/vblk4 --json"
        )
        records = model_device.get("devices", [])
        if (
            len(records) != 1
            or records[0].get("logical_sector_size") != 512
            or records[0].get("capacity_bytes", 0) <= source.stat().st_size
            or records[0].get("read_only") != 0
            or records[0].get("discard_supported") != 1
        ):
            raise RuntimeError(
                f"xaiFS block geometry/capabilities are invalid: {model_device!r}"
            )
        filesystems = run_ssh_json(
            key, port, "xaiosctl storage filesystem list --json"
        )
        mounts = {
            record.get("mount_path"): record
            for record in filesystems.get("filesystems", [])
        }
        if (
            mounts.get("/", {}).get("filesystem") != "xaibootFS"
            or mounts.get("/models", {}).get("filesystem") != "xaiFS"
            or mounts.get("/models", {}).get("device_identifier")
            != "/dev/vblk4"
            or mounts.get("/models", {}).get("staging_writable") != 1
        ):
            raise RuntimeError(
                f"storage mount inventory is inconsistent: {filesystems!r}"
            )
        initial_models = mounts["/models"]

        resumed = run_sftp(
            key,
            port,
            f"reput {source_arg} {remote_path}\n"
            f"ls -l {remote_path}\n"
            f"get {remote_path} {downloaded_arg}\n",
        )
        if not re.search(r"(?:^|\s)2162688(?:\s|$)", resumed):
            raise RuntimeError(
                f"resumed staging package has wrong size: {resumed!r}"
            )
        if source.read_bytes() != downloaded.read_bytes():
            raise RuntimeError("resumed xaiFS SFTP payload mismatch")

        package_id = remote_path.rsplit("/", 1)[1]
        verified = run_ssh(
            key, port, f"xaiosctl model verify {package_id}"
        )
        if "generation=10" not in verified or "changed=0" not in verified:
            raise RuntimeError(f"unexpected model verify response: {verified!r}")
        activated = run_ssh(
            key,
            port,
            f"xaiosctl model activate {package_id} --operation-id 9001",
        )
        if "generation=11" not in activated or "changed=1" not in activated:
            raise RuntimeError(
                f"unexpected model activation response: {activated!r}"
            )
        audit = run_ssh(key, port, "xaiosctl audit show --since 0 --limit 16")
        if "operation=model.package.activate" not in audit:
            raise RuntimeError("model activation is absent from the audit log")
        active_path = f"/models/{package_id}"
        active = run_sftp(
            key,
            port,
            f"ls -l {active_path}\n"
            f"get {active_path} {active_download_arg}\n",
        )
        if not re.search(r"(?:^|\s)2162688(?:\s|$)", active):
            raise RuntimeError(f"active package has wrong size: {active!r}")
        if source.read_bytes() != active_download.read_bytes():
            raise RuntimeError("activated xaiFS payload mismatch")
        usage = run_ssh_json(
            key, port, "xaiosctl storage usage /models --json"
        )
        usage_records = usage.get("filesystems", [])
        if (
            len(usage_records) != 1
            or usage_records[0].get("mount_path") != "/models"
            or usage_records[0].get("format_version") != 1
            or usage_records[0].get("active_packages")
            != initial_models.get("active_packages", 0) + 1
            or usage_records[0].get("staging_packages", 0) + 1
            != initial_models.get("staging_packages")
            or usage_records[0].get("package_count")
            != initial_models.get("package_count")
            or usage_records[0].get("allocated_bytes", 0)
            > usage_records[0].get("total_bytes", 0)
        ):
            raise RuntimeError(f"activated xaiFS usage is invalid: {usage!r}")

        for manifest, operation_id in (
            (mac_manifest, 9101),
            (debian_manifest, 9102),
        ):
            registered = run_ssh_json(
                key, port, register_command(manifest, operation_id)
            )
            if registered.get("changed") != 1:
                raise RuntimeError(f"dynamic registration failed: {registered!r}")

        mac_remote = f"/models/.staging/{mac_manifest.package_id.hex()}"
        debian_remote = f"/models/.staging/{debian_manifest.package_id.hex()}"
        run_parallel_sftp(
            gate_dir,
            key,
            port,
            f"put {mac_source.relative_to(ROOT)} {mac_remote}\n",
            f"put /work/{debian_source.name} {debian_remote}\n",
        )
        for manifest, operation_id in (
            (mac_manifest, 9201),
            (debian_manifest, 9202),
        ):
            package = manifest.package_id.hex()
            verified_dynamic = run_ssh_json(
                key, port, f"xaiosctl model verify {package} --json"
            )
            if not isinstance(verified_dynamic.get("generation"), int):
                raise RuntimeError(
                    f"dynamic package verification failed: {verified_dynamic!r}"
                )
            activated_dynamic = run_ssh_json(
                key,
                port,
                f"xaiosctl model activate {package} "
                f"--operation-id {operation_id} --json",
            )
            if activated_dynamic.get("changed") != 1:
                raise RuntimeError(
                    f"dynamic package activation failed: {activated_dynamic!r}"
                )

        run_parallel_sftp(
            gate_dir,
            key,
            port,
            f"get /models/{mac_manifest.package_id.hex()} "
            f"{mac_download.relative_to(ROOT)}\n",
            f"get /models/{debian_manifest.package_id.hex()} "
            f"/work/{debian_download.name}\n",
        )
        if mac_source.read_bytes() != mac_download.read_bytes():
            raise RuntimeError("concurrent macOS xaiFS download mismatch")
        if debian_source.read_bytes() != debian_download.read_bytes():
            raise RuntimeError("concurrent Debian xaiFS download mismatch")

        cleanup_registered = run_ssh_json(
            key, port, register_command(cleanup_manifest, 9301)
        )
        if cleanup_registered.get("changed") != 1:
            raise RuntimeError(f"cleanup fixture registration failed: {cleanup_registered!r}")
        cleanup_remote = (
            f"/models/.staging/{cleanup_manifest.package_id.hex()}"
        )
        run_sftp(
            key,
            port,
            f"put {cleanup_partial.relative_to(ROOT)} {cleanup_remote}\n",
        )
        cleaned = run_ssh_json(
            key,
            port,
            f"xaiosctl model cleanup {cleanup_manifest.package_id.hex()} "
            "--operation-id 9302 --json",
        )
        if (
            cleaned.get("changed") != 1
            or cleaned.get("reclaimed_bytes") != cleanup_source.stat().st_size
        ):
            raise RuntimeError(f"staging cleanup did not reclaim its extent: {cleaned!r}")

        reused = run_ssh_json(key, port, register_command(reuse_manifest, 9303))
        if reused.get("changed") != 1:
            raise RuntimeError(f"free-extent reuse registration failed: {reused!r}")
        reused_cleanup = run_ssh_json(
            key,
            port,
            f"xaiosctl model cleanup {reuse_manifest.package_id.hex()} "
            "--operation-id 9304 --json",
        )
        if reused_cleanup.get("reclaimed_bytes") != reuse_source.stat().st_size:
            raise RuntimeError(f"reused extent cleanup failed: {reused_cleanup!r}")

        scrub = run_ssh_json(
            key,
            port,
            "xaiosctl storage scrub /models --start "
            "--operation-id 9401 --json",
        )
        for _ in range(128):
            if scrub.get("state") == "complete":
                break
            if scrub.get("state") == "failed":
                raise RuntimeError(f"xaiFS scrub failed: {scrub!r}")
            scrub = run_ssh_json(
                key, port, "xaiosctl storage scrub /models --status --json"
            )
        else:
            raise RuntimeError(f"xaiFS scrub did not complete: {scrub!r}")
        if scrub.get("checked_bytes") != scrub.get("total_bytes"):
            raise RuntimeError(f"xaiFS scrub byte accounting is invalid: {scrub!r}")

        trim = run_ssh_json(
            key,
            port,
            "xaiosctl storage trim /models --dry-run --json",
        )
        for _ in range(128):
            if trim.get("state") == "complete":
                break
            if trim.get("state") == "failed":
                raise RuntimeError(f"xaiFS trim dry-run failed: {trim!r}")
            trim = run_ssh_json(
                key, port, "xaiosctl storage trim-status /models --json"
            )
        else:
            raise RuntimeError(f"xaiFS trim dry-run did not complete: {trim!r}")
        if trim.get("dry_run") != 1 or trim.get("processed_bytes", 0) == 0:
            raise RuntimeError(f"xaiFS trim dry-run reported no work: {trim!r}")

        trim = run_ssh_json(
            key,
            port,
            "xaiosctl storage trim /models --all-free "
            "--operation-id 9501 --json",
        )
        for _ in range(128):
            if trim.get("state") == "complete":
                break
            if trim.get("state") == "failed":
                raise RuntimeError(f"xaiFS trim failed: {trim!r}")
            trim = run_ssh_json(
                key, port, "xaiosctl storage trim-status /models --json"
            )
        else:
            raise RuntimeError(f"xaiFS trim did not complete: {trim!r}")
        if trim.get("processed_bytes") != trim.get("eligible_bytes"):
            raise RuntimeError(f"xaiFS trim byte accounting is invalid: {trim!r}")
        post_trim_device = run_ssh_json(
            key, port, "xaiosctl storage device show /dev/vblk4 --json"
        )["devices"][0]
        if post_trim_device.get("discarded_bytes", 0) == 0:
            raise RuntimeError(
                f"VirtIO discard accounting did not advance: {post_trim_device!r}"
            )

        audit = run_ssh(key, port, "xaiosctl audit show --since 0 --limit 16")
        for operation in (
            "model.package.stage",
            "model.package.cleanup",
            "storage.scrub.start",
            "storage.trim.start",
        ):
            if f"operation={operation}" not in audit:
                raise RuntimeError(f"audit log lacks {operation}: {audit!r}")
        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited unexpectedly rc={qemu.returncode}")
    finally:
        stop_process(qemu)
        log_file.close()

    log = log_path.read_text(errors="replace")
    if (
        "staging fsync record=3" not in log
        or "xaifs: activated package=" not in log
        or "xaifs: registered dynamic staging package" not in log
        or "xaifs: cleaned staging package=" not in log
    ):
        raise RuntimeError("guest log lacks xaiFS commit/activation evidence")
    print(
        "qemu-model-sftp: one XAIOS VM passed concurrent "
        f"{'macOS' if platform.system() == 'Darwin' else platform.system()}/Debian 13 "
        "dynamic SFTP upload/download, resume, verify, activate, scrub, "
        "staging cleanup/reuse, audited trim, and VirtIO discard accounting"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
