#!/usr/bin/env python3
"""Run and aggregate the XAIOS four-endpoint network interoperability matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
PICOLIBC_PIN = "2ae376c6cdf4fef90ca2388ecf7a07457fa63cff"


def run(command: list[str], timeout: float) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True, timeout=timeout)


def read_report(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise RuntimeError(f"required child report is missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("status", "pass") != "pass":
        raise RuntimeError(f"child report did not pass: {path}")
    return data


def source_archive(destination: Path) -> tuple[str, str]:
    picolibc_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT / "third_party" / "picolibc",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if picolibc_revision != PICOLIBC_PIN:
        raise RuntimeError(
            f"Picolibc source is {picolibc_revision}, expected {PICOLIBC_PIN}"
        )
    files = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    submodule_paths = subprocess.run(
        ["git", "submodule", "foreach", "--quiet", "printf '%s\\0' \"$sm_path\""],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    with tarfile.open(destination, "w:gz") as archive:
        for encoded in files:
            if not encoded:
                continue
            relative = encoded.decode("utf-8")
            archive.add(ROOT / relative, arcname=relative, recursive=False)
        for encoded_path in submodule_paths:
            if not encoded_path:
                continue
            relative_path = encoded_path.decode("utf-8")
            submodule = ROOT / relative_path
            tracked = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=submodule,
                check=True,
                capture_output=True,
            ).stdout.split(b"\0")
            for encoded_file in tracked:
                if not encoded_file:
                    continue
                sub_relative = encoded_file.decode("utf-8")
                archive.add(
                    submodule / sub_relative,
                    arcname=f"{relative_path}/{sub_relative}",
                    recursive=False,
                )
    with tarfile.open(destination, "r:gz") as archive:
        if "third_party/picolibc/meson.build" not in archive.getnames():
            raise RuntimeError("source archive is missing the Picolibc submodule")
    identity = hashlib.sha256(destination.read_bytes()).hexdigest()
    revision = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise RuntimeError(f"invalid source revision: {revision!r}")
    return identity, revision


def remote_matrix(vps: str, remote_root: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="xaios-network-source-") as temporary:
        archive = Path(temporary) / "source.tar.gz"
        identity, revision = source_archive(archive)
        run_root = f"{remote_root.rstrip('/')}/four-endpoint-{identity[:16]}"
        mkdir = [
            "ssh",
            "-o",
            "BatchMode=yes",
            vps,
            "mkdir",
            "-p",
            run_root,
        ]
        run(mkdir, 30)
        print(f"+ stream source archive to {vps}:{run_root}", flush=True)
        with archive.open("rb") as source:
            subprocess.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    vps,
                    f"tar -xzf - -C {run_root}",
                ],
                cwd=ROOT,
                stdin=source,
                check=True,
                timeout=300,
            )
        remote_command = (
            f"cd {run_root} && "
            f"export XAIOS_BUILD_REVISION_OVERRIDE={revision} && "
            f"export XAIOS_PICOLIBC_REVISION_OVERRIDE={PICOLIBC_PIN} && "
            "XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-docker-network-suite && "
            "XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-freebsd-bidirectional-suite"
        )
        run(
            ["ssh", "-o", "BatchMode=yes", vps, remote_command],
            4 * 60 * 60,
        )
        remote_reports = BUILD / "four-endpoint-vps"
        remote_reports.mkdir(parents=True, exist_ok=True)
        for name in (
            "qemu-docker-network-suite-x86_64.json",
            "qemu-freebsd-bidirectional-x86_64.json",
        ):
            run(
                [
                    "scp",
                    "-q",
                    f"{vps}:{run_root}/build/{name}",
                    str(remote_reports / name),
                ],
                120,
            )
        result = read_remote_reports()
        result["source_archive_sha256"] = identity
        result["source_revision"] = revision
        return result


def read_remote_reports() -> dict[str, object]:
    remote_reports = BUILD / "four-endpoint-vps"
    return {
        "endpoint": "Intel Debian VPS",
        "debian_to_xaios_x86_64": read_report(
            remote_reports / "qemu-docker-network-suite-x86_64.json"
        ),
        "freebsd_x86_64_bidirectional": read_report(
            remote_reports / "qemu-freebsd-bidirectional-x86_64.json"
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vps", help="SSH destination for the Intel Debian VPS")
    parser.add_argument("--remote-root", default="/var/xaios")
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument("--remote-only", action="store_true")
    parser.add_argument("--reuse-local", action="store_true")
    parser.add_argument("--reuse-remote", action="store_true")
    args = parser.parse_args()
    if args.local_only and args.remote_only:
        parser.error("--local-only and --remote-only are mutually exclusive")
    if not args.local_only and not args.vps:
        parser.error("--vps is required unless --local-only is used")
    return args


def main() -> int:
    args = parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {
        "schema": "xaios.qemu.four_endpoint_network.v1",
        "status": "pass",
        "evidence_scope": "QEMU correctness and interoperability; not physical performance",
        "endpoints": {},
    }
    endpoints = report["endpoints"]
    assert isinstance(endpoints, dict)
    if not args.remote_only:
        if not args.reuse_local:
            run(["make", "qemu-docker-network-suite"], 2 * 60 * 60)
            run(["make", "qemu-parallel-network-load"], 2 * 60 * 60)
            run(["make", "qemu-freebsd-bidirectional-suite"], 2 * 60 * 60)
        endpoints["macos_and_debian"] = {
            "debian_full": read_report(BUILD / "qemu-docker-network-suite.json"),
            "parallel_load": read_report(BUILD / "qemu-parallel-network-load.json"),
        }
        endpoints["freebsd_aarch64"] = read_report(
            BUILD / "qemu-freebsd-bidirectional-aarch64.json"
        )
    if not args.local_only:
        endpoints["intel_vps"] = (
            read_remote_reports()
            if args.reuse_remote
            else remote_matrix(args.vps, args.remote_root)
        )
    report_path = BUILD / "qemu-four-endpoint-network-suite.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"PASS: four-endpoint network suite ({report_path})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
