#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time


def run(cmd, env=None):
    return subprocess.run(
        cmd,
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def main() -> int:
    root = os.getcwd()
    build_dir = os.path.join(root, "build")
    os.makedirs(build_dir, exist_ok=True)

    benchmark_output = os.path.join(build_dir, "qemu-benchmark-report.json")
    preview_output = os.path.join(build_dir, "qemu-preview-manifest.json")

    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "60")
    env["XAIOS_QEMU_BENCHMARK_OUTPUT"] = benchmark_output

    bench = run(["python3", "./tests/scripts/qemu-benchmark.py"], env=env)
    sys.stdout.write(bench.stdout)
    if bench.returncode != 0:
        print("qemu-preview: benchmark gate failed")
        return bench.returncode

    with open(benchmark_output, "r", encoding="utf-8") as handle:
        benchmark = json.load(handle)

    manifest = {
        "schema": "xaios.qemu.preview.v1",
        "created_unix": int(time.time()),
        "status": "pass",
        "image": "build/xaios-aarch64.img",
        "virtio_test_block": "build/xaios-virtio-test.img",
        "benchmark_report": "build/qemu-benchmark-report.json",
        "release_candidate_contract": "contracts/qemu-rc-v1.json",
        "contracts": {
            "architecture": "aarch64",
            "firmware": "UEFI",
            "machine": "qemu-virt",
            "release_candidate_contract_schema": "xaios.qemu.release_candidate_contract.v1",
            "userspace": "EL0 /init plus /bin/service-manager from VirtIO-backed read-only filesystem",
            "performance_claims_allowed": False,
        },
        "benchmark_schema": benchmark.get("schema"),
        "telemetry": benchmark.get("telemetry", {}),
    }

    with open(preview_output, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, sort_keys=True, indent=2)

    print(f"qemu-preview: manifest written to {preview_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
