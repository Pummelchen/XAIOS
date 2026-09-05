#!/usr/bin/env python3
import sys
from qemu_gate_lib import arch_from_argv, smoke_command, smoke_timeout, BUILD, check_markers, now, parse_telemetry, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.cpu_ai_runtime_simulator.v1"
REPORT = BUILD / "qemu-milestone-58-cpu-ai-suite.json"

MARKERS = {
    "model_loader_boundary": [
        "cpu-ai-runtime: model manifest loaded",
        "cpu-ai-runtime: model file loaded id=2 name=cpu-ai-v1-fixture",
        "cpu-ai-runtime: model file path=/models/cpu-ai-v1-fixture.xaiosmodel admitted arena=2",
        "cpu-ai-runtime: model file loader self-test passed file_loads=1 file_rejects=3",
    ],
    "tokenizer_runtime_boundary": [
        "cpu-ai-runtime: tokenizer/runtime boundary self-test passed tokenizer_calls=2 runtime_calls=2",
        "cpu-ai-runtime: tokenizer binding and CPU dispatch self-test passed tokenizer_binds=2 kernel_dispatches=2",
        "cpu-ai-runtime: v1 fixture decode input=ABCD output=1B1F2327",
        "/bin/lstm-xor: cpu-ai fixture decode=",
    ],
    "generic_ml_runtime": [
        "cpu-ai-runtime: generic ml model kind=2",
        "cpu-ai-runtime: generic ml model kind=3",
        "cpu-ai-runtime: generic ml model kind=4",
        "/bin/mltest: multi-model CPU-only ML runtime passed",
    ],
    "shared_weights_private_kv": [
        "cpu-ai-runtime: multi-cell shared weights self-test passed loads=2 shared_binds=2 kv_writes=8",
        "ai-cell: multi-cell shared model/private kv self-test passed",
    ],
    "cpu_only_no_gpu_dependency": [
        "cpu-ai-runtime: model load failure self-test passed failures=3 gpu_rejects=1",
        "\"cpu_ai_gpu_rejects\":1",
    ],
    "admission_and_checksum": [
        "admission_rejects=5 checksum_failures=1",
        "\"cpu_ai_admission_rejects\":5",
        "\"cpu_ai_checksum_failures\":1",
    ],
}


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    proc = run(smoke_command(arch), timeout=smoke_timeout(arch, 140))
    failures = []
    checks = []
    telemetry = {}
    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")
    else:
        try:
            telemetry = parse_telemetry(proc.stdout)
        except ValueError as exc:
            failures.append(str(exc))

    for name, markers in MARKERS.items():
        missing = check_markers(proc.stdout, markers)
        checks.append(result(name, not missing, missing_markers=missing))
        failures.extend(f"{name} missing marker: {marker}" for marker in missing)

    counters_ok = (
        telemetry.get("cpu_ai_model_loads", 0) >= 5
        and telemetry.get("cpu_ai_shared_weight_binds", 0) >= 5
        and telemetry.get("cpu_ai_kv_writes", 0) >= 19
        and telemetry.get("cpu_ai_runtime_calls", 0) >= 8
        and telemetry.get("cpu_ai_gpu_rejects", 0) >= 1
    )
    checks.append(result("telemetry_counters", counters_ok,
                         model_loads=telemetry.get("cpu_ai_model_loads"),
                         shared_weight_binds=telemetry.get("cpu_ai_shared_weight_binds"),
                         kv_writes=telemetry.get("cpu_ai_kv_writes"),
                         runtime_calls=telemetry.get("cpu_ai_runtime_calls"),
                         gpu_rejects=telemetry.get("cpu_ai_gpu_rejects")))
    if not counters_ok:
        failures.append("CPU-AI telemetry counters below required thresholds")

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 58,
        "created_at_unix": now(),
        "description": "CPU-only AI runtime simulator gate for model loader, tokenizer/runtime, shared weights, private KV/cache, and CPU-only admission policy.",
        "smoke_exit_code": proc.returncode,
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    print(proc.stdout)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
