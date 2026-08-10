#!/usr/bin/env python3
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

from qemu_gate_lib import contract, parse_telemetry, validate_telemetry_against_contract


TARGETS = [
    "exceptions: self-test",
    "spinlock: early single-core try-lock self-test passed",
    "SMMU: self-test bypass mode streams=0 invalidations=1",
    "timer: monotonic self-test passed",
    "smp: per-core registry self-test passed",
    "VMM map/unmap self-test passed",
    "VMM architecture device mappings installed",
    "arena: self-test passed",
    "sandbox: lifecycle self-test passed",
    "sandbox: VM build self-test passed",
    "source-index: fixture loaded files=2 symbols=2 updates=1",
    "source-index: C scanner self-test passed",
    "git-workspace: self-test passed",
    "git-workspace: blob hash and diff self-test passed",
    "virtio-blk: read/write/error/reset self-test passed",
    "persistence: mutable state region sector=3000 sectors=1",
    "persistence: disk write sector=3000 version=1 records=5",
    "persistence: disk loaded sector=3000 version=1 records=5",
    "persistence: disk reload/rollback self-test passed snapshots=5 rollbacks=5 rejects=2 disk_writes=1 disk_loads=1 checksum_errors=0",
    "mutable-fs: mounted start=3072 metadata=16 journal=2 data=3090 sectors=96 nodes=32 policy=rw",
    "mutable-fs: write path=/state/services/source-index.state",
    "mutable-fs: snapshot committed",
    "mutable-fs: snapshot rollback",
    "mutable-fs: allocator self-test passed",
    "mutable-fs: directory tree self-test passed directories=15",
    "mutable-fs: multi-sector file self-test passed files=7 multi_sector=1",
    "mutable-fs: journal replay self-test passed replays=1 journal_writes=1",
    "mutable-fs: public API self-test passed list=1 stat=3 rename=1 open=3 close=3",
    "mutable-fs: subsystem records self-test passed records=4",
    "mutable-fs: self-test passed files=7 directories=15 writes=12 reads=6 deletes=1 commits=1 rollbacks=1 replays=1 rejects=8 checksum_errors=0",
    "modelfs: mounted /models device=/dev/vblk4 generation=",
    "modelfs: signed active read and crash-consistent staging write self-test passed active_bytes=8192 staging_bytes=4096",
    "update: self-test passed transactions=2 staged=2 committed=1 failed=1 recovered=1 rollbacks=1 boot_fallbacks=1 records=8 rollback_points=2 rejects=2",
    "virtio-net: malformed packet/drop self-test passed",
    "virtio-net: queue/tx/parser/reset self-test passed",
    "network: stack initialized",
    "ipv4: fragmentation/reassembly self-test passed",
    "ipv6: fragmentation/reassembly passed",
    "network: udp flow id=",
    "expired queue=",
    "retransmit=1",
    "timeout queue=",
    "network: queue-backed udp/tcp self-test passed rx=6 tx=6 drops=2 lifecycle=18 udp_flows=1 udp_hits=1 udp_expired=1 tcp_timeouts=1 tcp_retransmits=1 queue_rx=6 queue_tx=6 queue_done=6 backpressure=0 flow_mismatch=0",
    "network: external host udp session port=2222",
    "network: external host tcp session port=2222",
    "ipv6: self-test passed",
    "icmpv6: self-test passed",
    "ndp: self-test passed",
    "initramfs: config service=/init mode=qemu-mvp",
    "initramfs: service-manager path=/bin/service-manager descriptor=/etc/services/source-index.svc",
    "initramfs: child service=/svc/source-index parent=/init restart=never",
    "initramfs: mounted rofs version=2 files=19",
    "initramfs: rofs metadata/config self-test passed",
    "syscall: table self-test passed entries=49",
    "virtio-rng: entropy delivery self-test passed",
    "user: process table initialized slots=1024",
    "user: process lifecycle invalid/failed transition self-test passed",
    "scheduler: lifecycle self-test passed",
    "user: process pid=1 name=/init state=loaded",
    "security: self-test passed denied=15 capability_denials=3 fs_denials=2 workspace_denials=1 sandbox_denials=1 rollback_denials=1 update_policy_rejects=4 credential_rejects=2 signature_accepts=1 signature_rejects=4 admin_denials=2 update_authorizations=1 update_replay_rejects=1 key_accepts=1 key_rejects=1 sandbox_escape_rejects=1",
    "remote-login: isolated session cwd self-test passed",
    "remote-login: self-test passed sessions=6 commands=6 denials=4",
    "threads: runtime initialized capacity=",
    "threads: concurrent scheduler self-test passed threads=",
    "scheduler: SIMD/FP interrupt preservation passed",
    "model-arena: shared read-only arena self-test passed",
    "ai-kernel: scalar fp16 and packed no-expand self-test passed fp16=10 int4=6 int6=2",
    "nic-conflict-agent",
    "core-conflict-agent",
    "workspace-conflict-agent",
    "ai-cell: descriptor ABI self-test passed accepts=5 rejects=4",
    "ai-cell: resource contract self-test passed admissions=2 rejects=10 arena_pages=160 arena_bytes=655360 queue_binds=3 queue_releases=3 workspace_binds=2 workspace_releases=2 conflicts=3",
    "ai-cell: lifecycle self-test passed",
    "agent-protocol: self-test passed",
    "control: protocol self-test passed version=1 malformed=5 denied=1 redaction=1",
    "admin-control: self-test passed schema=1 invalid=1 principal=2 transactional=1",
    "elf_loader: self-test passed dynamic_page_capacity=513",
    "cpu-ai-runtime: Q8.8 kernel self-test passed",
    "kheap: self-test passed",
    "VMM translation test passed",
    "gic: discovery self-test passed",
    "nvme: self-test skipped no PCI NVMe controller",
    "PMM 1024 page allocate/free test passed",
    "cpu-ai-runtime: model manifest loaded",
    "cpu-ai-runtime: model file loaded id=2 name=cpu-ai-v1-fixture",
    "cpu-ai-runtime: model file path=/models/cpu-ai-v1-fixture.xaiosmodel admitted arena=2",
    "cpu-ai-runtime: tokenizer/runtime boundary self-test passed tokenizer_calls=2 runtime_calls=2",
    "cpu-ai-runtime: multi-cell shared weights self-test passed loads=2 shared_binds=2 kv_writes=8",
    "cpu-ai-runtime: model load failure self-test passed failures=3 gpu_rejects=1",
    "cpu-ai-runtime: model file loader self-test passed file_loads=1 file_rejects=3",
    "admission_rejects=5 checksum_failures=1",
    "cpu-ai-runtime: tokenizer binding and CPU dispatch self-test passed tokenizer_binds=2 kernel_dispatches=2",
    "cpu-ai-runtime: v1 fixture decode input=ABCD output=1B1F2327",
    "cpu-ai-runtime: self-test passed",
    "cpu-ai-runtime: generic ml model kind=2",
    "cpu-ai-runtime: generic ml model kind=3",
    "cpu-ai-runtime: generic ml model kind=4",
    "ai-cell: multi-cell shared model/private kv self-test passed",
    "user: loaded /init ELF",
    "user: process pid=1 name=/init state=running",
    "user: rejected syscall=99",
    "user: rejected syscall=1",
    "/init: bad syscall tests passed",
    "/init: hello from ELF",
    "service-manager: configured /init restart=never log=serial max_restarts=0",
    "service-manager: log /init manager-ready records=1",
    "/init: service manager policy ready",
    "service-manager: restart denied /init policy=never attempts=1",
    "/init: restart denied by policy",
    "service: /init state=running",
    "/init: service setup complete",
    "rejected=3",
    "user: /init exited status=0",
    "user: process pid=1 name=/init state=exited",
    "user: kernel resumed after EL0 pid=1 state=exited exit_code=0",
    "kernel: /init returned to kernel exit_code=0",
    "user: reclaimed aspace pid=1",
    "user: loaded /bin/service-manager ELF",
    "user: process pid=2 name=/bin/service-manager state=running",
    "/service-manager: hello from ELF",
    "user: service descriptor read path=/etc/services/source-index.svc",
    "/service-manager: descriptor loaded",
    "user: rejected syscall=9",
    "user: rejected syscall=10",
    "/service-manager: missing capability tests passed",
    "service-manager: defined child /svc/source-index parent=/init restart=never",
    "service-supervisor: tree parent=/init child=/svc/source-index children=1 edges=1",
    "service: /svc/source-index state=running",
    "service: /svc/source-index mutable-state persisted state=running",
    "osctl: /svc/source-index state=running",
    "service-manager: restart denied /svc/source-index policy=never",
    "/service-manager: child service supervised",
    "service-manager: configured /svc/source-index restart=always log=serial max_restarts=2",
    "service-manager: log /svc/source-index crash-test records=1",
    "service-supervisor: observed crash /svc/source-index code=7 parent=/init",
    "service: /svc/source-index state=failed exit_code=7",
    "service-supervisor: cleanup /svc/source-index reason=crash cleanups=1",
    "service-supervisor: restarting child /svc/source-index parent=/init attempt=2",
    "/service-manager: child crash supervised",
    "admin: policy ssh_only=1 password_login=0 admin_cap_required=1 remote_safe_allowlist=1 exports=1",
    "admin: status service=/svc/source-index state=running",
    "mutable-fs: write path=/state/services/admin.state",
    "admin: logs service=/svc/source-index records=1",
    "admin: remote-safe command=status accepted accepts=1",
    "admin: remote-safe command=shell rejected rejects=1",
    "/service-manager: admin status exported",
    "/service-manager: remote-safe checks passed",
    "osctl: status legacy=1 processes=",
    "osctl: ps slots=1024",
    "osctl: services transitions=",
    "osctl: cells transitions=",
    "osctl: fs files=",
    "osctl: net udp_tx=",
    "osctl: telemetry cpu_ai_loads=",
    "osctl: update transactions=",
    "osctl: rollback persistence=",
    "/service-manager: osctl command surface passed",
    "/service-manager: mutable fs syscalls passed",
    "/service-manager: control plane complete",
    "user: /bin/service-manager exited status=0",
    "kernel: /bin/service-manager returned to kernel exit_code=0",
    "parent=2 runnable name=/bin/xaios-worker",
    "parent=2 name=/bin/xaios-worker",
    "name=/bin/xaios-worker state=exited exit_code=0",
    "/worker: scheduled child process ran",
    "/bin/xaios-shell: command surface passed 1..15 + ls variants + tar/cpio archive",
    "/bin/xaios-shell: nano and htop utilities passed",
    "kernel: /bin/xaios-shell returned to kernel exit_code=0",
    "/bin/xaiosctl: control commands passed human=14 json=14",
    "/bin/xaiosctl: negative tests passed malformed=1 authorization=1 node=1",
    "kernel: /bin/xaiosctl returned to kernel exit_code=0",
    "/bin/hello: hello world from C userspace",
    "/bin/hello: C toolchain and EL0 runtime integration passed",
    "kernel: /bin/hello returned to kernel exit_code=0",
    "/bin/sysinfo: legacy utility; use xaiosctl status and xaiosctl hardware for measured state",
    "/bin/sysinfo: complete",
    "kernel: /bin/sysinfo returned to kernel exit_code=0",
    "/bin/systest: syscall and filesystem suite passed",
    "kernel: /bin/systest returned to kernel exit_code=0",
    "/bin/smptest: complete",
    "/bin/smptest: app-requested SMP worker set passed",
    "/bin/smptest: concurrent kernel-dispatched worker group passed",
    "/bin/smptest: general EL0 create/join threads passed",
    "kernel: /bin/smptest returned to kernel exit_code=0",
    "/bin/nettest: complete",
    "/bin/nettest: app-callable udp/tcp path passed",
    "/bin/nettest: external host-to-guest tcp/udp session path passed",
    "/bin/nettest: userspace DNS resolve/cache path passed",
    "kernel: /bin/nettest returned to kernel exit_code=0",
    "/bin/lstm-xor: CPU-only two-hidden-layer LSTM XOR example starting",
    "/bin/lstm-xor: production decode unsupported as required",
    "/bin/lstm-xor: cpu-ai fixture decode=",
    "/bin/lstm-xor: train_ns=",
    "/bin/lstm-xor: run3_avg_ns=",
    "/bin/lstm-xor: final_errors=0",
    "/bin/lstm-xor: xor solve passed predictions=0,1,1,0",
    "kernel: /bin/lstm-xor returned to kernel exit_code=0",
    "/bin/sshtest: interactive remote login command surface passed",
    "kernel: /bin/sshtest returned to kernel exit_code=0",
    "/bin/mltest: multi-model CPU-only ML runtime passed",
    "kernel: /bin/mltest returned to kernel exit_code=0",
    "/bin/posix-shell: pipe and redirect surface passed",
    "kernel: /bin/posix-shell returned to kernel exit_code=0",
    "/bin/agenttest: agent protocol dispatch passed",
    "/bin/agenttest: complete",
    "kernel: /bin/agenttest returned to kernel exit_code=0",
    "boot-ui: progress=90 loaded=runtime services loading=IPv4 internet check remaining=2",
    "sshd: Phase 2 runtime ready",
    "boot-ui: progress=100 loaded=SSH-server loading=complete remaining=0",
]

# OR targets: each entry is a list of alternative strings.
# At least one string from each group must appear in the output.
OR_TARGETS = [
    ["core-lease: dynamic isolation self-test passed", "core-lease: self-test skipped"],
    ["core-lease: owner=0 cpus=1 acquired", "core-lease: self-test skipped"],
]

def telemetry_line_complete(text):
    marker = "telemetry: {"
    start = text.rfind(marker)
    return start >= 0 and "\n" in text[start:]


def echo_best_effort(text: str) -> None:
    """Mirror serial diagnostics without making stdout backpressure fail a gate."""
    try:
        os.write(sys.stdout.fileno(), text.encode("utf-8", errors="replace"))
    except (BlockingIOError, BrokenPipeError, OSError):
        pass


def main() -> int:
    env = os.environ.copy()
    env["XAIOS_QEMU_HOSTFWD_PORT"] = "none"
    log_path = Path("build/qemu-smoke.log")
    persistent_image = Path("build/xaios-smoke-persistent.img")
    persistent_image.unlink(missing_ok=True)
    env["XAIOS_PERSISTENT_IMAGE"] = str(persistent_image)
    proc = subprocess.Popen(
        ["make", "qemu-aarch64"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        start_new_session=True,
    )
    seen = []
    deadline = time.time() + int(os.environ.get("XAIOS_QEMU_SMOKE_TIMEOUT", "60"))
    try:
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                echo_best_effort(chunk)
                seen.append(chunk)
                text = "".join(seen)
                telemetry_failures = []
                if telemetry_line_complete(text):
                    try:
                        telemetry_failures = validate_telemetry_against_contract(
                            parse_telemetry(text), contract()
                        )
                    except (ValueError, KeyError) as error:
                        telemetry_failures = [str(error)]
                if (all(target in text for target in TARGETS) and
                        all(any(alt in text for alt in group) for group in OR_TARGETS) and
                        telemetry_line_complete(text) and not telemetry_failures):
                    echo_best_effort(
                        "\nQEMU smoke boot reached all full userspace/resource markers\n"
                    )
                    return 0
            elif proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                proc.wait(timeout=3)
        log_path.write_text("".join(seen), encoding="utf-8")
        persistent_image.unlink(missing_ok=True)

    text = "".join(seen)
    missing = [target for target in TARGETS if target not in text]
    for group in OR_TARGETS:
        if not any(alt in text for alt in group):
            missing.append(f"({' | '.join(group)})")
    if telemetry_line_complete(text):
        try:
            missing.extend(validate_telemetry_against_contract(
                parse_telemetry(text), contract()
            ))
        except (ValueError, KeyError) as error:
            missing.append(f"telemetry: {error}")
    else:
        missing.append("telemetry: complete JSON line")
    echo_best_effort(f"\nmissing targets: {missing}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
