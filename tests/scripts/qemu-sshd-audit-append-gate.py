#!/usr/bin/env python3
"""B-45: what an audit record costs the machine, measured on both sides of it.

`ssh_log` appends about forty bytes per audit record and sshd writes several
per connection. Before this gate's fix every one of those appends read the
whole log file back off the durable volume and wrote all of it out again, and
`load_authorized_keys` re-read the key file on every publickey attempt. Both
run inside sshd's service loop, and by B-44 that loop is the machine's network
thread: `network_poll_tick` has no timer, no interrupt and no thread of its
own, so for the length of a write to the volume nothing is taken off the
receive ring, no ACK leaves the guest and nothing is retransmitted.

A claim about cost has to be measured, and measured the same way on both sides
or it is not a comparison. So this gate does not compare today's tree against a
number somebody wrote down last week. It builds the *same tree* twice:

  * `baseline` -- `-DXBFS_APPEND_IN_PLACE=0 -DSSHD_KEY_CACHE=0`, which is
    exactly the filesystem and the server as they were before B-45;
  * `fixed` -- the shipped defaults.

and drives an identical workload of SSH connections through each, reading the
same two instruments: the kernel's own `xaibootfs:` console lines, which say
what was read and written per file, and sshd's `sshd: durable cost` line, which
carries the running totals of calls, bytes and nanoseconds spent on the volume
inside the loop.

The gate's own falsifiability is the baseline. If the baseline does not show
the defect -- several whole-file read-modify-writes of the audit log per
connection, and a key-file read per publickey attempt -- then this gate is
measuring something that is not B-45 and every green result below is worth
nothing, so it fails and says so. A gate whose "before" is already clean is a
gate that would pass on a tree where the fix had been reverted.

Two controls, each closing a way a green run could be meaningless.

  1. The append path has to fail when it should. The kernel's own append
     self-test does that at boot on a volume it fills to the last block, and
     this gate requires the line it prints -- so a build whose append path
     quietly accepted an append it had no block for would not reach the
     measurement at all.

  2. The key cache has to invalidate. Caching the parsed keys is only safe
     because the cache is keyed on the file's generation, which xaibootFS bumps
     on every write and `xaios_fs_stat` reports. A cache that never looked
     again would be faster than this one and would be wrong the moment an
     administrator added or revoked a key -- so a third image is built with
     `-DSSHD_KEY_CACHE_INVALIDATES=0`, a key is added through `xaiosctl auth
     key add`, and the new key must be *refused* by that build and *accepted*
     by the shipped one. Same boot, same command, opposite outcomes.

What it deliberately does not assert: an absolute time. The figures come from
an emulator sharing a laptop, and pinning them would make this a gate on the
host's mood. What it asserts is the shape of the change -- no whole-file
rewrites at all, no key-file read per attempt, and a large drop in the bytes
the log costs -- and it reports the times.

Read the times with the last line of the report next to them. Every file write
on this filesystem, appended or rewritten, ends in `write_metadata`, which
writes the volume's entire metadata region and flushes: 1280 sectors, 640 KiB,
on the v5 volume these boots mount. That is the same before and after, it is
about forty times the file traffic the whole-file path moved, and it is where
almost all of the time an audit record costs actually goes. So the traffic
figures fall by an order of magnitude while the time falls by about a quarter,
and all of that quarter comes from writing two fewer records per connection --
the key cache removes two `Loaded N authorized keys` lines -- rather than from
a record being cheaper. The report carries the metadata figure so that nobody
reads the first number as the whole cost of an audit record.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout, write_report)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
READY_MARKER = "SSH server: up and running (tcp/22)"
APPEND_SELF_TEST = "xaibootfs: append self-test passed"

# Enough connections for a per-connection mean to mean something, and well
# inside SSHD_CONNECTION_RATE_LIMIT for the window they take.
CONNECTIONS = 40

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR"]

LOG_PATH = "/state/sshd.log"
KEY_PATH = "/etc/xaios_authorized_keys"

REWRITE = re.compile(
    r"xaibootfs: write path=" + re.escape(LOG_PATH) +
    r" size=(?P<size>\d+) blocks=(?P<blocks>\d+)")
LOG_READ = re.compile(
    r"xaibootfs: read path=" + re.escape(LOG_PATH) +
    r" size=(?P<size>\d+) blocks=(?P<blocks>\d+)")
APPEND = re.compile(
    r"xaibootfs: append path=" + re.escape(LOG_PATH) +
    r" added=(?P<added>\d+) size=(?P<size>\d+) touched=(?P<touched>\d+)")
KEY_READ = re.compile(
    r"xaibootfs: read path=" + re.escape(KEY_PATH) + r" size=(?P<size>\d+)")
COST = re.compile(
    r"sshd: durable cost conns=(?P<conns>\d+) audit_writes=(?P<writes>\d+) "
    r"audit_bytes=(?P<bytes>\d+) audit_us=(?P<audit_us>\d+) "
    r"key_loads=(?P<loads>\d+) key_file_reads=(?P<reads>\d+) "
    r"key_us=(?P<key_us>\d+)")
REFUSAL = re.compile(r"sshd: connection refused reason=(?P<reason>[a-z-]+)")
STALL = re.compile(r"sshd: service loop stalled ms=(?P<ms>\d+)")

MOUNTED = re.compile(r"xaibootfs: persistent mounted v(?P<version>\d+) "
                     r"nodes=(?P<nodes>\d+) sectors=(?P<sectors>\d+)")


def metadata_sectors(version: str) -> int:
    """How many sectors a file write commits *besides* the file's own blocks.

    Every write, appended or rewritten, ends in `write_metadata`, which writes
    the whole metadata region and flushes. That cost is identical on both sides
    of this change and it is far larger than the file traffic either side
    moves, so leaving it out of the report would make the improvement look like
    the whole story. Read from the kernel source rather than written down here,
    for the reason every other constant in these gates is: a copy passes after
    someone changes the original.
    """
    text = (ROOT / "kernel" / "fs" / "xaiboot_fs.c").read_text(encoding="utf-8")
    name = ("XBFS_METADATA_SECTORS" if version == "2"
            else f"XBFS_V{version}_METADATA_SECTORS")
    match = re.search(rf"#define\s+{name}\s+(\d+)U", text)
    return int(match.group(1)) if match else 0


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_marker(log_path: Path, marker: str, timeout: float,
                    process: subprocess.Popen) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("the guest exited before it was ready")
        if log_path.exists() and marker in log_path.read_text(errors="replace"):
            return
        time.sleep(0.5)
    raise TimeoutError(f"the guest never printed {marker!r}")


def run_ssh(key: Path, port: int, command: str, timeout: float,
            expect_failure: bool = False) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["ssh", *SSH_BASE, "-i", str(key), "-p", str(port),
             "admin@127.0.0.1", command],
            cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 255, "", "timed out"
    return result.returncode, result.stdout, result.stderr.strip()


def wait_for_ssh(key: Path, port: int, process: subprocess.Popen,
                 timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("the guest exited before it answered SSH")
        rc, out, _ = run_ssh(key, port, "recovery status", 30.0, True)
        if rc == 0 and "rescue=" in out:
            return
        time.sleep(1.0)
    raise TimeoutError("the guest never answered an SSH command")


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def build(key: Path, kernel_flags: str, sshd_flags: str) -> None:
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key.with_suffix(".pub"))
    if kernel_flags:
        env["XAIOS_KERNEL_CFLAGS_EXTRA"] = kernel_flags
    else:
        env.pop("XAIOS_KERNEL_CFLAGS_EXTRA", None)
    if sshd_flags:
        env["XAIOS_SSHD_CFLAGS_EXTRA"] = sshd_flags
    else:
        env.pop("XAIOS_SSHD_CFLAGS_EXTRA", None)
    commands = {
        "aarch64": [["make", "image-qemu-test"]],
        "x86_64": [["make", "image-x86_64-qemu-test"]],
        "riscv64": [["./scripts/build-riscv64.sh"],
                    ["./scripts/build-riscv64-image.sh"]],
    }[ARCH]
    for command in commands:
        subprocess.run(command, cwd=ROOT, env=env, check=True,
                       timeout=smoke_timeout(ARCH, 600))


def console_since(log_path: Path, mark: int) -> str:
    """What the guest printed after `mark` bytes of console.

    Sliced as bytes and decoded afterwards. The boot banner carries escape
    sequences and the console is not guaranteed to be valid UTF-8, so a byte
    count is not a character index -- decoding first and slicing by a byte
    offset silently skips past real output.
    """
    return log_path.read_bytes()[mark:].decode(errors="replace")


def measure(window: str) -> dict[str, object]:
    """Everything the two instruments say about one workload.

    A write of size zero is the truncate that rotation performs, not a
    read-modify-write of a file's contents, and counting it as one would have
    left the fixed build looking as though it still rewrote the log. They are
    counted apart.

    The running totals are differenced from the first and the last line *inside
    the window*, rather than against a reading taken before it. A reading taken
    before the window races the close it is waiting on -- the connection has
    returned to the host before the guest has printed the line about letting it
    go -- and the first draft of this gate reported every time as zero for
    exactly that reason.
    """
    writes = [m.groupdict() for m in REWRITE.finditer(window)]
    rewrites = [w for w in writes if int(w["size"]) != 0]
    truncates = [w for w in writes if int(w["size"]) == 0]
    log_reads = [m.groupdict() for m in LOG_READ.finditer(window)]
    appends = [m.groupdict() for m in APPEND.finditer(window)]
    key_reads = [m.groupdict() for m in KEY_READ.finditer(window)]
    costs = [{k: int(v) for k, v in m.groupdict().items()}
             for m in COST.finditer(window)]

    result: dict[str, object] = {
        "log_rewrites": len(rewrites),
        "log_rewrite_bytes": sum(int(r["size"]) for r in rewrites),
        "log_rewrite_blocks": sum(int(r["blocks"]) for r in rewrites),
        "log_truncates": len(truncates),
        "log_reads": len(log_reads),
        "log_read_bytes": sum(int(r["size"]) for r in log_reads),
        "appends": len(appends),
        "append_bytes": sum(int(a["added"]) for a in appends),
        "append_blocks_touched": sum(int(a["touched"]) for a in appends),
        "key_file_reads_kernel": len(key_reads),
        "refusals": [m.group("reason") for m in REFUSAL.finditer(window)],
        "loop_stalls": [int(m.group("ms")) for m in STALL.finditer(window)],
    }
    if len(costs) < 2:
        result["cost"] = None
        result["cost_connections"] = 0
        return result
    result["cost"] = {key: costs[-1][key] - costs[0][key] for key in costs[-1]}
    result["cost_connections"] = costs[-1]["conns"] - costs[0]["conns"]
    return result


def per_connection(value: float, connections: int) -> float:
    return round(value / connections, 2) if connections else 0.0


def boot(gate_dir: Path, port: int, log_path: Path) -> subprocess.Popen:
    log_path.unlink(missing_ok=True)
    env = qemu_boot_environment(
        ARCH, os.environ.copy(), accel="tcg", smp=4, hostfwd_port=port,
        persistent=gate_dir / "persistent.img",
        state_dir=gate_dir / "state",
        serial_to_stdout=True)
    handle = log_path.open("wb")
    return subprocess.Popen([str(ROOT / qemu_runner(ARCH))], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=handle,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)


def workload(key: Path, port: int, failures: list[str], name: str) -> int:
    """The connections that are measured. Sequential, and each one a full
    connection: version exchange, key exchange, publickey authentication, one
    command, close. That is the shape a soak's round has and the shape B-45's
    arithmetic is about."""
    served = 0
    for index in range(CONNECTIONS):
        rc, out, message = run_ssh(key, port, "recovery status", 60.0, True)
        if rc != 0 or "rescue=" not in out:
            failures.append(
                f"{name}: connection {index + 1} of {CONNECTIONS} did not "
                f"complete: rc={rc} {message!r}. The measurement below is "
                f"about a workload that did not run")
            break
        served += 1
    return served


def rotate_key(key: Path, new_key: Path, port: int,
               timeout: float) -> dict[str, object]:
    """Add a second authorized key the way an administrator would, and see
    whether the server notices. `xaiosctl auth key add` has the kernel write
    the managed key database, which bumps that file's generation -- the thing
    the cache is keyed on. Nothing here tells sshd to reload."""
    put = subprocess.run(
        ["sftp", *SSH_BASE, "-i", str(key), "-P", str(port), "-b", "-",
         "admin@127.0.0.1"], cwd=ROOT, text=True,
        input=f"put {new_key.with_suffix('.pub')} /tmp/gate-key-b.pub\n",
        capture_output=True, timeout=timeout)
    add_rc, add_out, add_err = run_ssh(
        key, port,
        "xaiosctl auth key add /tmp/gate-key-b.pub --principal gate-key-b "
        "--role administrator --operation-id 94501",
        timeout, True)
    used_rc, used_out, used_err = run_ssh(new_key, port, "recovery status",
                                          timeout, True)
    return {
        "upload_rc": put.returncode,
        "upload_message": put.stderr.strip()[-300:],
        "add_rc": add_rc,
        "add_output": add_out.strip()[-300:],
        "add_message": add_err[-300:],
        "new_key_rc": used_rc,
        "new_key_accepted": used_rc == 0 and "rescue=" in used_out,
        "new_key_message": used_err[-300:],
    }


def run_configuration(name: str, kernel_flags: str, sshd_flags: str,
                      key: Path, second_key: Path, measured: bool,
                      rotate: bool, failures: list[str]) -> dict[str, object]:
    gate_dir = BUILD / f"sshd-audit-append{SUFFIX}" / name
    # A persistent.img left behind holds the previous run's key database, and
    # a stale one would decide this run's authentication for it.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)

    build(key, kernel_flags, sshd_flags)
    port = reserve_port()
    log_path = BUILD / f"qemu-sshd-audit-append{SUFFIX}-{name}.log"
    qemu = boot(gate_dir, port, log_path)
    report: dict[str, object] = {"kernel_flags": kernel_flags,
                                 "sshd_flags": sshd_flags}
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 300)), qemu)
        boot_console = console_since(log_path, 0)

        # Control one: the append path's own refusals, proved at boot on a
        # volume filled to the last block. A build that reached the numbers
        # below without this line would have an append path that never says no.
        report["append_self_test"] = APPEND_SELF_TEST in boot_console
        mounted = MOUNTED.search(boot_console)
        report["persistent_volume"] = mounted.groupdict() if mounted else None

        wait_for_ssh(key, port, qemu, float(smoke_timeout(ARCH, 240)))
        if measured:
            mark = len(log_path.read_bytes())
            served = workload(key, port, failures, name)
            time.sleep(3.0)
            window = console_since(log_path, mark)
            report["connections"] = served
            report.update(measure(window))
        if rotate:
            report["rotation"] = rotate_key(key, second_key, port,
                                            float(smoke_timeout(ARCH, 120)))
    finally:
        stop_process(qemu)
    return report


def main() -> int:
    if ARCH == "riscv64":
        # Said rather than discovered. This gate's whole method is building
        # one tree two ways, and the RISC-V scripts compile the kernel and
        # sshd themselves without the XAIOS_KERNEL_CFLAGS_EXTRA and
        # XAIOS_SSHD_CFLAGS_EXTRA hooks that build-image.sh has. Run on that
        # architecture it would build the same image three times and then fail
        # for a reason that reads like a defect in the fix. Refusing is the
        # honest answer until those two scripts grow the same two lines.
        print("qemu-sshd-audit-append-gate: riscv64 is not supported: "
              "scripts/build-riscv64.sh and scripts/build-riscv64-image.sh do "
              "not honour XAIOS_KERNEL_CFLAGS_EXTRA or "
              "XAIOS_SSHD_CFLAGS_EXTRA, so the baseline and the control "
              "builds would be identical to the fixed one", file=sys.stderr)
        return 2

    gate_dir = BUILD / f"sshd-audit-append{SUFFIX}"
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    second = gate_dir / "admin-b"
    for path in (key, second):
        if path.exists():
            path.unlink()
        if path.with_suffix(".pub").exists():
            path.with_suffix(".pub").unlink()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                        f"xaios-audit-append-gate-{path.name}", "-f",
                        str(path)], cwd=ROOT, check=True, timeout=30)

    failures: list[str] = []
    report: dict[str, object] = {"arch": ARCH, "connections_requested":
                                 CONNECTIONS}

    report["baseline"] = run_configuration(
        "baseline", "-DXBFS_APPEND_IN_PLACE=0", "-DSSHD_KEY_CACHE=0",
        key, second, measured=True, rotate=False, failures=failures)
    report["fixed"] = run_configuration(
        "fixed", "", "", key, second, measured=True, rotate=True,
        failures=failures)
    report["stale_cache_control"] = run_configuration(
        "stale", "", "-DSSHD_KEY_CACHE_INVALIDATES=0",
        key, second, measured=False, rotate=True, failures=failures)

    base = report["baseline"]
    fixed = report["fixed"]
    stale = report["stale_cache_control"]

    for name, entry in (("baseline", base), ("fixed", fixed),
                        ("stale", stale)):
        if entry.get("append_self_test") is not True and name != "baseline":
            failures.append(
                f"{name}: the kernel did not print {APPEND_SELF_TEST!r}. The "
                f"append path's own refusal control did not run, so nothing "
                f"below is evidence that it refuses anything")

    base_conns = int(base.get("connections") or 0)
    fixed_conns = int(fixed.get("connections") or 0)
    if base_conns < CONNECTIONS or fixed_conns < CONNECTIONS:
        failures.append(
            f"the workload did not complete on both builds: baseline "
            f"{base_conns}, fixed {fixed_conns}, of {CONNECTIONS}")

    summary: dict[str, object] = {}
    if base_conns and fixed_conns:
        base_cost = base.get("cost") or {}
        fixed_cost = fixed.get("cost") or {}
        base_timed = int(base.get("cost_connections") or 0)
        fixed_timed = int(fixed.get("cost_connections") or 0)
        volume = base.get("persistent_volume") or {}
        metadata = metadata_sectors(str(volume.get("version", "5")))
        if base_timed == 0 or fixed_timed == 0:
            failures.append(
                "sshd's `durable cost` line did not appear on both builds, so "
                "the time either of them spent on the volume was not measured "
                "and only the counts below mean anything")
        summary = {
            "baseline_rewrites_per_connection":
                per_connection(base["log_rewrites"], base_conns),
            "baseline_log_reads_per_connection":
                per_connection(base["log_reads"], base_conns),
            "baseline_file_bytes_per_connection":
                per_connection(base["log_rewrite_bytes"] +
                               base["log_read_bytes"], base_conns),
            "baseline_file_blocks_per_connection":
                per_connection(base["log_rewrite_blocks"], base_conns),
            "baseline_key_file_reads_per_connection":
                per_connection(base["key_file_reads_kernel"], base_conns),
            "baseline_audit_us_per_connection":
                per_connection(base_cost.get("audit_us", 0), base_timed),
            "baseline_key_us_per_connection":
                per_connection(base_cost.get("key_us", 0), base_timed),
            "baseline_audit_records_per_connection":
                per_connection(base_cost.get("writes", 0), base_timed),
            "baseline_loop_stalls": base["loop_stalls"],
            "fixed_rewrites_per_connection":
                per_connection(fixed["log_rewrites"], fixed_conns),
            "fixed_appends_per_connection":
                per_connection(fixed["appends"], fixed_conns),
            "fixed_file_bytes_per_connection":
                per_connection(fixed["append_blocks_touched"] * 512,
                               fixed_conns),
            "fixed_file_blocks_per_connection":
                per_connection(fixed["append_blocks_touched"], fixed_conns),
            "fixed_key_file_reads_per_connection":
                per_connection(fixed["key_file_reads_kernel"], fixed_conns),
            "fixed_audit_us_per_connection":
                per_connection(fixed_cost.get("audit_us", 0), fixed_timed),
            "fixed_key_us_per_connection":
                per_connection(fixed_cost.get("key_us", 0), fixed_timed),
            "fixed_audit_records_per_connection":
                per_connection(fixed_cost.get("writes", 0), fixed_timed),
            "fixed_loop_stalls": fixed["loop_stalls"],
            # The part neither side makes cheaper, so that the figures above
            # are not read as the whole cost of an audit record.
            "metadata_sectors_per_write": metadata,
            "metadata_bytes_per_write": metadata * 512,
        }

        # The gate's own falsifiability. If the "before" is already clean this
        # is not measuring B-45, and every green figure after it is worthless.
        if summary["baseline_rewrites_per_connection"] < 3.0:
            failures.append(
                f"the baseline build shows only "
                f"{summary['baseline_rewrites_per_connection']} whole-file "
                f"rewrites of {LOG_PATH} per connection. B-45 is the claim "
                f"that there are several; with the premise gone this gate is "
                f"not measuring it and the 'after' figures mean nothing")
        if summary["baseline_key_file_reads_per_connection"] < 1.0:
            failures.append(
                f"the baseline build re-read {KEY_PATH} only "
                f"{summary['baseline_key_file_reads_per_connection']} times "
                f"per connection; the re-read this gate exists to remove is "
                f"not there to remove")

        if fixed["log_rewrites"] != 0:
            failures.append(
                f"the fixed build still rewrote {LOG_PATH} whole "
                f"{fixed['log_rewrites']} times over {fixed_conns} "
                f"connections; the append path is not taking the appends")
        if fixed["appends"] <= 0:
            failures.append(
                "the fixed build made no appends at all, so the audit log was "
                "not being written and there was nothing to make cheaper")
        # B-44's question, reported rather than asserted. A pass of sshd's
        # loop over SSHD_LOOP_STALL_REPORT_NS is a second in which this guest
        # has no networking at all, and the baseline build does produce them --
        # six, of 1.0 to 2.2 seconds, in the first forty-connection run of this
        # gate, against none in the fixed build. It is not a gate condition
        # because it is not reliably reproducible on a shared machine: whether
        # a pass crosses one second depends on what else the laptop is doing,
        # and a later run of the same two builds produced none on either side.
        # Asserting it would make this gate a gate on the host's load.

        # What is asserted is the traffic itself, which does not depend on the
        # host at all.
        if summary["baseline_file_bytes_per_connection"] < \
                5.0 * summary["fixed_file_bytes_per_connection"]:
            failures.append(
                f"the fixed build did not materially reduce the bytes this "
                f"log costs: {summary['baseline_file_bytes_per_connection']} "
                f"per connection before, "
                f"{summary['fixed_file_bytes_per_connection']} after")
        if summary["fixed_audit_us_per_connection"] > \
                summary["baseline_audit_us_per_connection"]:
            failures.append(
                f"the fixed build spends longer on the durable volume than "
                f"the baseline: {summary['fixed_audit_us_per_connection']} us "
                f"per connection against "
                f"{summary['baseline_audit_us_per_connection']}")
        if summary["fixed_key_file_reads_per_connection"] >= 1.0:
            failures.append(
                f"the fixed build still reads {KEY_PATH} "
                f"{summary['fixed_key_file_reads_per_connection']} times per "
                f"connection; the cache is not serving")

    # Control two: the cache's invalidation, shown by taking it away.
    fixed_rotation = fixed.get("rotation") or {}
    stale_rotation = stale.get("rotation") or {}
    if fixed_rotation.get("add_rc") != 0:
        failures.append(
            f"`xaiosctl auth key add` failed on the fixed build "
            f"(rc={fixed_rotation.get('add_rc')}, "
            f"{fixed_rotation.get('add_message')!r}). Without it neither side "
            f"of the cache control was exercised")
    else:
        if fixed_rotation.get("new_key_accepted") is not True:
            failures.append(
                "a key added through `xaiosctl auth key add` was not accepted "
                "by the shipped build. The cache is stale in the direction "
                "that locks an administrator out")
        if stale_rotation.get("new_key_accepted") is not False:
            failures.append(
                "the control build, whose cache never invalidates, accepted "
                "the newly added key anyway. The cache is therefore not what "
                "is being tested, and 'it invalidates' is unproven")

    report["summary"] = summary
    report["failures"] = failures
    report["status"] = "pass" if not failures else "fail"
    write_report(BUILD / f"qemu-sshd-audit-append{SUFFIX}-report.json", report)
    print(json.dumps({"summary": summary, "status": report["status"]},
                     indent=2, sort_keys=True))
    for failure in failures:
        print(f"qemu-sshd-audit-append-gate: FAIL: {failure}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
