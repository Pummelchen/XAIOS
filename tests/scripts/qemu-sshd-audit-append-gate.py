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
import subprocess
import sys

from qemu_sshd_audit_append_lib import (APPEND_SELF_TEST, ARCH, BUILD,
                                        CONNECTIONS, KEY_PATH, LOG_PATH, ROOT,
                                        SUFFIX, metadata_sectors,
                                        per_connection, run_configuration,
                                        write_report)


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
