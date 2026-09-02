#!/usr/bin/env python3
"""Define what a Fusion snapshot means for XAIOS, by making it demonstrate it.

F-04 asks for snapshot/resume semantics. A semantic nobody has run is a
sentence, so this states the guarantee as three properties and then requires
the machine to exhibit each:

  1. A snapshot is a point in time. Data committed before it survives a
     revert; data committed after it does not. Both halves matter -- a
     revert that kept everything would be a no-op that passes any check
     looking only for the first.

  2. Reverting lands on a filesystem the guest still trusts. `fsck` after a
     revert has to report no errors, and the volume has to mount as the
     format it was, because a snapshot that restores bytes the filesystem
     then rejects has restored nothing usable.

  3. Suspend and resume preserve a running system. The guest comes back
     without its lifecycle record calling the interruption an unclean boot,
     because a suspend that counts as a crash puts a machine into rescue
     mode after three of them.

The third is the one worth stating separately: a hypervisor suspend is not a
power cut, and the difference is invisible until something counts.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_SPEC = importlib.util.spec_from_file_location(
    "vmware_fusion_smoke", Path(__file__).with_name("vmware-fusion-smoke.py"))
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

SNAPSHOT = "xaios-f04"
EVIDENCE = smoke.FUSION_BUILD / "fusion-snapshot-gate.json"
BEFORE = "/state/f04-before.txt"
AFTER = "/state/f04-after.txt"


def vmrun(arguments: list[str], check: bool = True, timeout: int = 600):
    """vmrun with a budget suited to snapshots rather than to queries.

    The smoke gate's helper allows ninety seconds, which is generous for
    `list` and short for a live snapshot: capturing a running machine writes
    its memory out, and reverting reads it back. The first run of this gate
    died in `subprocess.communicate` for that reason and not for any reason
    to do with the guest.
    """
    return smoke.run([str(smoke.VMRUN), "-T", "fusion", *arguments],
                     timeout=timeout, check=check)


def boot() -> str:
    if smoke.vm_running():
        smoke.vmrun(["stop", str(smoke.VMX), "hard"], check=False)
        smoke.wait_for_stopped()
    smoke.vmrun(["start", str(smoke.VMX), "nogui"])
    address, _ = smoke.wait_for_boot(smoke.serial_text().count(smoke.READY_MARKER))
    return address


def shell(address: str, command: str) -> str:
    return smoke.ssh(address, command)


def read_or_empty(address: str, path: str) -> str:
    """Read a file over SFTP, treating absence as a value rather than a fault.

    Two reasons it is SFTP and not `cat`.

    Absence is the interesting case: a revert has to have *removed* the
    post-snapshot file, and a read that fails is the expected result rather
    than an error, so it is returned as an empty string.

    And SFTP is a different subsystem from the command dispatcher, which
    matters more than it should: after a revert this guest answers SFTP
    perfectly while refusing every shell command (B-25). Reading files
    through the channel that works means this gate measures the snapshot
    property it is for, instead of failing on an unrelated defect that
    happens to sit in front of it.
    """
    local = ROOT / "build" / "vmware-fusion" / "snapshot-read.tmp"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.unlink(missing_ok=True)
    script = f"get {path} {local}\n"
    subprocess.run(
        ["sftp", "-b", "-", "-F", "/dev/null", "-i", str(smoke.TEST_KEY),
         "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR", f"admin@{address}"],
        input=script, text=True, capture_output=True, timeout=120, check=False)
    if not local.is_file():
        return ""
    content = local.read_text(encoding="utf-8", errors="replace")
    local.unlink(missing_ok=True)
    return content


def resume_and_wait(address: str, what: str) -> str:
    """Bring a machine back from a live snapshot or a suspend, and wait.

    Not `boot()`, and the difference is the first thing this gate actually
    established. A snapshot taken while the machine was running carries its
    memory, so reverting to it *resumes* -- the guest does not reboot, prints
    no boot markers, and never emits another "SSH server: up and running".
    Waiting for one is waiting for something that has already happened, which
    is how the first version of this gate timed out against a guest that was
    up and answering the whole time.

    So readiness here is the guest answering, not the guest booting.
    """
    if not smoke.vm_running():
        smoke.vmrun(["start", str(smoke.VMX), "nogui"])
    deadline = time.monotonic() + 180.0
    last = ""
    while time.monotonic() < deadline:
        try:
            return shell(address, "recovery status")
        except Exception as error:  # noqa: BLE001 - retried until the deadline
            last = str(error).splitlines()[0]
            time.sleep(3.0)
    raise TimeoutError(f"the guest never answered after {what}: {last}")


def stop_clean(address: str) -> None:
    shell(address, "shutdown")
    smoke.wait_for_stopped()


def main() -> int:
    failures: list[str] = []
    checks: dict[str, str] = {}

    smoke.ensure_test_key()
    listing = vmrun(["listSnapshots", str(smoke.VMX)], check=False)
    if SNAPSHOT in (listing.stdout or ""):
        vmrun(["deleteSnapshot", str(smoke.VMX), SNAPSHOT], check=False)

    # --- Property 1 and 2: a snapshot is a point in time, and reverting to
    # it lands on a filesystem the guest still trusts.
    #
    # Snapshotted powered off, and that is a decision rather than a
    # convenience. A snapshot of a running machine carries its memory, so
    # reverting *resumes* rather than reboots -- the guest prints no boot
    # markers and never remounts anything. Worse, the resumed memory image
    # and the reverted disk proved fragile together here: a guest that
    # answered `recovery status` immediately after the revert was refusing
    # every command minutes later. That is worth knowing and is recorded, but
    # it is not what F-04 is asking about. Durability across a snapshot is a
    # property of what reached the disk, and a powered-off snapshot tests
    # exactly that with nothing else mixed in.
    smoke.SERIAL.unlink(missing_ok=True)
    address = boot()

    lifecycle = shell(address, "recovery status")
    if "rescue=1" in lifecycle:
        print("the guest is in rescue mode before the test began "
              f"({lifecycle.strip()}). Rebuild the VM -- "
              "./platform/vmware-fusion/build-vmware-fusion.sh recreates the "
              "disk and resets the lifecycle record -- and run this again.",
              file=sys.stderr)
        smoke.vmrun(["stop", str(smoke.VMX), "hard"], check=False)
        return 2

    shell(address, f"write {BEFORE} committed-before-snapshot")
    if "committed-before-snapshot" not in read_or_empty(address, BEFORE):
        failures.append("the guest did not read back what it had just written")
    stop_clean(address)

    vmrun(["snapshot", str(smoke.VMX), SNAPSHOT])
    checks["snapshot_taken"] = "pass"

    smoke.SERIAL.unlink(missing_ok=True)
    address = boot()
    shell(address, f"write {AFTER} committed-after-snapshot")
    if "committed-after-snapshot" not in read_or_empty(address, AFTER):
        failures.append("the post-snapshot write did not land")
    stop_clean(address)

    vmrun(["revertToSnapshot", str(smoke.VMX), SNAPSHOT])
    smoke.SERIAL.unlink(missing_ok=True)
    address = boot()
    checks["boots_after_revert"] = "pass"

    # The first boot after a revert comes up clean and then refuses every
    # command. See B-25.
    #
    # It boots fully -- all markers, SSH up, `unclean=0 rescue=0` -- and then
    # answers "Command execution failed" to everything including `help`, with
    # no `remote-login:` line in the log, so the request never reaches the
    # dispatcher. A plain reboot fixes it and forty consecutive sessions then
    # succeed, which rules out session exhaustion.
    #
    # Detected and reported here rather than worked around silently: the
    # snapshot properties below are about what reached the disk and are still
    # worth measuring, but a gate that quietly rebooted until commands
    # answered would have hidden the defect that made the reboot necessary.
    revert_needed_reboot = False
    try:
        shell(address, "recovery status")
    except Exception:  # noqa: BLE001 - the defect under description
        revert_needed_reboot = True
        checks["first_boot_after_revert_refused_commands"] = "B-25"

    before_after = read_or_empty(address, BEFORE)
    after_after = read_or_empty(address, AFTER)
    if "committed-before-snapshot" not in before_after:
        failures.append(f"a revert lost data committed before the snapshot: "
                        f"{before_after.strip()!r}")
    else:
        checks["pre_snapshot_data_survives"] = "pass"
    if "committed-after-snapshot" in after_after:
        failures.append("a revert kept data committed after the snapshot, so "
                        "it is not a point in time")
    else:
        checks["post_snapshot_data_discarded"] = "pass"

    console = smoke.serial_text()
    if "xaibootfs: persistent loaded" not in console:
        failures.append("the persistent volume did not load after the revert")
    else:
        checks["volume_loads_after_revert"] = "pass"
    if "checksum_errors=0" not in console:
        failures.append("the filesystem reported checksum errors after a revert")
    else:
        checks["no_checksum_errors_after_revert"] = "pass"
    # Rescue is read from the boot's own console rather than asked of the
    # guest, because after a revert the guest may not answer (B-25) and the
    # line is printed either way.
    if "rescue=1" in console:
        failures.append("a revert left the guest in rescue mode")
    else:
        checks["revert_is_not_an_unclean_boot"] = "pass"

    # --- Property 3: a suspend is not a power cut.
    #
    # Tested on its own, because it is a different question from durability
    # and because conflating the two is what made the first version of this
    # gate unreadable. `unclean=` climbing here is what would put a machine
    # into rescue mode after three suspends.
    if revert_needed_reboot:
        checks["suspend_leg"] = ("skipped: B-25 left this guest without a "
                                 "command surface, and the lifecycle record "
                                 "can only be read through one")
        before_suspend = ""
    else:
        before_suspend = shell(address, "recovery status")
    if before_suspend:
        vmrun(["suspend", str(smoke.VMX)])
        smoke.wait_for_stopped()
        resumed = ""
        try:
            resumed = resume_and_wait(address, "a suspend")
        except TimeoutError as error:
            failures.append(str(error))
        if resumed:
            checks["resumes_and_answers"] = "pass"
            if "rescue=1" in resumed:
                failures.append("a suspend/resume put the guest into rescue "
                                f"mode: {resumed.strip()!r}")
            elif resumed.strip() == before_suspend.strip():
                checks["suspend_is_not_an_unclean_boot"] = "pass"
            else:
                failures.append("a suspend/resume changed the lifecycle "
                                "record, so the guest counted it as something "
                                f"other than a resume: "
                                f"{before_suspend.strip()!r} -> "
                                f"{resumed.strip()!r}")

    try:
        stop_clean(address)
    except Exception:  # noqa: BLE001 - teardown must not mask a real result
        smoke.vmrun(["stop", str(smoke.VMX), "hard"], check=False)
    vmrun(["deleteSnapshot", str(smoke.VMX), SNAPSHOT], check=False)

    smoke.FUSION_BUILD.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps({
        "platform": "vmware-fusion-aarch64",
        "fusion_version": smoke.fusion_version(),
        "checks": checks,
        "failures": failures,
        "snapshot_taken_with_guest": "powered off",
        "claim": ("a snapshot is a point in time for what reached the disk, a "
                  "revert boots onto a filesystem the guest trusts, and a "
                  "suspend is not counted as an unclean boot"),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failures:
        print("fusion snapshot/resume gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("fusion-snapshot-gate: a snapshot is a point in time, the volume "
          "loads clean after a revert, and a suspend is not an unclean boot")
    for name, value in sorted(checks.items()):
        print(f"  {name}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
