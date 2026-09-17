#!/usr/bin/env python3
import os
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from qemu_gate_lib import (arch_from_argv, contract, dropped_line_note,
                           parse_telemetry, qemu_boot_environment, qemu_runner,
                           validate_telemetry_against_contract)

from qemu_smoke_markers import (ARCH_TARGETS, OR_TARGETS, PATTERN_TARGETS,
                                SKIP_MARKERS, TARGETS)


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


def describe_refusals(text: str) -> str:
    """Name the self-tests the guest reported as not run, for the run's log.

    A reader of this gate's output could not previously tell a smoke that
    passed with every self-test executed from one that passed with two of them
    refused, because both printed nothing but the absence of a failure.
    `wiki/Testing-XAIOS.md` says a skip should be a verdict in its own right;
    the closest this gate can come without inventing a fourth verdict is to say
    them out loud.
    """
    refused = sorted(marker for marker in SKIP_MARKERS if marker in text)
    if not refused:
        return ""
    lines = [f"self-test not run, as the guest reported it: {marker}\n"
             for marker in refused]
    return "".join(lines)


# The image each architecture's shared smoke has to be looking at, and the
# reason it has to say so itself.
#
# This gate used to reach the guest through `make <arch runner target>`. For
# AArch64 that target is a bare runner invocation, but for x86-64 it is
# `qemu-x86_64: image-x86_64` -- which runs `build-image.sh` *without*
# `XAIOS_BOOT_TEST_APPS=1` and so overwrites the boot image with the
# configuration this gate is not asking about, immediately before booting it.
# Without the boot test apps the splash owns the console and the kernel log is
# suppressed: the machine comes up perfectly, `SSH server: up and running`
# appears, and 214 of the markers below are invisible. That is why no milestone
# gate had ever applied to x86-64, and why the first attempt to fix it -- build
# the test image first -- changed nothing: the build step was correct and the
# `make` target rebuilt over it one line later.
#
# So this gate builds its own configuration and then starts the runner itself,
# which is what `make qemu-aarch64` was doing for AArch64 all along. Building
# the image explicitly also removes the luck that leg was relying on: it passed
# because the test image happened to be the one in `build/`, not because
# anything asked for it.
#
# RISC-V is absent here and that is a gap rather than a decision: its image is
# built by two scripts instead of by a make target, so `qemu-riscv64-update-gate`
# builds it itself and the RISC-V leg below still depends on that having
# happened.
TEST_IMAGE_TARGETS = {
    "aarch64": "image-qemu-test",
    "x86_64": "image-x86_64-qemu-test",
}


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    targets = list(TARGETS) + list(ARCH_TARGETS.get(arch, []))
    env = os.environ.copy()
    log_path = Path(f"build/qemu-smoke-{arch}.log" if arch != "aarch64"
                    else "build/qemu-smoke.log")
    persistent_image = Path(f"build/xaios-smoke-persistent-{arch}.img"
                            if arch != "aarch64"
                            else "build/xaios-smoke-persistent.img")
    persistent_image.unlink(missing_ok=True)
    state_dir = Path(f"build/qemu-smoke-{arch}-state")
    if arch == "riscv64":
        shutil.rmtree(state_dir, ignore_errors=True)
        state_dir.mkdir(parents=True, exist_ok=True)
    # A blank disk for the partition self-test to write a table onto. Without
    # one the kernel says the scratch device is unavailable and skips the
    # test, which is how the partition table writer went this long without
    # ever running against a device. Fresh every run: the test deletes what it
    # creates, and a disk carrying the last run's leftovers would let a broken
    # cleanup pass unnoticed.
    scratch_image = Path("build/xaios-smoke-storage-admin.img")
    scratch_image.unlink(missing_ok=True)
    with scratch_image.open("wb") as handle:
        handle.truncate(16 * 1024 * 1024)
    env = qemu_boot_environment(arch, env, persistent=persistent_image,
                                storage_admin=scratch_image,
                                state_dir=state_dir, hostfwd_port="none",
                                serial_to_stdout=True)
    # Build the configuration this gate is about to assert, then start the
    # runner directly. See TEST_IMAGE_TARGETS for why neither step is optional.
    test_image = TEST_IMAGE_TARGETS.get(arch)
    if test_image is not None:
        built = subprocess.run(["make", test_image], env=env,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True,
                               check=False)
        if built.returncode != 0:
            sys.stdout.write(built.stdout)
            print(f"qemu-smoke: could not build {test_image}, so the machine "
                  f"below would not be the one this gate is asking about")
            return 1

    proc = subprocess.Popen(
        [qemu_runner(arch)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        start_new_session=True,
    )
    seen = []
    # A full QEMU boot includes the complete userspace/resource gate. Keep a
    # bounded timeout, but leave margin for an unloaded Apple Silicon host.
    # RISC-V boots the same closure through an interpreter with no host
    # acceleration available for it, so it needs longer for the same work.
    # A shared number would either fail that machine or stop bounding the
    # other two.
    default_timeout = "420" if arch == "riscv64" else "120"
    deadline = time.time() + int(
        os.environ.get("XAIOS_QEMU_SMOKE_TIMEOUT", default_timeout))
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
                if (all(target in text for target in targets) and
                        all(pattern.search(text) for pattern in PATTERN_TARGETS) and
                        all(any(alt in text for alt in group) for group in OR_TARGETS) and
                        telemetry_line_complete(text) and not telemetry_failures):
                    # Before the verdict, so a run that passed with two
                    # self-tests refused says which ones. The verdict is
                    # unchanged: every marker here is still required, because
                    # the guest reporting the absence is the evidence. See
                    # SKIP_MARKERS.
                    echo_best_effort(describe_refusals(text))
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
    missing = [target for target in targets if target not in text]
    missing.extend(pattern.pattern for pattern in PATTERN_TARGETS
                   if not pattern.search(text))
    for group in OR_TARGETS:
        if not any(alt in text for alt in group):
            missing.append(f"({' | '.join(group)})")

    # Name the self-tests that were refused rather than run, so "passed" and
    # "passed with two of them skipped" are different sentences in the log.
    # This changes no verdict: every marker here is still required, because the
    # guest reporting the absence is the evidence. See SKIP_MARKERS.
    echo_best_effort(describe_refusals(text))

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
    # A missing marker and a dropped line look the same from here, and the
    # kernel now says when it has dropped one (`klog: N log lines dropped`).
    # Printed with the failure so the reader does not have to know to look for
    # it: under load this is the difference between "the machine did not do it"
    # and "the machine did it and the console lost the sentence".
    note = dropped_line_note(text)
    if note:
        echo_best_effort(f"{note}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
