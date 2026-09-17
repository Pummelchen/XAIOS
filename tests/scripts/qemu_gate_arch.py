#!/usr/bin/env python3
# The architecture half of the QEMU gate helper, split out of qemu_gate_lib so
# that the shared helper stays under the repository's 500-line limit. Nothing
# in the code below changed in the move: every gate still imports these names
# from qemu_gate_lib, which re-exports them, so a caller cannot tell.
from __future__ import annotations

import os
from typing import Any, Dict, List, Sequence


# --------------------------------------------------------------- architecture
#
# Three machines, three runners, and three sets of names for the same knobs:
# aarch64 reads XAIOS_QEMU_* and XAIOS_PERSISTENT_IMAGE, x86_64 mixes
# XAIOS_QEMU_* with XAIOS_QEMU_X86_* and XAIOS_X86_PERSISTENT_IMAGE, and
# riscv64 reads XAIOS_RISCV64_* throughout and keeps its disks in a state
# directory rather than naming an image. Renaming any of that would break
# every existing caller for no gain, so the difference lives here instead:
# one place that a gate asks "boot this architecture" and gets the right
# names. A gate that hardcodes a runner can reach exactly one machine, which
# is how a third architecture ends up with six gates against seventy.

QEMU_ARCHES = ("aarch64", "x86_64", "riscv64")

_MAKE_TARGETS = {
    "aarch64": "qemu-aarch64",
    "x86_64": "qemu-x86_64",
    "riscv64": "qemu-riscv64",
}


def arch_from_argv(argv: Sequence[str], default: str = "aarch64") -> str:
    """--arch NAME or --arch=NAME, validated. Gates take it the same way."""
    arch = default
    for index, argument in enumerate(argv):
        if argument == "--arch" and index + 1 < len(argv):
            arch = argv[index + 1]
        elif argument.startswith("--arch="):
            arch = argument.split("=", 1)[1]
    if arch not in QEMU_ARCHES:
        raise SystemExit(f"unsupported --arch {arch!r}; expected one of "
                         f"{', '.join(QEMU_ARCHES)}")
    return arch


def qemu_make_target(arch: str) -> str:
    return _MAKE_TARGETS[arch]


def qemu_boot_environment(arch: str, env: Dict[str, str], *,
                          persistent: Any = None,
                          persistent_sectors: Any = None,
                          storage_admin: Any = None,
                          system_volume: Any = None,
                          state_dir: Any = None,
                          hostfwd_port: Any = None,
                          hostfwd_udp_port: Any = None,
                          smp: Any = None,
                          boot_mode: Any = None,
                          extra_args: Any = None,
                          qmp_socket: Any = None,
                          keyboard: Any = None,
                          accel: Any = None,
                          user_net_cidr: Any = None,
                          net_socket_port: Any = None,
                          net_socket_port_2: Any = None,
                          net_socket_host: Any = None,
                          model_discard: Any = None,
                          xai_fs: Any = None,
                          serial_to_stdout: bool = False) -> Dict[str, str]:
    """The knobs for one boot, under the names this architecture's runner reads.

    Three of them -- the durable volume's file and size, and the signed A/B
    system volume -- happen to share a name across all three runners, so they
    are set unconditionally. The rest differ, and that is what this exists for.

    `serial_to_stdout` matters only on RISC-V, whose runner writes the console
    to a file by default. A gate that reads the boot from the runner's stdout,
    as the smoke helper does, needs it; one that reads the log file does not.

    `boot_mode` also matters only on RISC-V, which is the one architecture
    here that can start either way: "kernel" hands the ELF to QEMU, "uefi"
    boots the medium through EDK2. A gate about the A/B system volume needs
    uefi, because with -kernel nothing has chosen a slot.
    """
    env = dict(env)
    if extra_args is not None:
        env["XAIOS_QEMU_EXTRA_ARGS" if arch != "riscv64"
            else "XAIOS_RISCV64_EXTRA_ARGS"] = str(extra_args)
    if qmp_socket is not None:
        env["XAIOS_QEMU_QMP_SOCKET" if arch != "riscv64"
            else "XAIOS_RISCV64_QMP_SOCKET"] = str(qmp_socket)
    if hostfwd_udp_port is not None:
        env["XAIOS_QEMU_HOSTFWD_UDP_PORT" if arch != "riscv64"
            else "XAIOS_RISCV64_HOSTFWD_UDP_PORT"] = str(hostfwd_udp_port)
    if user_net_cidr is not None:
        env["XAIOS_QEMU_USER_NET_CIDR" if arch != "riscv64"
            else "XAIOS_RISCV64_USER_NET_CIDR"] = str(user_net_cidr)
    if xai_fs is not None:
        env["XAIOS_XAI_FS_IMAGE"] = str(xai_fs)
    if model_discard is not None:
        # The one knob all three runners already spell the same way, because
        # the RISC-V one was taught it under the existing name rather than
        # given a fourth spelling of the same idea.
        env["XAIOS_QEMU_MODEL_DISCARD"] = str(model_discard)
    prefix = "XAIOS_QEMU" if arch != "riscv64" else "XAIOS_RISCV64"
    if net_socket_port is not None:
        env[f"{prefix}_NET_SOCKET_PORT"] = str(net_socket_port)
    if net_socket_port_2 is not None:
        env[f"{prefix}_NET_SOCKET_PORT_2"] = str(net_socket_port_2)
    if net_socket_host is not None:
        env[f"{prefix}_NET_SOCKET_HOST"] = str(net_socket_host)
    if keyboard is not None:
        env["XAIOS_QEMU_KEYBOARD" if arch != "riscv64"
            else "XAIOS_RISCV64_KEYBOARD"] = str(keyboard)
    if persistent is not None:
        env["XAIOS_PERSISTENT_IMAGE"] = str(persistent)
    if persistent_sectors is not None:
        env["XAIOS_PERSISTENT_SECTORS"] = str(persistent_sectors)
    if system_volume is not None:
        env["XAIOS_SYSTEM_VOLUME_IMAGE"] = str(system_volume)
    if arch == "aarch64":
        if accel is not None:
            env["XAIOS_QEMU_ACCEL"] = str(accel)
        if storage_admin is not None:
            env["XAIOS_STORAGE_ADMIN_IMAGE"] = str(storage_admin)
        if hostfwd_port is not None:
            env["XAIOS_QEMU_HOSTFWD_PORT"] = str(hostfwd_port)
        if smp is not None:
            env["XAIOS_QEMU_SMP"] = str(smp)
    elif arch == "x86_64":
        if accel is not None:
            env["XAIOS_QEMU_X86_ACCEL"] = str(accel)
        if persistent is not None:
            # Both names, deliberately: a gate that sets only the shared one
            # for an x86_64 boot falls through to the shared image, whose
            # /state holds whichever run created it. That cost a day once.
            env["XAIOS_X86_PERSISTENT_IMAGE"] = str(persistent)
        if storage_admin is not None:
            env["XAIOS_X86_STORAGE_ADMIN_IMAGE"] = str(storage_admin)
        if hostfwd_port is not None:
            env["XAIOS_QEMU_HOSTFWD_PORT"] = str(hostfwd_port)
        if smp is not None:
            env["XAIOS_QEMU_X86_SMP"] = str(smp)
    else:
        if state_dir is not None:
            env["XAIOS_RISCV64_STATE"] = str(state_dir)
        if hostfwd_port is not None:
            # "none" reaches the runner intact: it understands it, and a gate
            # that wants no host port must be able to say so rather than get
            # the default.
            env["XAIOS_RISCV64_SSH_PORT"] = str(hostfwd_port)
        if smp is not None:
            env["XAIOS_RISCV64_CPUS"] = str(smp)
        if storage_admin is not None:
            env["XAIOS_STORAGE_ADMIN_IMAGE"] = str(storage_admin)
        if boot_mode is not None:
            env["XAIOS_RISCV64_BOOT"] = str(boot_mode)
        # accel has no RISC-V spelling: there is no hypervisor for this
        # architecture on any host this runs on, so it is always TCG. A gate
        # that asks for TCG gets it; one that asked for anything else would be
        # asking for something that does not exist.
        if serial_to_stdout:
            env["XAIOS_RISCV64_SERIAL"] = "stdio"
    return env


# The environment names a gate may already be written against, and what each
# means on a machine that spells it differently. Gates that grew up on one
# architecture set XAIOS_QEMU_* directly at a dozen call sites; rewriting all
# of them to logical names would be a bigger change than teaching one place
# what they mean.
_QEMU_ENV_ALIASES = {
    "XAIOS_QEMU_HOSTFWD_PORT": "XAIOS_RISCV64_SSH_PORT",
    "XAIOS_QEMU_HOSTFWD_UDP_PORT": "XAIOS_RISCV64_HOSTFWD_UDP_PORT",
    "XAIOS_QEMU_NET_SOCKET_PORT": "XAIOS_RISCV64_NET_SOCKET_PORT",
    "XAIOS_QEMU_NET_SOCKET_PORT_2": "XAIOS_RISCV64_NET_SOCKET_PORT_2",
    "XAIOS_QEMU_NET_SOCKET_HOST": "XAIOS_RISCV64_NET_SOCKET_HOST",
    "XAIOS_QEMU_USER_NET_CIDR": "XAIOS_RISCV64_USER_NET_CIDR",
    "XAIOS_QEMU_KEYBOARD": "XAIOS_RISCV64_KEYBOARD",
    "XAIOS_QEMU_EXTRA_ARGS": "XAIOS_RISCV64_EXTRA_ARGS",
    "XAIOS_QEMU_QMP_SOCKET": "XAIOS_RISCV64_QMP_SOCKET",
    "XAIOS_QEMU_SMP": "XAIOS_RISCV64_CPUS",
    "XAIOS_QEMU_MEMORY": "XAIOS_RISCV64_MEMORY",
}


def translate_qemu_env(arch: str, env: Dict[str, str]) -> Dict[str, str]:
    """Rewrite XAIOS_QEMU_* names into what this architecture's runner reads.

    Names both runners already share -- XAIOS_PERSISTENT_IMAGE,
    XAIOS_SYSTEM_VOLUME_IMAGE, XAIOS_QEMU_RNG, XAIOS_QEMU_NET_DUMP,
    XAIOS_QEMU_MODEL_DISCARD, XAIOS_XAI_FS_IMAGE -- pass through untouched.
    Names that mean nothing here, such as the accelerator, are dropped rather
    than passed on: there is one accelerator on this machine and pretending to
    choose it would be a lie in the environment.
    """
    if arch != "riscv64":
        return dict(env)
    translated: Dict[str, str] = {}
    for name, value in env.items():
        if name in ("XAIOS_QEMU_ACCEL", "XAIOS_QEMU_CPU",
                    "XAIOS_QEMU_MSI_CONTROLLER", "XAIOS_QEMU_IOMMU"):
            continue
        translated[_QEMU_ENV_ALIASES.get(name, name)] = value
    return translated


def smoke_command(arch: str) -> List[str]:
    """The boot-closure helper, for this architecture.

    Gates that need a full boot before they assert anything run the smoke
    helper rather than a runner, which is what lets them follow the machine
    rather than name it.
    """
    command = ["python3", "./tests/scripts/qemu-smoke.py"]
    if arch != "aarch64":
        command += ["--arch", arch]
    return command


def timeout_scale() -> float:
    """How much slower this machine is than the one the budgets were written on.

    Budgets scaled by architecture and by nothing else, which is half the
    question. The other half is the host: a GitHub runner has no hardware
    virtualisation, so every guest is interpreted and everything takes several
    times longer than it does on the Mac these numbers came from. The
    fragmentation step is the example -- 96 to 98 seconds here across five
    consecutive runs, and past its 360-second budget on every CI run.

    Declared rather than detected. A gate that guesses at its host will
    eventually guess wrong and silently give itself more room, which is how a
    budget stops meaning anything; an environment that knows it is slow says so.
    """
    raw = os.environ.get("XAIOS_GATE_TIMEOUT_SCALE", "1")
    try:
        scale = float(raw)
    except ValueError:
        return 1.0
    # A scale below 1 would tighten budgets, which is not what this is for.
    return scale if scale >= 1.0 else 1.0


def smoke_timeout(arch: str, base: int) -> int:
    """A budget scaled to the machine rather than to the fastest one.

    RISC-V runs the same closure through an interpreter with no host
    acceleration available for it. Gates were written with AArch64's numbers,
    and reusing them would report a slower machine as a broken one.
    """
    scaled = base * 4 if arch == "riscv64" else base
    return int(scaled * timeout_scale())


def qemu_runner(arch: str) -> str:
    """The script that starts this machine.

    Gates that drive the boot themselves -- reading the console, cutting
    power, rebooting -- cannot go through make, so they need the runner. They
    should still not name one.
    """
    return f"./platform/qemu/run-qemu-{arch}.sh"
