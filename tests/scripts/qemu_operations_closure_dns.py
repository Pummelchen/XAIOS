#!/usr/bin/env python3
"""Resolver checks for the QEMU operations closure gate.

The gate is `qemu-operations-closure.py`. This is the part of it that asks the
guest's asynchronous resolver a question and tells the four possible answers
apart, split out so that the gate stays under the repository's 500-line limit.
Nothing in the code below changed in the move; the gate imports these names.
"""

from __future__ import annotations

from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import timeout_scale  # noqa: E402
from qemu_operations_closure_lib import (  # noqa: E402
    assert_contains,
    ssh_command,
)


# What "nslookup <name>" can end up saying, and what each one means. The gate
# needs all four apart, because three of them used to arrive as the same word.
#
#   an address         the chain validated
#   dnssec-unverified  the chain was walked and refused -- a verdict
#   dnssec-timeout     the walk ran out of budget -- no verdict was reached
#   invalid-argument   the command was wrong; nothing was asked about any name
DNS_UNVERIFIED = "dnssec-unverified"
DNS_TIMEOUT = "dnssec-timeout"
DNS_BAD_ARGUMENT = "nslookup: invalid-argument"

# Longer than the resolver's own walk budget (45 s), deliberately. At 15 s this
# gate gave up first and reported its own impatience as the resolver's, which
# is the wrong end of the wire to be measuring: the point is to see the verdict
# the resolver reached, including "dnssec-timeout" when it reached none.
#
# It is the *local* bound and it is scaled on a host that declares itself slow,
# the way every other wait in this file is. The budget is host-side patience
# with an SSH session, not the resolver's walk: 60 s of it was not enough on the
# CI runner, where the aarch64 leg failed with `DNS A (well-formed) produced no
# output at all for 60 seconds` on a commit that changed neither the kernel nor
# this gate, while the resolver's own budget is 45 s and was never reached.
# A stalled session is the runner's measured behaviour (B-43, B-63), and
# `timeout_scale()` is what this repository already uses to say so out loud.
DNS_PATIENCE_SECONDS = 60.0


def wait_dns_result(key: Path, port: int, command: str, label: str) -> str:
    """Wait for XAIOS's asynchronous resolver without accepting a timeout.

    An *empty* answer is waited for like a pending one rather than treated as a
    verdict, and the two are told apart when the patience runs out. The command
    is run with `ok=None`, so a connection that failed produces an empty string
    exactly as a command with nothing to say does -- and CI's aggregate caught
    this the one way it must not be caught: the aarch64 leg failed with
    `DNS A response was neither authenticated nor fail-closed: ''`, which reads
    as a resolver that answered an empty address. The run before it, with
    identical kernel and gate code, passed the same check, so what the message
    described was a probe that produced no output, not a resolver verdict.
    """
    patience = DNS_PATIENCE_SECONDS * timeout_scale()
    deadline = time.monotonic() + patience
    value = ""
    while time.monotonic() < deadline:
        value = ssh_command(key, port, command, ok=None)
        if "pending" not in value and value.strip() != "":
            return value
        time.sleep(0.5)
    if value.strip() == "":
        raise RuntimeError(
            f"DNS {label} produced no output at all for "
            f"{patience:.0f} seconds: the command printed nothing, "
            f"which is a connection that did not run rather than a resolver "
            f"that answered"
        )
    raise RuntimeError(
        f"DNS {label} remained pending for {patience:.0f} seconds, "
        f"longer than the resolver's own walk budget: it never completed at all"
    )


def check_dns_argument_errors(key: Path, port: int) -> None:
    """A malformed nslookup must be refused as a malformed nslookup.

    B-36. Every one of these used to print "dnssec-unverified" and this gate
    accepted that word as a fail-closed resolver, so a shell that reported a
    typo as a DNSSEC failure read here as a pass. The assertion that matters is
    the negative one: the argument error must not be spelled like a verdict
    about a name, because a gate that accepts both cannot tell them apart.
    """
    for command in ("nslookup example.com extra-argument",
                    "nslookup",
                    "nslookup -6",
                    "nslookup -6 a.example.com spare",
                    # 64 characters, one past what the resolver accepts: the
                    # resolver rejects it with the same code it uses for a
                    # refused chain, so the shell has to catch it first.
                    "nslookup " + "a" * 64):
        output = ssh_command(key, port, command, ok=False)
        if DNS_UNVERIFIED in output or DNS_TIMEOUT in output:
            raise RuntimeError(
                f"{command!r} reported a malformed argument as a verdict about "
                f"a name: {output!r}"
            )
        assert_contains(output, DNS_BAD_ARGUMENT)
    # ...and the same shell still answers a well-formed lookup, so the check
    # above cannot be passed by refusing every nslookup.
    well_formed = wait_dns_result(key, port, "nslookup example.com",
                                  "A (well-formed)")
    if DNS_BAD_ARGUMENT in well_formed:
        raise RuntimeError(
            f"a well-formed nslookup was rejected as malformed: {well_formed!r}"
        )
