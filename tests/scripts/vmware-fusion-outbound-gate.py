#!/usr/bin/env python3
"""What a Fusion guest does as a client, and as something in the middle.

`vmware-fusion-network-gate.py` answers the inbound half of F-03: a bridged
guest takes a real lease, forms a global SLAAC address, answers ICMPv6 and
serves SSH and SFTP on both families. It says nothing about the guest reaching
out, and it said so, listing outbound SSH under `not_claimed` because the only
far end available was the operator's own Mac account.

That is no longer the only option. The far end here is a disposable Debian 13
container built and thrown away by this gate, published on the port this host
offers to the LAN the guest is bridged onto; nothing on the operator's machine
is touched, and no key of theirs is used. What that buys is the other three
claims F-03 still owed: the guest opening an outbound session and getting an
answer, a file moved each way and compared byte for byte, and a `direct-tcpip`
channel through the guest -- the shape OpenSSH's `ProxyJump` uses.

Every one of those has a negative control beside it, because each of them can
be made to look green by something that is not the thing:

  * an outbound session that "succeeds" because the far end would let anyone
    in -- so the same command is run once with the guest's key removed from
    the far end's `authorized_keys`, and has to be refused;
  * an SCP that reports `scp: transfer complete` and exit zero having moved
    the wrong bytes -- so the payload is compared three ways, and the gate
    additionally fetches a copy with one byte changed and requires the
    comparison to notice;
  * a forwarded channel that "opened" and carried nothing, or an `ssh -J` that
    silently bypassed the jump host because the target happens to be reachable
    from here too -- so 256 KiB is pulled through the channel and checksummed,
    and a forward to a closed port has to fail as a *channel* open failure,
    which is a different sentence from the one this host's own stack produces
    when it refuses a connection itself.

DNSSEC is the claim this host can only half answer, and the half it cannot is
left alone rather than dressed up. See `dnssec_checks` below.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time

from vmware_fusion_outbound_guest import (
    GuestShell,
    forwarding_checks,
    outbound_checks,
)
from vmware_fusion_outbound_host import (
    BUILD,
    DNS_COMPILED_FALLBACK,
    OUTBOUND_KEY,
    REPORT,
    SERIAL,
    WORK,
    build_far_end_image,
    ensure_keys,
    host_lan_address,
    reserve_port,
    smoke,
    start_far_end,
    stop_far_end,
    write_provisioning,
)

NSLOOKUP = re.compile(r"^\s*(\S+): (.+?)\s*$", re.MULTILINE)


# XAIOS_ERR_CANCELLED, which the resolver reports when a query misses its own
# deadline or the chain walk misses its budget. It is not a verdict about the
# chain; it means no verdict was reached, and reading it as one is how a
# timeout gets recorded as a refusal.
#
# This used to be the bare "error(7)" of the status code, which said nothing
# and sat one typo away from "dnssec-unverified" in a reader's eye. B-36 gave
# the shell a word for it; B-35 made the thing it names less likely, by giving
# each query in the walk its own deadline instead of sharing one across all of
# them.
TIMED_OUT = "dnssec-timeout"

# B-33's fixture zone, answered from the committed chain in boot-test
# builds. 10.53.0.7 is the address the chain signs; the forged name shares
# its zone and key with one bit flipped in the signature.
DNSSEC_FIXTURE_NAME = "selftest"
DNSSEC_FIXTURE_FORGED = "forged.selftest"
DNSSEC_FIXTURE_ADDRESS = "10.53.0.7"


def guest_nslookup(shell: GuestShell, name: str, *, attempts: int = 40,
                   retry_timeouts: int = 0) -> str:
    """The guest's answer for one name, waited out rather than sampled once.

    The resolver is asynchronous: the first call starts the chain and returns
    `pending`, and the answer arrives on a later call. A check that read the
    first reply would record `pending` for everything and never fail.

    `retry_timeouts` restarts the whole resolution when it comes back as
    `dnssec-timeout`. Each query in the chain now has its own fifteen-second
    deadline and the walk as a whole has a forty-five-second budget, so a slow
    delegation no longer spends the whole allowance on one hop -- but a walk
    can still run out, and retrying gives it another budget rather than filing
    the timeout as an answer.
    """
    for attempt in range(retry_timeouts + 1):
        answer = "pending"
        for _ in range(attempts):
            output = shell.command(f"nslookup {name}")
            found = None
            for owner, value in NSLOOKUP.findall(output):
                if owner.lower() == name.lower():
                    found = value
            if found is not None:
                answer = found
            if answer != "pending":
                break
            time.sleep(1.0)
        if answer != TIMED_OUT or attempt == retry_timeouts:
            return answer
        time.sleep(2.0)
    return answer


def dnssec_checks(shell: GuestShell, checks: dict[str, object],
                  failures: list[str], not_claimed: list[str]) -> None:
    """What this host can and cannot establish about the guest's resolver.

    This used to say a signed chain could not be staged inside a guest, and
    gave a good reason: the anchors are the compiled IANA roots,
    `dnssec_set_trust_anchors` has no in-guest caller, and the resolver address
    comes from the DHCP lease with no override, so a chain this gate controlled
    had no root to hang from. B-33 gave it one. In boot-test builds -- which is
    how `vmware-fusion-smoke` builds this guest -- the resolver answers
    `selftest` and `forged.selftest` from the chain committed at
    `kernel/net/dns_selftest_chain.h`, walking it in full with the anchor
    passed in as the parent DS set rather than installed globally. That is
    asserted here, and it is the claim.

    Two further things are asserted, and neither of them is:

      * the resolver was wired from the bridged lease rather than falling back
        to the compiled address, which is falsifiable and fails whenever the
        bridge or the lease does; and
      * an RFC 6761 `.invalid` name yields no address, which is the fail-closed
        contract. This one cannot go red on a healthy machine and is recorded
        as a contract assertion rather than as evidence.

    `XAIOS_FUSION_DNSSEC_LIVE=1` runs the pair that does demonstrate local
    validation -- `example.com`, correctly signed, against `dnssec-failed.org`,
    deliberately signed wrong, through the same LAN resolver in the same
    minute. When both land it is its own negative control: the bogus answer is
    present and handed to the guest, because the guest sets CD and the upstream
    passes the RRset through, so a refusal is a signature decision and nothing
    else. It has been seen to land -- `example.com` to an address and
    `dnssec-failed.org` to `dnssec-unverified` -- and it is still recorded as
    an observation that never fails the gate, for two reasons. It needs the
    public internet, which no gate here may. And it does not always reach a
    verdict: the longer chain was observed spending its budget and saying so,
    which reports a timeout and says nothing about the signature. That used to
    be much easier to hit, because the whole walk shared one fifteen-second
    budget against a five-second retransmit timer (B-35); each query now has
    that budget to itself and the walk has one of its own. Failing a gate on a
    timeout would be reporting the weather; passing on it would be worse.
    """
    text = SERIAL.read_text(errors="replace")
    lease = re.search(r"network: DHCP lease ip=\w+ mask=\w+ gw=\w+ dns=(\w+)",
                      text)
    configured = re.search(
        r"dns: configured validating resolver (\d+\.\d+\.\d+\.\d+)", text)
    leased_dns = (str(ipaddress.IPv4Address(int(lease.group(1), 16)))
                  if lease else None)
    checks["dnssec_resolver_wiring"] = {
        "dhcp_offered_dns": leased_dns,
        "resolver_configured": configured.group(1) if configured else None,
        "compiled_fallback": DNS_COMPILED_FALLBACK,
        "from_bridged_lease": bool(
            configured and leased_dns
            and configured.group(1) == leased_dns
            and configured.group(1) != DNS_COMPILED_FALLBACK),
    }
    if not checks["dnssec_resolver_wiring"]["from_bridged_lease"]:
        failures.append(
            f"the guest did not take its validating resolver from the bridged "
            f"lease: DHCP offered {leased_dns}, the resolver was configured as "
            f"{configured.group(1) if configured else None}")

    # The signed chain, validated inside this guest, on this hypervisor.
    #
    # This is what the docstring above used to say could not be staged, and
    # the reason it gave was right at the time: the anchors are the compiled
    # IANA roots, dnssec_set_trust_anchors has no in-guest caller, and the
    # resolver address comes from the bridged lease, so a chain we control had
    # no root to hang from. B-33 gave it one. Under XAIOS_BOOT_TEST_APPS --
    # which vmware-fusion-smoke builds this guest with -- the resolver answers
    # two names from the chain committed at kernel/net/dns_selftest_chain.h,
    # walking root DNSKEY to DS to child DNSKEY to RRSIG with the anchor passed
    # in as the parent DS set rather than installed globally. No packet leaves
    # the guest, nothing depends on the LAN's resolver, and no anchor is
    # swapped underneath a real resolution.
    #
    # The pair is its own control: the two names share a zone and a key and
    # differ by one flipped bit in the signature. Both answering means nothing
    # is being verified; neither answering means the resolver is broken rather
    # than strict. Only good-resolves-and-forged-refused can happen if the
    # chain is really being walked.
    good = guest_nslookup(shell, DNSSEC_FIXTURE_NAME, attempts=12)
    forged = guest_nslookup(shell, DNSSEC_FIXTURE_FORGED, attempts=12)
    checks["dnssec_local_chain"] = {
        "name": DNSSEC_FIXTURE_NAME,
        "answer": good,
        "expected": DNSSEC_FIXTURE_ADDRESS,
        "forged_name": DNSSEC_FIXTURE_FORGED,
        "forged_answer": forged,
        "validated": good == DNSSEC_FIXTURE_ADDRESS,
        "forged_refused": forged == "dnssec-unverified",
    }
    if good != DNSSEC_FIXTURE_ADDRESS:
        failures.append(
            f"the guest did not validate the committed signed chain: "
            f"{DNSSEC_FIXTURE_NAME} answered {good!r}, expected "
            f"{DNSSEC_FIXTURE_ADDRESS}. This walk needs no network and no "
            f"LAN resolver, so a failure here is the guest's own validator")
    if forged != "dnssec-unverified":
        failures.append(
            f"the guest accepted a tampered signature: "
            f"{DNSSEC_FIXTURE_FORGED} answered {forged!r}, expected "
            f"dnssec-unverified. The forged zone differs from the good one by "
            f"a single bit in the RRSIG, so accepting it means the signature "
            f"is not being checked at all")

    unresolvable = f"{secrets.token_hex(6)}.xaios-fusion-gate.invalid"
    answer = guest_nslookup(shell, unresolvable, attempts=8)
    manufactured = False
    try:
        ipaddress.ip_address(answer)
        manufactured = True
    except ValueError:
        manufactured = False
    checks["dnssec_fail_closed"] = {
        "name": unresolvable,
        "answer": answer,
        "no_address_returned": not manufactured,
        "note": "a contract assertion, not evidence: on a healthy machine "
                "nothing can make this go red",
    }
    if manufactured:
        failures.append(
            f"the guest returned an address for a name that cannot exist: "
            f"{unresolvable} -> {answer}")

    # The claim stays open whatever the observation below says. A gate cannot
    # rest on the public internet, and this one does not: the sentence names
    # what would have to change for the claim to be closable here.
    not_claimed.append(
        "live recursive DNSSEC against a public resolver: that needs the "
        "internet, which no gate here may depend on, and it does not always "
        "reach a verdict. XAIOS_FUSION_DNSSEC_LIVE=1 records the signed-versus"
        "-bogus pair as an observation that never affects pass or fail. Local "
        "validation of a signed chain is no longer in this list -- see "
        "dnssec_local_chain above")

    if os.environ.get("XAIOS_FUSION_DNSSEC_LIVE") != "1":
        return

    signed = guest_nslookup(shell, "example.com", retry_timeouts=1)
    bogus = guest_nslookup(shell, "dnssec-failed.org", retry_timeouts=2)
    signed_ok = False
    try:
        signed_ok = ipaddress.ip_address(signed).version == 4
    except ValueError:
        signed_ok = False
    if signed_ok and bogus == "dnssec-unverified":
        verdict = ("the guest accepted a correctly signed chain and refused a "
                   "mis-signed one through the same resolver")
    elif TIMED_OUT in (signed, bogus):
        verdict = ("inconclusive: a resolution spent its budget before "
                   "reaching a verdict, which is a timeout and not a "
                   "signature decision")
    else:
        verdict = (f"inconclusive: signed={signed!r} bogus={bogus!r}, which is "
                   f"neither the accept-and-refuse pair nor a timeout")
    checks["dnssec_live_chain_observation"] = {
        "contributes_to_status": False,
        "requires_public_internet": True,
        "signed_name": "example.com",
        "signed_answer": signed,
        "signed_accepted": signed_ok,
        "bogus_name": "dnssec-failed.org",
        "bogus_answer": bogus,
        "bogus_refused": bogus == "dnssec-unverified",
        "verdict": verdict,
    }
    print(f"vmware-fusion-outbound-gate: DNSSEC observation -- {verdict}",
          flush=True)


CONTAINER = f"xaios-fusion-outbound-{os.getpid()}"


def main() -> int:
    if sys.platform != "darwin":
        print("vmware-fusion-outbound-gate: needs macOS with VMware Fusion")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"vmware-fusion-outbound-gate: no vmrun at {smoke.VMRUN}; "
              f"skipping")
        return 0
    if shutil.which("docker") is None:
        print("vmware-fusion-outbound-gate: the far end is a Docker "
              "container and there is no docker on PATH; skipping")
        return 0

    BUILD.mkdir(parents=True, exist_ok=True)
    smoke.ensure_test_key()
    ensure_keys()
    host_ip, netmask = host_lan_address()
    port = reserve_port()

    # The guest's client identity has to be inside the image, so it is set
    # before the build rather than after: build_guest copies this environment.
    os.environ["XAIOS_SSH_CLIENT_IDENTITY_FILE"] = str(OUTBOUND_KEY)
    smoke.build_guest()
    # After the build, not before: a failed build-image.sh clears build/ on its
    # way out, and a working directory created ahead of it comes back missing.
    WORK.mkdir(parents=True, exist_ok=True)
    build_far_end_image()
    write_provisioning()

    failures: list[str] = []
    checks: dict[str, object] = {"host_lan_address": host_ip,
                                 "far_end_port": port}
    not_claimed: list[str] = [
        "outbound SSH and SCP over IPv6: the far end is published on this "
        "host's IPv4 LAN address only, so nothing here exercises the guest's "
        "client on the other family",
        "behaviour under loss or reordering: the LAN is not a controlled link",
    ]
    shell: GuestShell | None = None
    try:
        start_far_end(CONTAINER, port)
        smoke.stop_hard()
        guest_ip, _ = smoke.start_vm(0)
        checks["guest_ipv4"] = guest_ip
        network = ipaddress.IPv4Network(f"{host_ip}/{netmask}", strict=False)
        checks["guest_shares_host_lan"] = (
            ipaddress.IPv4Address(guest_ip) in network)
        if not checks["guest_shares_host_lan"]:
            failures.append(
                f"the guest took {guest_ip}, which is not on {network}; the "
                f"far end is published on this host's LAN address and a guest "
                f"elsewhere cannot reach it")

        shell = GuestShell(guest_ip)
        outbound_checks(shell, CONTAINER, host_ip, port, checks, failures)
        token = (WORK / "token.txt").read_text(encoding="ascii").strip()
        forwarding_checks(CONTAINER, guest_ip, host_ip, port, token, checks,
                          failures)
        dnssec_checks(shell, checks, failures, not_claimed)
    except (OSError, RuntimeError, subprocess.SubprocessError,
            TimeoutError) as error:
        failures.append(str(error))
    finally:
        if shell is not None:
            try:
                shell.close()
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
        try:
            smoke.stop_hard()
        except (OSError, RuntimeError, subprocess.SubprocessError,
                TimeoutError) as error:
            failures.append(f"cleanup: the Fusion VM did not stop: {error}")
        stop_far_end(CONTAINER)

    report = {
        "schema": "xaios.vmware-fusion.outbound.v1",
        "status": "pass" if not failures else "fail",
        "fusion_version": smoke.fusion_version(),
        "revision": smoke.git_revision(),
        "attachment": "bridged",
        "far_end": "disposable Debian 13 OpenSSH container on this host's LAN "
                   "address; no account or setting on the Mac is used",
        "checks": checks,
        "failures": failures,
        "not_claimed": not_claimed,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vmware-fusion-outbound-gate: FAIL {failure}")
        print(f"vmware-fusion-outbound-gate: report={REPORT}")
        return 1
    forward = checks.get("forward_payload", {})
    print(f"vmware-fusion-outbound-gate: guest {checks.get('guest_ipv4')} "
          f"opened SSH and SCP to {host_ip}:{port} with content verified both "
          f"ways, carried {forward.get('bytes_received')} bytes through a "
          f"direct-tcpip channel, and refused the wrong key, a corrupted "
          f"payload and a closed forward; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
