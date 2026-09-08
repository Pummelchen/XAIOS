#!/usr/bin/env python3
"""A global IPv6 address formed from a real router advertisement, under QEMU.

The capability matrix used to claim "IPv6 by SLAAC: yes" for the QEMU columns
and nothing supported it. Every QEMU guest reported only a link-local address,
so the claim was corrected to "implemented, not evidenced here" -- and this
gate exists to earn back the original word.

Why the default network could not answer it. SLIRP advertises `fec0::/64`,
which is deprecated site-local space, and this stack deliberately keeps its
public address slot for genuinely global addresses: a guest asked for a public
address must not hand out one that cannot be routed. So the guest formed a
SLAAC address, correctly declined to call it public, and reported its
link-local one. Nothing was broken; there was simply no configuration in which
the question could be put.

`ipv6-net=2001:db8::/64` puts it. That is the RFC 3849 documentation range --
reserved so it can appear in examples without colliding with a real allocation
-- and it is global scope, so an address formed from it exercises the same path
a real advertisement on a real network would.

Both networks are run, because either alone proves the wrong thing. On the
default network the guest must report link-local and no more, which is what
says the public slot is not handed a site-local address. On the global prefix
it must report an address inside that prefix, derived from its own interface
identifier. A gate that ran only the second would pass equally well against a
stack that called every address public.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout

REPORT = BUILD / "qemu-slaac-gate.json"
ARCH = os.environ.get("XAIOS_SLAAC_ARCH", "aarch64")
PREFIX = "2001:db8::"
# The trailing \r matters: a serial console ends lines with CR LF, so an
# end-of-line anchor immediately after the address never matches. This
# regex found nothing on two perfectly good boots, and the gate reported
# "no IPv6 address at all" about consoles that plainly contained one.
IPV6_LINE = re.compile(r"^IPv6: ([0-9a-fA-F:]+)\s*$", re.MULTILINE)
READY = "SSH server: up and running (tcp/22)"

CASES = (
    # (name, ipv6-net value, must the reported address be global?)
    ("default", "none", False),
    ("global-prefix", "2001:db8::/64", True),
)


def boot(ipv6_net: str, port: int) -> str:
    env = os.environ.copy()
    if ipv6_net != "none":
        env["XAIOS_QEMU_USER_NET_IPV6"] = ipv6_net
    env = qemu_boot_environment(ARCH, env, hostfwd_port=str(port),
                                serial_to_stdout=True)
    process = subprocess.Popen(
        [qemu_runner(ARCH)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env, cwd=ROOT, start_new_session=True)
    deadline = time.time() + smoke_timeout(ARCH, 240)
    output: list[str] = []
    try:
        descriptor = process.stdout.fileno()
        import select
        while time.time() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                chunk = os.read(descriptor, 8192).decode("utf-8",
                                                         errors="replace")
                if not chunk:
                    break
                output.append(chunk)
                # Wait for the address line, which is printed after the
                # readiness banner -- stopping at the banner would cut the
                # very field this gate reads.
                if IPV6_LINE.search("".join(output)) and READY in "".join(output):
                    break
            elif process.poll() is not None:
                break
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - the boot is over either way
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
    return "".join(output)


def main() -> int:
    failures: list[str] = []
    results: list[dict[str, object]] = []
    port = 2410
    for name, ipv6_net, expect_global in CASES:
        print(f"qemu-slaac-gate: booting on the {name} network", flush=True)
        text = boot(ipv6_net, port)
        port += 1
        log = BUILD / f"qemu-slaac-{name}.log"
        log.write_text(text, encoding="utf-8")
        found = IPV6_LINE.findall(text)
        address = found[-1] if found else ""
        entry = {"case": name, "ipv6_net": ipv6_net, "address": address,
                 "ra_processed": "ndp: RA processed" in text,
                 "console": str(log.relative_to(ROOT))}
        results.append(entry)
        if not address:
            failures.append(f"the {name} boot reported no IPv6 address at all")
            continue
        if not entry["ra_processed"]:
            failures.append(
                f"the {name} boot processed no router advertisement, so "
                f"whatever it reported did not come from one")
        if expect_global:
            if not address.lower().startswith(PREFIX):
                failures.append(
                    f"the {name} boot reported {address}, which is not inside "
                    f"the advertised {PREFIX}/64: no global address was formed "
                    f"from the advertisement")
        else:
            if not address.lower().startswith("fe80:"):
                failures.append(
                    f"the {name} boot reported {address} as its address on a "
                    f"network advertising only site-local space. The public "
                    f"slot is for globally routable addresses, and handing it "
                    f"a site-local one is the defect this case guards")

    report = {"schema": "xaios.qemu.slaac.v1",
              "status": "pass" if not failures else "fail",
              "architecture": ARCH,
              "results": results,
              "failures": failures}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-slaac-gate: FAIL {failure}")
        print(f"qemu-slaac-gate: report={REPORT}")
        return 1
    default = next(r["address"] for r in results if r["case"] == "default")
    globalv6 = next(r["address"] for r in results
                    if r["case"] == "global-prefix")
    print(f"qemu-slaac-gate: on a network advertising only site-local space "
          f"the guest reports {default} and no more; on one advertising "
          f"{PREFIX}/64 it forms {globalv6} from the advertisement; "
          f"report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
