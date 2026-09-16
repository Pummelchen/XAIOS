# Operations and Recovery

XAIOS has one architecture-neutral operations layer. The kernel owns lifecycle
state, resource inspection, recovery policy, and command authorization; small
architecture backends perform PSCI power calls on AArch64, QEMU-compatible
ACPI/reset-port operations on x86_64, and SBI system-reset calls on RISC-V.

## Clean shutdown and reboot

An authenticated `shutdown` or `reboot` request is acknowledged first. After a
bounded delay, XAIOS writes the lifecycle record, commits xaibootFS, flushes the
persistent log, flushes every registered block device that advertises flush
support, and invokes the requested power operation. Unsupported flush capability
is reported separately from I/O failure. QEMU tests reopen the same disk after
poweroff and require `unclean_boots=0`.

## Unclean boot and rescue mode

At mount time XAIOS reads `/state/lifecycle/record`. A prior `state=running`
record means the previous instance did not complete its power transaction and
increments the consecutive unclean count. Three consecutive unclean boots or a
persistent `/state/lifecycle/rescue` marker enable rescue mode.

Every boot then says on the console what became of its own record, in every
build:

    lifecycle: record durable state=running boots=2 unclean=1 storage=disk status=ok

`durable` is the only verdict that means the next boot can read it. A machine
whose state volume did not mount runs on a volume made of memory and says
`volatile ... storage=memory`; a write, commit or flush failure says
`unwritten` with the status; a machine with no state volume at all says
`absent`. This is written before SSH starts, because a test that kills a guest
to make an unclean boot has to know the record it will ask about is already on
the disk -- reaching SSH does not say that.

Rescue mode still starts networking and SSH so an administrator can inspect the
system. It permits status, support, clock/network diagnostics, update status,
power actions, and bounded file inspection/repair. Other application commands
fail explicitly. `recovery clear` removes the forced marker and resets the
consecutive count.

## Clock sources

`date` reports `rtc`, `manual`, or `ntp` as the active source. `date -s EPOCH`
rejects overflow and dates before 2000. `ntp sync [IP]` sends an SNTPv4 request,
binds the response to its originate timestamp, validates server mode/version
and stratum, applies half the measured RTT, retries once, and then exposes a
timeout rather than pretending synchronization. The default server is
`162.159.200.1`; deployment policy should configure an approved source.

## Resource and support output

`limits` classifies pressure from free physical pages and process-table use,
while retaining the underlying counts. `support` emits a bounded redacted text
bundle with build identity, lifecycle, timer frequency, CPU count, memory,
process, filesystem, network, resolver, and log-ring counters. Thermal and PMU
fields say `unavailable` until a real platform backend exists; QEMU values are
never fabricated.

## Worked examples

**Shut down or reboot, and see that it was clean.**

```text
admin@xaios:/$ shutdown
shutdown: acknowledged; writing lifecycle record
admin@xaios:/$ reboot
```

The machine acknowledges first and powers down after it has flushed; the
`lifecycle:` line on the *next* boot is the confirmation:

```text
lifecycle: record durable state=running boots=2 unclean=0 storage=disk status=ok
```

`unclean=0` means the previous instance completed its power transaction. A
`volatile … storage=memory` line means the state volume did not mount and this
boot is running on memory; `unwritten` names a write, commit or flush failure;
`absent` means there was no state volume at all.

**After a machine that was killed rather than shut down.**

```text
admin@xaios:/$ recovery status
admin@xaios:/$ recovery clear
```

`status` reports the consecutive unclean count and whether the rescue marker is
set; `clear` removes a *forced* marker and resets the count, which is what an
administrator does once the cause is understood. Three consecutive unclean boots
enter rescue mode on their own.

**What rescue mode will and will not do.** Networking and SSH still come up so
the machine can be inspected. Status, support, clock and network diagnostics,
update status, power actions and bounded file inspection/repair all work;
anything else fails explicitly rather than half-running.

**Correct the clock.**

```text
admin@xaios:/$ date
admin@xaios:/$ ntp sync
admin@xaios:/$ ntp status
admin@xaios:/$ date -s 1789000000
```

`ntp sync` sends one bounded SNTPv4 request, validates the reply and applies
half the measured round trip; if no reply arrives it reports a timeout rather
than claiming synchronization. The default server is `162.159.200.1` — an
approved source belongs in deployment policy.

**Before opening a bug.**

```text
admin@xaios:/$ limits
admin@xaios:/$ support
```

`limits` gives the pressure verdict and the memory, heap, process, filesystem and
CPU counts behind it; `support` is the redacted bundle to capture on the host
and attach to a report.

## Evidence boundary

`make qemu-operations-closure` performs abrupt termination, reboot, clean
shutdown, persistent recovery checks, and authenticated command checks against
AArch64 and x86_64; it has no RISC-V leg. It also uses Debian 13 OpenSSH when
Docker is available.
This proves the named QEMU behavior only. Physical power loss, firmware reset,
RTC quality, thermals, PMU access, and device durability still require named
hardware qualification.

The consolidated pre-physical evidence packet is
`make qemu-qualification-readiness`. It preserves this boundary while
collecting the QEMU network/SSH, storage, topology, diagnostic, and sustained
soak reports in one hashed manifest. See
[`docs/PHYSICAL-QUALIFICATION-READINESS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PHYSICAL-QUALIFICATION-READINESS.md).
