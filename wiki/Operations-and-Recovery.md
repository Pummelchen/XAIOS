# Operations and Recovery

XAIOS has one architecture-neutral operations layer. The kernel owns lifecycle
state, resource inspection, recovery policy, and command authorization; small
architecture backends perform PSCI power calls on AArch64 and QEMU-compatible
ACPI/reset-port operations on x86_64.

## Clean shutdown and reboot

An authenticated `shutdown` or `reboot` request is acknowledged first. After a
bounded delay, XAIOS writes the lifecycle record, commits MutableFS, flushes the
persistent log, flushes every registered block device that advertises flush
support, and invokes the requested power operation. Unsupported flush capability
is reported separately from I/O failure. QEMU tests reopen the same disk after
poweroff and require `unclean_boots=0`.

## Unclean boot and rescue mode

At mount time XAIOS reads `/state/lifecycle/record`. A prior `state=running`
record means the previous instance did not complete its power transaction and
increments the consecutive unclean count. Three consecutive unclean boots or a
persistent `/state/lifecycle/rescue` marker enable rescue mode.

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

## Evidence boundary

`make qemu-operations-closure` performs abrupt termination, reboot, clean
shutdown, persistent recovery checks, and authenticated command checks against
both AArch64 and x86_64. It also uses Debian 13 OpenSSH when Docker is available.
This proves the named QEMU behavior only. Physical power loss, firmware reset,
RTC quality, thermals, PMU access, and device durability still require named
hardware qualification.
