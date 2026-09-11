#!/usr/bin/env python3
"""The SSH wire chunk and the syscall's transfer limit must agree.

B-46: `SSH_MAX_PACKET_SIZE` is 35000 and the network syscalls refuse anything
larger than `SOCKET_BUFFER_SIZE`, which is 16384. Three places that chunk a
transfer clamped to `SSH_MAX_PACKET_SIZE - 9` -- 34991 -- so a chunk at that
size came back `net-send-denied` rather than short-written. Nothing reached it,
because `SSH_CHANNEL_MAX_PACKET` is 10240 and bounds the data that gets that
far. It was a cliff waiting for the day someone raised the channel maximum for
a good reason.

Two of those three numbers now guard each other in C: `ssh_channel.h` asserts
at compile time that the channel maximum fits `SSH_WIRE_MAX_CHUNK`. The third
cannot be checked that way. Userspace does not get the kernel's include path --
`compile-check`'s userspace pass has no `-Ikernel/include`, and
`userspace/include/xaios/` holds only `types.h` -- so `SSH_WIRE_MAX_CHUNK` is
written as a literal, and a literal copied across that boundary is precisely
how the two came to disagree in the first place.

So this reads both files and requires them to match. It is the same job the
ABI contract does for syscall numbers, done where a header cannot reach.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL_HEADER = ROOT / "kernel" / "include" / "xaios" / "socket_buffer.h"
SSH_HEADER = ROOT / "userspace" / "sshd" / "ssh_protocol.h"
CHANNEL_HEADER = ROOT / "userspace" / "sshd" / "ssh_channel.h"


def define(path: Path, name: str) -> int:
    """One `#define NAME <number>U`, or a failure that names the file."""
    found = re.search(rf"#define\s+{name}\s+(\d+)U?\b",
                      path.read_text(encoding="utf-8"))
    if not found:
        raise SystemExit(
            f"check-ssh-wire-bound: {name} not found in "
            f"{path.relative_to(ROOT)}. This check exists to keep two numbers "
            f"in step; it cannot do that if one of them has moved or been "
            f"renamed, and passing quietly would be worse than stopping.")
    return int(found.group(1))


def main() -> int:
    socket_buffer = define(KERNEL_HEADER, "SOCKET_BUFFER_SIZE")
    wire_chunk = define(SSH_HEADER, "SSH_WIRE_MAX_CHUNK")
    channel_max = define(CHANNEL_HEADER, "SSH_CHANNEL_MAX_PACKET")
    packet_max = define(SSH_HEADER, "SSH_MAX_PACKET_SIZE")

    failures: list[str] = []
    if wire_chunk != socket_buffer:
        failures.append(
            f"SSH_WIRE_MAX_CHUNK is {wire_chunk} and SOCKET_BUFFER_SIZE is "
            f"{socket_buffer}. sshd would clamp a transfer to a size the "
            f"syscall refuses, and the refusal is net-send-denied rather than "
            f"a short write, so the transfer fails instead of taking longer")
    # The compile-time assertion in ssh_channel.h covers this too. Stated here
    # as well because a build error only reaches whoever builds, and this runs
    # in docs-check where a reviewer sees it.
    if channel_max + 9 > wire_chunk:
        failures.append(
            f"SSH_CHANNEL_MAX_PACKET is {channel_max}, which with its 9-byte "
            f"overhead exceeds SSH_WIRE_MAX_CHUNK {wire_chunk}: a full-size "
            f"channel packet could not be handed to a socket in one call")
    if packet_max < wire_chunk:
        failures.append(
            f"SSH_MAX_PACKET_SIZE {packet_max} is below SSH_WIRE_MAX_CHUNK "
            f"{wire_chunk}, so the wire chunk no longer fits the protocol's "
            f"own buffers")

    if failures:
        print("check-ssh-wire-bound: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"ssh-wire-bound: chunk {wire_chunk} matches the syscall's "
          f"{socket_buffer}, and a {channel_max}-byte channel packet fits it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
