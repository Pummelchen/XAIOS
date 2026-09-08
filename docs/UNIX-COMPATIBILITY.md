# Unix compatibility boundary

What XAIOS claims and does not claim relative to Unix, what evidence exists for
each claim, and the rule for new guest code, live on the published Wiki at
[Unix Compatibility](https://github.com/Pummelchen/XAIOS/wiki/Unix-Compatibility)
(`wiki/Unix-Compatibility.md` in this repository).

The subject was covered on both sides. Neither treatment was a specification —
the command surface is specified by
[Applications](https://github.com/Pummelchen/XAIOS/wiki/Applications) and
[Commands](https://github.com/Pummelchen/XAIOS/wiki/Commands), which the
repository checks read, and this file was a third description of the same
utilities. Stating what the system is and is not is orientation, so the
single copy is the published one.

The version claim this file carried is a good illustration of why one copy is
better than two: it bounded the command surface by xaibootFS v5 and a 4 MiB
data capacity long after the filesystem moved to v6 and 1 GiB.
