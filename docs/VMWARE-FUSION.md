# VMware Fusion ARM64

The Fusion guest profile — what is qualified, what it was verified doing, how
to build and run it, and what is still open — lives on the published Wiki at
[VMware Fusion](https://github.com/Pummelchen/XAIOS/wiki/VMware-Fusion)
(`wiki/VMware-Fusion.md` in this repository).

This is the pair that drifted furthest. Both files described the same profile,
and by the time they were merged this one still said Fusion multi-vCPU startup
was outside the profile, that VMXNET3 was not implemented, and that IPv6 needed
separate qualification. All three had been closed and gated: four vCPUs come
online and `make vmware-fusion-smoke` holds the guest to the count in the VMX,
`XAIOS_FUSION_NIC=vmxnet3` carries real traffic, and a bridged guest configures
a globally routable SLAAC address. A reader had no way to tell which file to
believe, which is the entire argument for having one.

Fusion is a platform, and describing what a platform does is the Wiki's job.
The two specifications underneath it stayed here:

- [Firmware platform profiles](./FIRMWARE-PLATFORM-PROFILES.md) — the
  three-profile evidence contract Fusion reports under, and the report format
  that makes a passing run checkable
- [Hardware portability](./HARDWARE-PORTABILITY.md) — the rule that keeps the
  E1000E and AHCI drivers selected by PCI identity rather than by recognizing
  the hypervisor, and the qualification layers above it
