# Getting started

Setting up a toolchain, building an image, and booting it live on the
published Wiki, at
[Getting Started](https://github.com/Pummelchen/XAIOS/wiki/Getting-Started)
(`wiki/Getting-Started.md` in this repository). That page also covers taking a
released build instead of building one, which this file never did.

Both existed for a long time and drifted. This one still said SSH waits for an
external DNS lookup before it binds port 22; it waits for the interface to hold
a usable IPv4 address and deliberately probes no external name or endpoint.
Installing and running a system is operation, so it belongs where the
documentation is published.

The part of this guide that was not orientation was the contract for adding a
program to XAIOS — where its name is registered, how it becomes reachable, and
what capability mask it runs under. That is now
[Application development](./APPLICATION-DEVELOPMENT.md).

For everything else this file used to point at:

| For | See |
|---|---|
| The validation targets and what each one proves | [Testing XAIOS](https://github.com/Pummelchen/XAIOS/wiki/Testing-XAIOS) |
| Client interoperability, host forwarding and the framed-socket path | [Network and SSH status](./NETWORK-SSH-STATUS.md) |
| Key-only images and replacing the development password | [Network and SSH status](./NETWORK-SSH-STATUS.md) |
| VMware Fusion | [VMware Fusion](https://github.com/Pummelchen/XAIOS/wiki/VMware-Fusion) |
| The syscall and capability surface | [API](./API.md) |
| The architecture | [Architecture](https://github.com/Pummelchen/XAIOS/wiki/Architecture) |
| Contribution rules and where things live | [CONTRIBUTING.md](../CONTRIBUTING.md) |
