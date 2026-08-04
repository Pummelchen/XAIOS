# XAIOS Network + SSH Production Hardening Plan

## Scope
Bring 4 subsystems from prototype to production-grade: IPv4, IPv6, TCP/UDP stack, SSH server (with multi-threading), and add a real DNS resolver. Estimated ~6,000-8,000 new lines across ~25 files.

---

## Phase A: TCP/UDP Stack Hardening (~2,500 lines)
**Target: production-grade TCP (RFC 793/1122/5681/7323) + RFC-compliant UDP**

### A1. TCP Checksum Validation
- Add TCP checksum verification to `parse_tcp()` and `parse_tcp_v6()`
- Drop packets with invalid checksums before any state mutation
- Files: `kernel/runtime/network_stack.c`

### A2. Full TCP State Machine
- Add `SYN_SENT` state (for future outbound connections)
- Add `FIN_WAIT_2` state transition
- Implement proper `TIME_WAIT` with 2MSL timer (60s)
- Add connection cleanup/reaping for `CLOSED` and `TIME_WAIT` states
- Files: `kernel/include/xaios/network_stack.h`, `kernel/runtime/network_stack.c`

### A3. TCP Data Retransmission
- Timer-based retransmission for data segments (not just SYN)
- Exponential backoff: 200ms → 400ms → 800ms → 1.6s → 3.2s (max 5 attempts)
- Files: `kernel/runtime/network_stack.c`

### A4. TCP MSS Option Negotiation
- Advertise MSS of 1460 in SYN segments
- Parse peer MSS from SYN-ACK, clamp segment size
- Files: `kernel/runtime/network_stack.c`

### A5. TCP Window Scaling
- Advertise window scale factor of 0 initially (socket buffer is small)
- Parse window scale option from peer SYN
- Files: `kernel/runtime/network_stack.c`

### A6. TCP Congestion Control (Basic)
- Slow start (cwnd = 1 → 2 → 4 ... until ssthresh)
- Congestion avoidance (additive increase after ssthresh)
- Fast retransmit on 3 duplicate ACKs
- Files: `kernel/runtime/network_stack.c`
- New struct fields: `cwnd`, `ssthresh`, `dup_ack_count`, `in_flight`

### A7. TCP Keepalive
- Send keepalive probes after configured idle period
- Default: 2h idle, 3 probes at 10s interval
- Files: `kernel/runtime/network_stack.c`

### A8. IPv6 UDP Checksum (RFC 2460 Mandatory)
- Compute and verify UDP checksum for IPv6 (always non-zero per RFC)
- Files: `kernel/runtime/network_stack.c`

### A9. Out-of-Order Data Buffering
- Buffer segments with seq > expected_seq up to window limit
- Deliver in-order once gap fills
- Files: `kernel/runtime/network_stack.c`

### A10. Connection Backlog Per Listener
- Per-listener accept backlog (default 16) instead of single global queue
- Files: `kernel/runtime/network_stack.c`

---

## Phase B: IPv4 Stack Production (~1,500 lines)

### B1. IP Fragmentation/Reassembly
- Fragment outgoing packets exceeding path MTU
- Reassemble incoming fragmented datagrams (60s timeout)
- Files: `kernel/net/ipv4.c`, `kernel/include/xaios/ipv4.h`

### B2. ICMP Error Generation
- Send ICMP Destination Unreachable (Port, Host, Network)
- Send ICMP Time Exceeded (TTL=0)
- ICMP rate limiting (RFC 1812: max 100 errors/second)
- Files: `kernel/net/icmp.c`, `kernel/include/xaios/icmp.h`

### B3. ARP Cache with Aging
- LRU eviction when cache full
- Timeout entries after 300s (RFC 1122)
- Gratuitous ARP on address assignment
- Files: `kernel/net/arp.c`, `kernel/include/xaios/arp.h`

### B4. ARP Cache Expansion
- Increase from 4 to 32 entries
- Files: `kernel/include/xaios/arp.h`

### B5. Route Deletion + Larger Table
- Add `routing_remove()`, `routing_clear()`
- Increase from 8 to 32 entries
- Files: `kernel/net/routing.c`, `kernel/include/xaios/routing.h`

---

## Phase C: IPv6 Stack Production (~1,800 lines)

### C1. IPv6 Extension Header Parsing
- Walk extension header chain (Hop-by-Hop, Routing, Fragment, AH, ESP, Destination)
- Skip unrecognized headers gracefully
- Files: `kernel/net/ipv6.c`, `kernel/include/xaios/ipv6.h`

### C2. IPv6 Fragmentation
- Fragment extension header (RFC 8200 Section 4.5)
- Reassembly with 60s timeout
- Files: `kernel/net/ipv6.c`

### C3. NDP Neighbor Unreachability Detection (NUD)
- Track reachability state per neighbor (RFC 4861 Section 7.3)
- STALE → DELAY → PROBE transitions
- Send unicast NS on probe
- Files: `kernel/net/ndp.c`, `kernel/include/xaios/ndp.h`

### C4. NDP Cache LRU + Aging
- Expand from 8 to 32 entries
- LRU eviction, timeout after 300s
- Files: `kernel/net/ndp.c`

### C5. NDP Hop-Limit Validation
- Verify Hop Limit == 255 on all ND messages (RFC 4861 Section 11)
- Files: `kernel/net/ndp.c`

### C6. Duplicate Address Detection (DAD)
- Send NS for tentative address before using it
- Wait 1s for NA; if received, address is duplicate
- Files: `kernel/net/ndp.c`

### C7. Router Discovery (RS/RA)
- Send Router Solicitation on interface up
- Process Router Advertisements for default gateway
- Files: `kernel/net/ndp.c`, `kernel/net/icmpv6.c`

### C8. ICMPv6 Error Generation
- Send ICMPv6 Destination Unreachable (Port)
- Rate limiting (same as IPv4)
- Files: `kernel/net/icmpv6.c`, `kernel/include/xaios/icmpv6.h`

---

## Phase D: SSH Server Production + Multi-Threading (~3,000 lines)

### D1. Per-Connection State (Remove Global Singletons)
- Create `ssh_connection_t` struct holding crypto state, packet buffers, seq numbers
- Allocate per-connection instead of using global `g_crypto`
- Files: `userspace/sshd/sshd.c`, `userspace/sshd/sshd.h`
- New file: `userspace/sshd/ssh_connection.h`

### D2. Multi-Threading Support
- Worker thread pool (up to `SSHD_MAX_WORKER_THREADS`)
- Thread-safe connection queue (already exists: `sshd_queue_t` with atomics)
- Each worker picks a connection, processes its message loop
- Thread-safe logging (mutex around log writes)
- Files: `userspace/sshd/sshd.c`, `userspace/sshd/sshd.h`

### D3. Persistent Host Key
- On first boot: generate Ed25519 key, save to `/etc/xaios_host_key`
- On subsequent boots: load from filesystem
- Files: `userspace/sshd/ssh_host_key.c`, `userspace/sshd/ssh_host_key.h`

### D4. Public Key Authentication
- Implement `ssh-ed25519` public key auth method (RFC 4252 Section 7)
- Load authorized_keys from `/etc/xaios_authorized_keys`
- Verify signature using `ed25519_verify()` (currently stub)
- Files: `userspace/sshd/sshd.c`, `userspace/sshd/ssh_crypto.c`

### D5. Ed25519 Signature Verification
- Implement Edwards point addition for verification
- Replace stub `return -1` with real verification
- Files: `userspace/sshd/ssh_crypto.c`

### D6. SSH Re-Keying
- After 1GB data or 1 hour: initiate key re-exchange (RFC 4253 Section 9)
- Files: `userspace/sshd/sshd.c`

### D7. SFTP Production File Handles
- Keep kernel fd open in handle struct
- Implement real seek via `xaios_fs_seek()` or discard emulation
- Track file offset persistently across read/write operations
- Files: `userspace/sshd/sftp_server.c`, `userspace/sshd/sftp_server.h`

### D8. SFTP Random Padding
- Use `crypto_random_bytes()` for SSH packet padding (RFC 4253 Section 6)
- Files: `userspace/sshd/ssh_protocol.c`

### D9. SFTP Minimum Padding Enforcement
- Reject packets with `padding_len < 4` (RFC 4253)
- Files: `userspace/sshd/ssh_protocol.c`

### D10. Channel Window Management
- Track peer window in channel struct
- Stop sending when peer window exhausted
- Files: `userspace/sshd/ssh_channel.c`, `userspace/sshd/ssh_channel.h`

### D11. Stderr Channel Support
- Send extended data (type 95) for stderr output
- Files: `userspace/sshd/ssh_channel.c`

---

## Phase E: DNS Resolver (~800 lines)

### E1. DNS Message Format
- Implement DNS header, question, and resource record encoding/decoding
- Support A (IPv4) and AAAA (IPv6) record types
- Files: `kernel/net/dns.c`, `kernel/include/xaios/dns.h`

### E2. UDP DNS Query
- Send DNS query to configured resolver (default: 8.8.8.8 port 53)
- Handle truncation (TC bit) for TCP fallback
- Parse response, extract IP addresses
- Cache results with TTL
- Files: `kernel/net/dns.c`

### E3. DNS Resolver Configuration
- Configurable DNS server via manifest
- Default: 8.8.8.8 / 8.8.4.4
- Files: `kernel/net/dns.c`

---

## Implementation Order & Dependencies

```
Phase A (TCP/UDP core) ──────────────────┐
                                          ├──→ Phase E (DNS needs working UDP)
Phase B (IPv4 hardening) ────────────────┤
                                          │
Phase C (IPv6 hardening) ────────────────┤
                                          │
Phase D (SSH hardening) ─────────────────┘  (independent of network stack)
```

Phase D is independent and can run in parallel with A/B/C. Phase E depends on A (working UDP stack).

**Recommended execution order:** A1→A2→A3→A4→A5→A6→A7→A8→A9→A10 → B1→B2→B3→B4→B5 → C1→C2→C3→C4→C5→C6→C7→C8 → D1→D2→D3→D4→D5→D6→D7→D8→D9→D10→D11 → E1→E2→E3

---

## Verification Gates

| Gate | What it tests | Command |
|------|--------------|---------|
| Compile check | All C files compile with -Wall -Wextra -Werror | `make compile-check` |
| TCP checksum | Malformed checksum packets are dropped | `make qemu-network-suite` |
| TCP retransmit | Lost SYN is retransmitted after timeout | `make qemu-fault-injection` |
| TCP state machine | Full flow: SYN→ESTABLISHED→FIN→TIME_WAIT→CLOSED | `make qemu-network-suite` |
| ICMP errors | Port unreachable sent for unlistened TCP SYN | `make qemu-network-suite` |
| IPv6 UDP checksum | IPv6 UDP packets with zero checksum rejected | `make qemu-cpu-ai-suite` |
| SSH multi-connection | Two simultaneous SSH clients | `make qemu-ssh-smoke` |
| SSH public key auth | Login via Ed25519 key (not password) | `make qemu-ssh-smoke` |
| SFTP large file | 100MB file read with correct offset | Manual test |
| DNS resolution | `dns_resolve("google.com")` returns IP | `make qemu-network-suite` |
| Full regression | No regressions in existing tests | `make qemu-regression-suite` |

---

## File Inventory

### New files to create (14):
- `kernel/include/xaios/tcp.h` — TCP constants and state helpers
- `kernel/include/xaios/icmp_errors.h` — ICMP error generation API
- `kernel/include/xaios/fragment.h` — IP fragmentation API
- `kernel/include/xaios/ndp_nud.h` — NUD state types
- `userspace/sshd/ssh_connection.h` — Per-connection state struct
- `userspace/sshd/ssh_connection.c` — Connection lifecycle management
- `kernel/net/dns_resolver.c` — DNS query/response logic
- Plus 7 internal headers

### Files to modify (18):
- `kernel/runtime/network_stack.c` (largest changes)
- `kernel/net/ipv4.c`, `kernel/net/icmp.c`, `kernel/net/arp.c`, `kernel/net/routing.c`
- `kernel/net/ipv6.c`, `kernel/net/icmpv6.c`, `kernel/net/ndp.c`
- `userspace/sshd/sshd.c`, `sshd.h`, `ssh_crypto.c`, `ssh_protocol.c`, `ssh_channel.c`, `ssh_channel.h`, `sftp_server.c`, `sftp_server.h`, `ssh_host_key.c`
- `kernel/net/dns.c`

---

## Ready to proceed?

Review and approve this plan. Once approved, I will implement in order:
**Phase A (TCP/UDP)** → **Phase E (DNS)** → **Phase B (IPv4)** → **Phase C (IPv6)** → **Phase D (SSH)**
