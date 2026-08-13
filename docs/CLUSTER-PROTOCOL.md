# Cluster control and deterministic placement

The portable inference engine owns cluster membership and expert placement;
the kernel owns authenticated transport endpoints, queues, memory ownership and
resource admission. No database participates in a per-token route.

`engine/include/xaios_engine/cluster.h` defines the current hosted-reference
control protocol. Its fixed little-endian envelope carries sender, receiver,
epoch, monotonic nonce, opcode and a bounded payload. Every peer direction has
a distinct 256-bit key and every frame has HMAC-SHA256 authentication. Receivers
validate identity, epoch, exact length and tag before advancing the replay
window or membership state.

Expert identities are `(model_uuid, layer_id, expert_id, layout_id)`.
Deterministic rendezvous scoring selects an online owner, route output is sorted
by owner then expert, and reductions are ordered by node then expert. Simulated
node failure removes the owner from subsequent choices without changing the
identity function.

`tests/model_v2/test_cluster.c` proves three-node mutual authentication,
tamper and replay rejection, deterministic placement, failure-aware rerouting
and stable floating-point reduction. This is portable hosted groundwork only.
D-06 and D-07 remain open until independent XAIOS QEMU guests exchange these
frames over a capability-gated asynchronous transport and pass join, partition,
recovery, ownership-version and end-to-end execution tests.
