# The applications the kernel launches after userspace services are up. Plain
# freestanding C99 against the userspace library -- nothing in them was
# architecture-specific once the syscall stub and the entry stub knew about
# this one.
# The applications kmain launches, plus the ones sshd launches on demand --
# xtop is reached by typing its name at a login, not during boot, and a shell
# that offers a command whose binary is not in the image is worse than one
# that does not offer it.
# The same switch the kernel builder reads: 1 is the boot-test configuration
# the RISC-V gates run, 0 is the release configuration the other architectures
# ship as `make image`, where sshd dispatches on-demand applications such as
# xtop instead of the built-in test shell commands.
USER_APPS="xaios-shell xaiosctl nano pong hello spin sysinfo systest smptest joinnest smpstress perfbench nettest netmqtest netsocktest lstm-xor sshtest mltest posix-shell agenttest xaios-setup xtop clustertest"

# Which end of a cluster this image is, and where its peer is.
#
# The same two switches build-image.sh takes, because the two ends of a
# cluster are mirror images built from one source -- one listens, the other
# dials -- and an architecture that can only be built as a client can only
# ever be the junior half of a pair. This image carried no clustertest at
# all, so the two-node gate had nothing on RISC-V to run.
CLUSTER_ROLE_SERVER="${XAIOS_CLUSTER_ROLE_SERVER:-0}"
case "$CLUSTER_ROLE_SERVER" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_CLUSTER_ROLE_SERVER must be 0 or 1" >&2
    exit 1 ;;
esac
CLUSTER_APP_CFLAGS="-DXAIOS_CLUSTER_ROLE_SERVER=$CLUSTER_ROLE_SERVER"
if [ -n "${XAIOS_CLUSTER_PEER_IPV4:-}" ]; then
  cluster_peer_ok=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | awk -F. '
    NF == 4 {
      for (i = 1; i <= 4; ++i) {
        if ($i !~ /^[0-9]+$/ || $i + 0 > 255) { print "no"; exit }
      }
      print "yes"; exit
    }
    { print "no" }')
  if [ "$cluster_peer_ok" != yes ]; then
    printf '%s\n' \
      "error: XAIOS_CLUSTER_PEER_IPV4 must be a dotted IPv4 address" >&2
    exit 1
  fi
  cluster_a=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f1)
  cluster_b=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f2)
  cluster_c=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f3)
  cluster_d=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f4)
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_A=${cluster_a}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_B=${cluster_b}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_C=${cluster_c}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_D=${cluster_d}U"
fi
if [ -n "${XAIOS_CLUSTER_PEER_PORT:-}" ]; then
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DCLUSTER_PEER_PORT=${XAIOS_CLUSTER_PEER_PORT}U"
fi
# The three-node mesh, which is a different program in the same file.
#
# Node id and the three ports are compile-time because the app has no
# discovery and inventing one here would test the invention. They are checked
# here rather than left to the compiler: a node id of zero produces a peer
# table xaios_cluster_init rejects at run time, on a machine whose console
# nobody is reading yet, and a port that is not a number becomes a macro that
# fails to expand into something a person can recognise.
if [ -n "${XAIOS_CLUSTER_MESH_NODES:-}" ]; then
  case "$XAIOS_CLUSTER_MESH_NODES" in
    0|3) ;;
    *)
      printf '%s\n' "error: XAIOS_CLUSTER_MESH_NODES must be 0 or 3" >&2
      exit 1
      ;;
  esac
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_MESH_NODES=${XAIOS_CLUSTER_MESH_NODES}"
  if [ "$XAIOS_CLUSTER_MESH_NODES" = 3 ]; then
    case "${XAIOS_CLUSTER_NODE_ID:-}" in
      1|2|3) ;;
      *)
        printf '%s\n' \
          "error: XAIOS_CLUSTER_NODE_ID must be 1, 2 or 3 for a three-node mesh" >&2
        exit 1
        ;;
    esac
    CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_NODE_ID=${XAIOS_CLUSTER_NODE_ID}U"
    for mesh_index in 1 2 3; do
      eval "mesh_port=\${XAIOS_CLUSTER_MESH_PORT_${mesh_index}:-}"
      case "$mesh_port" in
        ''|*[!0-9]*)
          printf '%s\n' \
            "error: XAIOS_CLUSTER_MESH_PORT_${mesh_index} must be a port number" >&2
          exit 1
          ;;
      esac
      if [ "$mesh_port" -lt 1 ] || [ "$mesh_port" -gt 65535 ]; then
        printf '%s\n' \
          "error: XAIOS_CLUSTER_MESH_PORT_${mesh_index} is not a port" >&2
        exit 1
      fi
      CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_MESH_PORT_${mesh_index}=${mesh_port}U"
    done
    # Whether a node that loses quorum stops or keeps running. The kill gate
    # wants it to stop: its peers were SIGKILLed and are not coming back. The
    # partition gate wants it to keep running, because its peers are alive on
    # the far side of a cut link and the repair is the half of that test which
    # has not happened yet. Default zero, so the existing gate is unchanged by
    # this knob existing.
    MESH_HOLD="${XAIOS_CLUSTER_MESH_HOLD:-0}"
    case "$MESH_HOLD" in
      0|1) ;;
      *)
        printf '%s\n' "error: XAIOS_CLUSTER_MESH_HOLD must be 0 or 1" >&2
        exit 1
        ;;
    esac
    CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_MESH_HOLD=${MESH_HOLD}"
  fi
fi
# The two applications that fail on purpose, when a gate asks for them. The
# kernel builder already took XAIOS_FAILURE_TEST_APP; the image did not carry
# what that switch expects to launch, so a client asking the guest to run a
# failing application was told the executable was unavailable -- which is a
# true statement and not the failure the gate was testing for.
case "${XAIOS_FAILURE_TEST_APP:-0}" in
  0) ;;
  1) USER_APPS="$USER_APPS app-fail app-crash" ;;
  *)
    printf '%s\n' "error: XAIOS_FAILURE_TEST_APP must be 0 or 1" >&2
    exit 2 ;;
esac
