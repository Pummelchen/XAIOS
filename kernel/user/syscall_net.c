/*
 * The net syscall family. See syscall_family.h.
 *
 * Lifted out of syscall_dispatch in syscall.c, whose blocks for these
 * numbers are reproduced here verbatim: same guards, same order, same
 * error reasons.
 */

#include <xaios/agent_protocol.h>
#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/boot_ui.h>
#include <xaios/child_channel.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/control_protocol.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/initramfs.h>
#include <xaios/ipv4.h>
#include <xaios/network_config.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/local_ports.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/net_device.h>
#include <xaios/network_stack.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/socket_buffer.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>

#include "syscall_internal.h"
#include "syscall_table.h"
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/user.h>
#include <xaios/vfs.h>
#include <xaios/vmm.h>
#include "syscall_family.h"

uint64_t syscall_net(uint64_t syscall, uint64_t arg0,
                                                     uint64_t arg1, uint64_t arg2) {
  (void)arg2;

  if (syscall == XAIOS_SYSCALL_NET_CONNECT) {
    xaios_syscall_socket_request_t request;
    xaios_ip_addr_t remote_addr;
    uint64_t out_sockfd = 0U;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "bad-net-connect-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.protocol != XAIOS_NETWORK_PROTOCOL_TCP || request.port == 0U ||
        request.port > UINT16_MAX || request.addr_ptr == 0U ||
        vmm_validate_user_buffer(request.addr_ptr, sizeof(remote_addr), 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-connect-denied");
    }
    syscall_dispatch_bytes_copy(&remote_addr, (const void *)(uintptr_t)request.addr_ptr,
               sizeof(remote_addr));
    if (remote_addr.family != XAIOS_IP_FAMILY_V4 &&
        remote_addr.family != XAIOS_IP_FAMILY_V6) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "net-connect-family-unsupported");
    }
    uint32_t flow_id = 0U;
    xaios_status_t open_status = XAIOS_ERR_BUSY;
    for (uint32_t attempt = 0U; attempt < 16U; ++attempt) {
      /* Drawn atomically, for the same reason the datagram path is: two CPUs
         that lose an update to this counter draw the same local port. */
      uint16_t local_port = kernel_ephemeral_reserve();
      open_status = network_stack_tcp_open(
          &remote_addr, (uint16_t)request.port, local_port, &flow_id);
      if (open_status == XAIOS_OK) break;
      if (open_status != XAIOS_ERR_BUSY) break;
    }
    if (open_status != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-connect-open-failed");
    }
    uint64_t start = timer_now_ns();
    uint64_t deadline = start + UINT64_C(10000000000);
    do {
      network_poll_tick();
      open_status = network_stack_tcp_open_status(flow_id);
      if (open_status != XAIOS_ERR_BUSY) break;
    } while (timer_now_ns() < deadline);
    if (open_status != XAIOS_OK) {
      (void)network_stack_tcp_abort_flow(flow_id);
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "net-connect-handshake-failed");
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    uint64_t sockfd = kernel_socket_alloc(KERNEL_SOCK_CONNECTED,
                                          (uint16_t)request.port, owner_token);
    if (sockfd == 0U) {
      (void)network_stack_tcp_abort_flow(flow_id);
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "net-connect-socket-failed");
    }
    syscall_socket_lock();
    kernel_socket_t *socket =
        kernel_socket_find_owned_locked(sockfd, owner_token);
    kassert(socket != 0);
    socket->protocol = XAIOS_NETWORK_PROTOCOL_TCP;
    socket->family = remote_addr.family;
    socket->peer_port = (uint16_t)request.port;
    for (uint32_t i = 0U; i < 16U; ++i)
      socket->peer_addr[i] = remote_addr.addr[i];
    syscall_socket_unlock();
    if (network_stack_map_socket(sockfd, flow_id,
                                 XAIOS_NETWORK_PROTOCOL_TCP) != XAIOS_OK) {
      /* Same refusal as accept, for the same reason (B-47): a connected
         descriptor with no mapping can neither send nor receive, and would
         look to the caller like a peer that went quiet. */
      (void)kernel_socket_free(sockfd, owner_token);
      (void)network_stack_tcp_abort_flow(flow_id);
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-connect-no-flow-slot");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_sockfd, &sockfd, sizeof(sockfd));
    klog("syscall: net_connect port=%lu sockfd=%lu flow=%u\n", request.port,
         sockfd, flow_id);
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_NET_LISTEN) {
    xaios_syscall_socket_request_t request;
    uint64_t out_sockfd = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-listen-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        request.port == 0 || request.port > 65535U) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-listen-denied");
    }
    uint64_t protocol = request.protocol == 0 ? XAIOS_NETWORK_PROTOCOL_TCP
                                              : request.protocol;
    if (protocol != XAIOS_NETWORK_PROTOCOL_TCP &&
        protocol != XAIOS_NETWORK_PROTOCOL_UDP) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-listen-protocol");
    }
    uint8_t addr_buf[17];
    if (request.addr_ptr != 0U) {
      if (vmm_validate_user_buffer(request.addr_ptr, sizeof(addr_buf), 0) !=
          XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-listen-address");
      }
      syscall_dispatch_bytes_copy(addr_buf, (const void *)(uintptr_t)request.addr_ptr,
                 sizeof(addr_buf));
      if (addr_buf[0] != 0U && addr_buf[0] != 4U && addr_buf[0] != 6U) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-listen-family");
      }
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    uint32_t socket_type = protocol == XAIOS_NETWORK_PROTOCOL_UDP
                               ? KERNEL_SOCK_DATAGRAM
                               : KERNEL_SOCK_LISTEN;
    uint64_t sockfd = kernel_socket_alloc(socket_type, (uint16_t)request.port,
                                          owner_token);
    if (sockfd == 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-listen-no-memory");
    }
    syscall_socket_lock();
    kernel_socket_t *socket =
        kernel_socket_find_owned_locked(sockfd, owner_token);
    kassert(socket != 0);
    socket->protocol = (uint8_t)protocol;
    if (request.addr_ptr != 0U) {
      socket->family = addr_buf[0];
      for (uint32_t j = 0; j < 16; ++j) {
        socket->bind_addr[j] = addr_buf[1U + j];
      }
    }
    syscall_socket_unlock();
    /* The registry row is the listener. A socket that could not be given one
       is a socket nothing will ever answer on, so the listen is refused here
       rather than reported as listening: what the caller would otherwise be
       handed is a descriptor whose port can never receive, and `docs/API.md`
       states that guarantee without qualification (B-78). */
    xaios_status_t registered =
        protocol == XAIOS_NETWORK_PROTOCOL_UDP
            ? network_stack_register_udp_listener((uint16_t)request.port, sockfd)
            : network_stack_register_listener((uint16_t)request.port, sockfd);
    if (registered != XAIOS_OK) {
      (void)kernel_socket_free(sockfd, owner_token);
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-listen-registry-full");
    }
    *(uint64_t *)(uintptr_t)request.out_sockfd = sockfd;
    klog("syscall: net_listen protocol=%lu port=%lu sockfd=%lu\n", protocol,
         request.port, sockfd);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_OPEN_UDP) {
    xaios_syscall_socket_request_t request;
    uint64_t out_sockfd = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-open-udp-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    /* The caller supplies the port; port 0 asks the kernel to choose one. An
       explicit port is allowed because a program that wants a known one --
       a test, or a peer that must be told where to reply -- should not have to
       bind a listener first to get it. */
    if (request.port > 65535U ||
        vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        (request.out_port != 0U &&
         vmm_validate_user_buffer(request.out_port, sizeof(uint64_t),
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK) ||
        (request.addr_ptr != 0U &&
         vmm_validate_user_buffer(request.addr_ptr, 17U, 0) != XAIOS_OK)) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-open-udp-denied");
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    uint16_t port = (uint16_t)request.port;
    uint64_t sockfd = 0;
    if (port != 0U) {
      sockfd = kernel_socket_alloc(KERNEL_SOCK_DATAGRAM, port, owner_token);
      if (sockfd == 0U) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-open-udp-no-memory");
      }
    } else {
      /* The range, the wrap, the search for a port nobody holds and the
         allocation of the descriptor for it all happen inside one critical
         section: see `kernel_socket_alloc_ephemeral_datagram` for why doing
         them in two lets two CPUs end up holding one port. */
      sockfd = kernel_socket_alloc_ephemeral_datagram(owner_token, &port);
      if (sockfd == 0U) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-open-udp-no-port");
      }
    }
    uint8_t addr_buf[17];
    if (request.addr_ptr != 0U) {
      syscall_dispatch_bytes_copy(addr_buf, (const void *)(uintptr_t)request.addr_ptr,
                 sizeof(addr_buf));
      if (addr_buf[0] != 0U && addr_buf[0] != 4U && addr_buf[0] != 6U) {
        /* Frees the socket it just allocated. `kernel_socket_free` takes the
           socket lock itself, so it is called before that lock is taken and
           with nothing held. */
        (void)kernel_socket_free(sockfd, owner_token);
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-open-udp-family");
      }
    }
    syscall_socket_lock();
    kernel_socket_t *socket = kernel_socket_find_owned_locked(sockfd, owner_token);
    kassert(socket != 0);
    socket->protocol = XAIOS_NETWORK_PROTOCOL_UDP;
    if (request.addr_ptr != 0U) {
      socket->family = addr_buf[0];
      for (uint32_t j = 0; j < 16; ++j) {
        socket->bind_addr[j] = addr_buf[1U + j];
      }
    }
    syscall_socket_unlock();
    /* Registered before anything is reported, because the registration is what
       makes the port answer: process_udp_frame looks the listener up by port
       and drops the frame when it finds none, so a socket refused a row can
       never receive. Reporting the descriptor and the port first would tell
       the caller it owns an address that is already dead, which is the whole
       of B-78. Net close unregisters it, so an ephemeral socket frees its port
       like any other. */
    if (network_stack_register_udp_listener(port, sockfd) != XAIOS_OK) {
      (void)kernel_socket_free(sockfd, owner_token);
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-open-udp-registry-full");
    }
    /* The port the kernel chose goes to the caller's own out-pointer, beside
       the descriptor rather than inside the request. A caller that asked for
       an ephemeral port has no other way to learn its own address, and a peer
       told to reply needs the truth, so this is not optional for port zero --
       but it is written through a distinct pointer, so the request itself
       stays exactly as the caller wrote it. */
    *(uint64_t *)(uintptr_t)request.out_sockfd = sockfd;
    if (request.out_port != 0U) {
      *(volatile uint64_t *)(uintptr_t)request.out_port = (uint64_t)port;
    }
    klog("syscall: net_open_udp port=%lu sockfd=%lu\n", (uint64_t)port, sockfd);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_ACCEPT) {
    xaios_syscall_socket_request_t request;
    uint64_t out_sockfd = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-accept-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        (request.addr_out_ptr != 0U &&
         vmm_validate_user_buffer(request.addr_out_ptr, 17U,
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK) ||
        (request.port != 0U &&
         vmm_validate_user_buffer(request.port, sizeof(uint64_t),
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK)) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-accept-denied");
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    kernel_socket_t listener;
    if (kernel_socket_snapshot_owned(request.sockfd, owner_token, &listener) !=
            XAIOS_OK ||
        listener.state != KERNEL_SOCK_LISTEN ||
        listener.protocol != XAIOS_NETWORK_PROTOCOL_TCP) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-accept-bad-listen");
    }
    uint16_t listen_port = listener.port;
    /* Dequeue from accept queue */
    uint32_t flow_id = 0;
    uint32_t peer_ip = 0;
    uint16_t peer_port = 0;
    xaios_ip_addr_t peer_addr;
    xaios_ip_addr_zero(&peer_addr);
    network_poll_tick();
    if (network_stack_accept_connection(listen_port, &flow_id, &peer_ip,
                                          &peer_port, &peer_addr) != XAIOS_OK) {
      return UINT64_MAX;
    }
    /* Allocate connected socket */
    uint64_t connfd =
        kernel_socket_alloc(KERNEL_SOCK_CONNECTED, listen_port, owner_token);
    if (connfd == 0) {
      network_stack_tcp_close_flow(flow_id);
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-accept-no-memory");
    }
    /* Store peer info on the socket */
    syscall_socket_lock();
    kernel_socket_t *socket =
        kernel_socket_find_owned_locked(connfd, owner_token);
    kassert(socket != 0);
    socket->peer_port = peer_port;
    socket->family = peer_addr.family;
    for (uint32_t j = 0; j < 16; ++j) {
      socket->peer_addr[j] = peer_addr.addr[j];
    }
    syscall_socket_unlock();
    /* Map socket to flow. B-47: this used to be a void call, and a full map
       was a silent no-op -- the accept still succeeded, still logged, and
       handed back a descriptor with no flow behind it, which is precisely a
       connection that is accepted and then never progresses. Refuse instead:
       give the descriptor back, close the flow so the peer is told, and name
       the reason. */
    if (network_stack_map_socket(connfd, flow_id, 6) != XAIOS_OK) { /* TCP */
      (void)kernel_socket_free(connfd, owner_token);
      network_stack_tcp_close_flow(flow_id);
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-accept-no-flow-slot");
    }
    /* Write peer address to addr_out_ptr if requested */
    if (request.addr_out_ptr != 0) {
      uint8_t addr_buf[17];
      for (uint32_t j = 0; j < 17; ++j) addr_buf[j] = 0;
      addr_buf[0] = peer_addr.family;
      for (uint32_t j = 0; j < 16; ++j) {
        addr_buf[1U + j] = peer_addr.addr[j];
      }
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.addr_out_ptr, addr_buf, 17);
    }
    if (request.port != 0) {
      *(uint64_t *)(uintptr_t)request.port = peer_port;
    }
    *(uint64_t *)(uintptr_t)request.out_sockfd = connfd;
    klog("syscall: net_accept listenfd=%lu connfd=%lu flow=%u\n",
         request.sockfd, connfd, flow_id);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_CLOSE) {
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    kernel_socket_t socket_snapshot;
    if (kernel_socket_snapshot_owned(arg0, owner_token, &socket_snapshot) !=
        XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-close-no-socket");
    }
    /* Clean up flow mapping if this is a connected socket */
    socket_flow_mapping_t close_mapping_copy;
    socket_flow_mapping_t *close_mapping =
        network_stack_get_socket_mapping(arg0, &close_mapping_copy)
            ? &close_mapping_copy
            : 0;
    if (close_mapping != 0) {
      if (close_mapping->protocol == 6) {
        network_stack_tcp_close_flow(close_mapping->flow_id);
      }
      network_stack_unmap_socket(arg0);
    }
    if (socket_snapshot.state == KERNEL_SOCK_LISTEN) {
      network_stack_unregister_listener(socket_snapshot.port);
    } else if (socket_snapshot.state == KERNEL_SOCK_DATAGRAM) {
      network_stack_unregister_udp_listener(socket_snapshot.port);
    }
    /* The ownership check above and this free take the socket lock separately,
       so a sibling thread closing the same descriptor can land between them.
       Both callers pass the check, one frees it, and the other used to find
       nothing and halt the kernel on the assertion that stood here -- a panic
       any two threads could cause with a descriptor of their own. Losing that
       race is not an error worth a machine: the socket is closed, which is
       what this caller asked for, and the rejection path already used above
       for a descriptor that is not there says so. */
    if (kernel_socket_free(arg0, owner_token) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-close-raced");
    }
    klog("syscall: net_close sockfd=%lu\n", arg0);
    return XAIOS_OK;
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
