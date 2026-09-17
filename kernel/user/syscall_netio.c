/*
 * The netio syscall family. See syscall_family.h.
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

uint64_t syscall_netio(uint64_t syscall, uint64_t arg0,
                                                       uint64_t arg1, uint64_t arg2) {
  (void)arg2;

  if (syscall == XAIOS_SYSCALL_NET_LOCAL_IPV6) {
    xaios_ip_addr_t address;
    if (arg1 != 16U ||
        vmm_validate_user_buffer(arg0, 16U, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-ipv6-buffer");
    }
    /* Report the address this host sends IPv6 from, which on a network whose
       router advertises a unique-local prefix is that address rather than a
       globally routable one. Reporting only global addresses left userspace
       believing the machine had no IPv6 at all. */
    if (network_stack_local_ipv6(&address) != XAIOS_OK) {
      user_process_note_syscall(0);
      return 0U;
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)arg0, address.addr, 16U);
    user_process_note_syscall(0);
    return 1U;
  }

  if (syscall == XAIOS_SYSCALL_NET_LOCAL_IPV4) {
    user_process_note_syscall(0);
    return network_config_local_ipv4();
  }

  if (syscall == XAIOS_SYSCALL_NET_UDP_ECHO) {
    xaios_syscall_net_request_t request;
    uint8_t payload[64];
    uint64_t echoed = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-udp-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.payload_size == 0 || request.payload_size > sizeof(payload) ||
        vmm_validate_user_buffer(request.payload, request.payload_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_value, sizeof(echoed),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-udp-denied");
    }
    syscall_dispatch_bytes_copy(payload, (const void *)(uintptr_t)request.payload,
               request.payload_size);
    if (network_stack_app_udp_echo(payload, request.payload_size, &echoed) !=
        XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-udp-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_value, &echoed, sizeof(echoed));
    return syscall_dispatch_complete(echoed);
  }

  if (syscall == XAIOS_SYSCALL_NET_TCP_CONNECT) {
    xaios_syscall_net_request_t request;
    uint64_t round_trips = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-tcp-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_value, sizeof(round_trips),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-tcp-denied");
    }
    if (network_stack_app_tcp_connect(&round_trips) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-tcp-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_value, &round_trips,
               sizeof(round_trips));
    return syscall_dispatch_complete(round_trips);
  }

  if (syscall == XAIOS_SYSCALL_NET_EXTERNAL_SESSION) {
    xaios_syscall_net_external_session_request_t request;
    uint8_t payload[64];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-external-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.payload_size == 0 || request.payload_size > sizeof(payload) ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.payload, request.payload_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-external-denied");
    }
    syscall_dispatch_bytes_copy(payload, (const void *)(uintptr_t)request.payload,
               request.payload_size);
    if (network_stack_external_session(
            request.protocol, request.port, payload, request.payload_size,
            (char *)(uintptr_t)request.output, request.output_size,
            &out_size) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-external-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return syscall_dispatch_complete(out_size);
  }

  if (syscall == XAIOS_SYSCALL_NET_RECV) {
    xaios_syscall_socket_request_t request;
    uint64_t out_bytes = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-recv-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.buffer_size == 0 ||
        request.buffer_size > XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_bytes, sizeof(out_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        (request.addr_out_ptr != 0U &&
         vmm_validate_user_buffer(request.addr_out_ptr,
                                  sizeof(xaios_ip_addr_t),
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK)) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-recv-denied");
    }
    network_poll_tick();
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    kernel_socket_t socket_snapshot;
    if (kernel_socket_snapshot_owned(request.sockfd, owner_token,
                                     &socket_snapshot) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-recv-no-socket");
    }
    if (socket_snapshot.state == KERNEL_SOCK_DATAGRAM) {
      xaios_ip_addr_t source_addr;
      uint16_t source_port = 0;
      uint32_t flow_id = 0;
      xaios_ip_addr_zero(&source_addr);
      uint32_t bytes_read = network_stack_udp_recv(
          request.sockfd, (uint8_t *)(uintptr_t)request.buffer,
          (uint32_t)request.buffer_size, &source_addr, &source_port, &flow_id);
      if (request.addr_out_ptr != 0) {
        syscall_dispatch_bytes_copy((void *)(uintptr_t)request.addr_out_ptr, &source_addr,
                   sizeof(source_addr));
      }
      *(uint64_t *)(uintptr_t)request.out_bytes = bytes_read;
      (void)source_port;
      (void)flow_id;
      return XAIOS_OK;
    }
    if (socket_snapshot.state != KERNEL_SOCK_CONNECTED) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-recv-not-connected");
    }
    /* Look up a connected TCP socket. */
    socket_flow_mapping_t mapping_storage;
    socket_flow_mapping_t *mapping =
        network_stack_get_socket_mapping(request.sockfd, &mapping_storage)
            ? &mapping_storage
            : 0;
    if (mapping == 0) {
      *(uint64_t *)(uintptr_t)request.out_bytes = 0;
      return XAIOS_OK;
    }
    /* Find the flow and read from its rx_buf */
    uint32_t bytes_read = 0;
    if (mapping->protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
      bytes_read = network_stack_tcp_recv(mapping->flow_id,
          (uint8_t *)(uintptr_t)request.buffer,
          (uint32_t)request.buffer_size);
      if (bytes_read == 0 &&
          network_stack_tcp_peer_closed(mapping->flow_id) != 0) {
        *(uint64_t *)(uintptr_t)request.out_bytes = 0;
        return UINT64_MAX;
      }
    }
    *(uint64_t *)(uintptr_t)request.out_bytes = bytes_read;
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_SEND) {
    xaios_syscall_socket_request_t request;
    uint64_t out_bytes = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-send-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.buffer_size == 0 ||
        request.buffer_size > XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_bytes, sizeof(out_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-send-denied");
    }
    network_poll_tick();
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    kernel_socket_t socket_snapshot;
    if (kernel_socket_snapshot_owned(request.sockfd, owner_token,
                                     &socket_snapshot) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-send-no-socket");
    }
    /* sendto: a datagram addressed here in the call rather than by an earlier
       exchange. This is B-29, and it is the whole defect.

       The path below this requires a socket-to-flow mapping, and for a UDP
       socket the only thing that ever created one was network_stack_udp_recv,
       which maps the socket to the flow a datagram arrived on. So a socket
       that had bound a port and never received anything -- which is every
       sender -- reached "net-send-bad-state" on its first send and on all of
       them. The address the caller passed was not merely unused: it was never
       read. request.port was not read either, which is why the userspace
       wrapper had nothing to put in it and why the field sat empty in a
       struct that has carried it all along. Nothing noticed because every
       other userspace UDP caller went through xaios_net_udp_echo or
       xaios_net_external_session, and both of those hand a frame to
       network_stack_process_udp_frame -- the receive path -- so they neither
       need a flow nor reach the device.

       Kept ahead of the mapping lookup rather than folded into it, because a
       sendto that names a peer must go to that peer even when the socket has
       an older mapping pointing somewhere else. The mapping is then updated,
       so a plain net_send after a sendto continues to the same peer.

       The retry loop is not politeness about a slow link. The first datagram
       to an unseen peer finds no ARP entry, so the stack sends a request and
       returns BUSY with nothing transmitted; without a bounded poll-and-retry
       the first send to every destination would fail and the caller would
       have no way to tell that from a real refusal. */
    if (socket_snapshot.state == KERNEL_SOCK_DATAGRAM &&
        request.addr_ptr != 0U) {
      xaios_ip_addr_t destination;
      if (request.port == 0U || request.port > UINT16_MAX ||
          vmm_validate_user_buffer(request.addr_ptr, sizeof(destination), 0) !=
              XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-sendto-denied");
      }
      syscall_dispatch_bytes_copy(&destination, (const void *)(uintptr_t)request.addr_ptr,
                 sizeof(destination));
      if (destination.family != XAIOS_IP_FAMILY_V4) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-sendto-family");
      }
      uint8_t *datagram = (uint8_t *)kheap_alloc(request.buffer_size, 16U);
      if (datagram == 0) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "net-sendto-no-memory");
      }
      syscall_dispatch_bytes_copy(datagram, (const void *)(uintptr_t)request.buffer,
                 request.buffer_size);
      uint32_t datagram_bytes = 0U;
      uint32_t datagram_flow = 0U;
      xaios_status_t sendto_status = XAIOS_ERR_BUSY;
      uint64_t sendto_deadline = timer_now_ns() + UINT64_C(2000000000);
      for (;;) {
        sendto_status = network_stack_udp_sendto(
            socket_snapshot.port, &destination, (uint16_t)request.port,
            datagram, (uint32_t)request.buffer_size, &datagram_bytes,
            &datagram_flow);
        if (sendto_status != XAIOS_ERR_BUSY) break;
        if (timer_now_ns() >= sendto_deadline) break;
        network_poll_tick();
      }
      kheap_free(datagram);
      if (sendto_status != XAIOS_OK) {
        /* Two reasons rather than one, because they are two different
           machines: BUSY means the destination's link-layer address never
           arrived, which is a network fact, and anything else is the stack
           refusing the datagram. A single reason would have made the ARP case
           look like a bug in this code. */
        return syscall_dispatch_reject(syscall, arg0, arg1,
                              sendto_status == XAIOS_ERR_BUSY
                                  ? "net-sendto-unresolved"
                                  : "net-sendto-failed");
      }
      /* The datagram is already on the wire, so there is nothing left to
         refuse; an exhausted map costs this socket its reply path and the
         stack logs the exhaustion (B-47). */
      (void)network_stack_map_socket(request.sockfd, datagram_flow,
                                     XAIOS_NETWORK_PROTOCOL_UDP);
      *(uint64_t *)(uintptr_t)request.out_bytes = datagram_bytes;
      return XAIOS_OK;
    }
    socket_flow_mapping_t snd_mapping_storage;
    socket_flow_mapping_t *snd_mapping =
        network_stack_get_socket_mapping(request.sockfd, &snd_mapping_storage)
            ? &snd_mapping_storage
            : 0;
    if (snd_mapping == 0 ||
        !((socket_snapshot.state == KERNEL_SOCK_CONNECTED &&
           snd_mapping->protocol == XAIOS_NETWORK_PROTOCOL_TCP) ||
          (socket_snapshot.state == KERNEL_SOCK_DATAGRAM &&
           snd_mapping->protocol == XAIOS_NETWORK_PROTOCOL_UDP))) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-send-bad-state");
    }
    uint8_t *send_snapshot =
        (uint8_t *)kheap_alloc(request.buffer_size, 16U);
    if (send_snapshot == 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-send-no-memory");
    }
    syscall_dispatch_bytes_copy(send_snapshot, (const void *)(uintptr_t)request.buffer,
               request.buffer_size);
    uint32_t bytes_written = 0;
    xaios_status_t snd_st = XAIOS_ERR_INVALID;
    if (snd_mapping->protocol == 6) {
      snd_st = network_stack_tcp_send(snd_mapping->flow_id,
          send_snapshot, (uint32_t)request.buffer_size, &bytes_written);
    } else if (snd_mapping->protocol == 17) {
      snd_st = network_stack_udp_send(snd_mapping->flow_id,
          send_snapshot, (uint32_t)request.buffer_size, &bytes_written);
    }
    kheap_free(send_snapshot);
    if (snd_st != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-send-failed");
    }
    *(uint64_t *)(uintptr_t)request.out_bytes = bytes_written;
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_RESOLVE) {
    xaios_syscall_net_resolve_request_t request;
    char hostname[64];
    xaios_ip_addr_t address;
    xaios_ip_addr_zero(&address);
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-net-resolve-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (syscall_table_copy_user_string(request.hostname, request.hostname_size, hostname,
                         sizeof(hostname)) != XAIOS_OK ||
        (request.family != XAIOS_IP_FAMILY_V4 &&
         request.family != XAIOS_IP_FAMILY_V6) ||
        vmm_validate_user_buffer(request.out_address, sizeof(address),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "net-resolve-denied");
    }
    for (uint64_t i = 0U; i < request.hostname_size; ++i) {
      if (hostname[i] == '\0') {
        return syscall_dispatch_reject(syscall, arg0, arg1,
                              "net-resolve-embedded-nul");
      }
    }
    network_poll_tick();
    xaios_status_t status = dns_resolve_address(
        hostname, (uint8_t)request.family, &address);
    if (status == XAIOS_OK) {
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_address, &address,
                 sizeof(address));
    } else if (status != XAIOS_ERR_BUSY) {
      klog("dns: resolve syscall failed host=%s status=%d\n", hostname,
           (int)status);
    }
    user_process_note_syscall(0);
    return (uint64_t)(int64_t)status;
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
