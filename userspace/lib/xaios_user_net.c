#include <xaios_user.h>

/* The network syscall wrappers: the local-address queries, the UDP/TCP
 * bring-up tests, the external-session bridge, the whole socket family and
 * the synchronous DNS resolver. These were the request-marshalling half of
 * xaios_user.c; they moved here unchanged so no source file passes the
 * repository's 500-line limit. Every symbol is declared in
 * <xaios_user.h> and still has the same name and signature. */

u32 xaios_net_local_ipv4(void) {
  return (u32)xaios_syscall3(XAIOS_SYSCALL_NET_LOCAL_IPV4, 0U, 0U, 0U);
}

int xaios_net_local_ipv6(u8 address[16]) {
  return (int)(s64)xaios_syscall3(XAIOS_SYSCALL_NET_LOCAL_IPV6,
                                  (u64)(void *)address, 16U, 0U);
}

int xaios_net_udp_echo(const void *payload, u64 payload_size,
                      u64 *echoed_bytes) {
  xaios_net_request_t request;
  request.payload = (u64)payload;
  request.payload_size = payload_size;
  request.out_value = (u64)echoed_bytes;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_UDP_ECHO, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_tcp_connect(u64 *round_trips) {
  xaios_net_request_t request;
  request.payload = 0;
  request.payload_size = 0;
  request.out_value = (u64)round_trips;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_TCP_CONNECT, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_external_session(u64 protocol, u64 port, const void *payload,
                              u64 payload_size, char *output,
                              u64 output_size, u64 *out_size) {
  xaios_net_external_session_request_t request;
  request.protocol = protocol;
  request.port = port;
  request.payload = (u64)payload;
  request.payload_size = payload_size;
  request.output = (u64)output;
  request.output_size = output_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_EXTERNAL_SESSION, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_listen(u64 port, u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.protocol = XAIOS_NET_PROTOCOL_TCP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_LISTEN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_connect(const xaios_ip_addr_user_t *remote_addr, u64 port,
                      u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.addr_ptr = (u64)remote_addr;
  request.protocol = XAIOS_NET_PROTOCOL_TCP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_CONNECT, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_listen_addr(u64 port, const xaios_ip_addr_user_t *bind_addr,
                          u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.addr_ptr = (u64)bind_addr;
  request.protocol = XAIOS_NET_PROTOCOL_TCP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_LISTEN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_bind_udp(u64 port, u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.protocol = XAIOS_NET_PROTOCOL_UDP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_LISTEN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_open_udp(u64 port, u64 *out_sockfd, u64 *out_port) {
  xaios_socket_request_t request;
  if (out_sockfd == 0) return -1;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  /* The port is an out-parameter of its own, written by the kernel through
     this pointer, and not a field of the request that comes back changed. The
     request is a description of what the caller wants, read once; a field
     carrying an answer as well would make a call that failed after allocating
     a descriptor indistinguishable from one that succeeded, since both would
     look the same on return. This is the same shape as `out_sockfd`, and the
     same shape `xaios_net_accept_addr` uses for its peer port. */
  u64 chosen = 0U;
  request.out_port = out_port != 0 ? (u64)&chosen : 0U;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_OPEN_UDP, (u64)&request,
                          sizeof(request), 0);
  if (rc == ~0ULL) return -1;
  if (out_port != 0) {
    *out_port = chosen;
  }
  return (int)rc;
}

int xaios_net_accept(u64 sockfd, u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.out_sockfd = (u64)out_sockfd;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_ACCEPT, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_accept_addr(u64 sockfd, u64 *out_sockfd,
                          xaios_ip_addr_user_t *peer_addr, u64 *peer_port) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.out_sockfd = (u64)out_sockfd;
  request.addr_out_ptr = (u64)peer_addr;
  /* peer_port is written to request.port by kernel if provided */
  request.port = (u64)peer_port;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_ACCEPT, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_recv(u64 sockfd, void *buffer, u64 buffer_size, u64 *out_bytes) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_RECV, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_recvfrom(u64 sockfd, void *buffer, u64 buffer_size,
                       u64 *out_bytes, xaios_ip_addr_user_t *src_addr) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  request.addr_out_ptr = (u64)src_addr;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_RECV, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_send(u64 sockfd, const void *buffer, u64 buffer_size,
                  u64 *out_bytes) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_SEND, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_sendto(u64 sockfd, const void *buffer, u64 buffer_size,
                     u64 *out_bytes, const xaios_ip_addr_user_t *dst_addr,
                     u64 dst_port) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  request.addr_ptr = (u64)dst_addr;
  /* The field the struct always had and nothing ever filled. The kernel reads
     it now; a zero here is refused rather than sent to port zero. */
  request.port = dst_port;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_SEND, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_close(u64 sockfd) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_CLOSE, sockfd, 0, 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_net_resolve_address(const char *hostname, u32 family,
                              xaios_ip_addr_user_t *out_address) {
  if (hostname == 0 || out_address == 0 || (family != 4U && family != 6U))
    return -1;
  xaios_net_resolve_request_t request;
  request.hostname = (u64)hostname;
  request.hostname_size = xaios_strlen(hostname);
  request.out_address = (u64)out_address;
  request.family = family;
  /* DNS resolution advances through the kernel packet poller. Keep the
   * userspace ABI synchronous by driving pending work to completion rather
   * than exposing a one-shot XAIOS_ERR_BUSY result to every caller. */
  u64 deadline = xaios_clock_nanos() + 16000000000ULL;
  for (;;) {
    u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_RESOLVE, (u64)&request,
                            sizeof(request), 0);
    s64 status = (s64)rc;
    if (status != -5) return (int)status;
    if (xaios_clock_nanos() >= deadline) return -5;
  }
}

int xaios_net_resolve(const char *hostname, u32 *out_ipv4) {
  if (out_ipv4 == 0) return -1;
  xaios_ip_addr_user_t address;
  int status = xaios_net_resolve_address(hostname, 4U, &address);
  if (status == 0) {
    *out_ipv4 = ((u32)address.addr[0] << 24U) |
                ((u32)address.addr[1] << 16U) |
                ((u32)address.addr[2] << 8U) | address.addr[3];
  }
  return status;
}
