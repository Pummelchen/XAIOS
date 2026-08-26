/*
 * Privileged vmnet relay for the Virtualization.framework harness.
 *
 * Apple's NAT attachment carries guest-initiated traffic only: the Mac cannot
 * reach a guest behind it, so a listening sshd is unreachable. A bridged
 * attachment would expose the guest but needs an entitlement Apple issues only
 * with a provisioning profile.
 *
 * vmnet itself needs neither, only root, so this starts the interface and
 * relays Ethernet frames to an unprivileged datagram socket that the harness
 * hands to Virtualization.framework. Only this process runs as root; the
 * virtual machine does not.
 */

#include <dispatch/dispatch.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/un.h>
#include <unistd.h>
#include <vmnet/vmnet.h>
#include <xpc/xpc.h>

#define HELPER_SUFFIX ".vm"

static interface_ref g_interface;
static dispatch_queue_t g_queue;
static int g_socket = -1;
static uint64_t g_max_packet = 1518;
/* The relay runs on two threads -- vmnet delivers on its dispatch queue while
   the main thread reads the guest -- and these counters are the only account
   of what moved. Kept non-atomic once, they were held in a register and
   reported zero while frames were plainly flowing, which cost an evening. */
static _Atomic unsigned long g_from_vmnet, g_to_guest, g_from_guest, g_to_vmnet,
    g_send_errors, g_read_errors;

static FILE *g_log;

static void open_log(const char *path) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s.log", path);
    g_log = fopen(log_path, "a");
    if (g_log != NULL) {
        (void)chmod(log_path, 0666);
        setvbuf(g_log, NULL, _IOLBF, 0);
    }
}

static void note(const char *message) {
    if (g_log != NULL) {
        fprintf(g_log, "vmnet-helper: %s\n", message);
    }
    fprintf(stderr, "vmnet-helper: %s\n", message);
    fflush(stderr);
}

/* 192.168.18.0/24 was what vmnet chose unprompted, and it collided with a real
   LAN. This is deliberately somewhere less popular. */
#define XAIOS_VMNET_DEFAULT_SUBNET "192.168.201"

static void report(const char *reason) {
    char line[256];
    snprintf(line, sizeof(line),
             "%s vmnet->guest read=%lu sent=%lu send_err=%lu read_err=%lu | "
             "guest->vmnet recv=%lu written=%lu",
             reason, g_from_vmnet, g_to_guest, g_send_errors, g_read_errors,
             g_from_guest, g_to_vmnet);
    note(line);
}

static void relay_to_socket(void) {
    for (;;) {
        char buffer[65550];
        struct iovec iov = {buffer, (size_t)g_max_packet};
        struct vmpktdesc packet = {0};
        packet.vm_pkt_size = (size_t)g_max_packet;
        packet.vm_pkt_iov = &iov;
        packet.vm_pkt_iovcnt = 1;
        int count = 1;
        vmnet_return_t status = vmnet_read(g_interface, &packet, &count);
        if (status != VMNET_SUCCESS) {
            ++g_read_errors;
            report("read failed");
            return;
        }
        if (count < 1) {
            return;
        }
        ++g_from_vmnet;
        /* Read first, then decide. Returning early when no machine is attached
           left the packet sitting in vmnet's queue, so the event never cleared
           and the callback fired again immediately: the helper held a core busy
           for as long as anything was on the network, with its counters frozen
           because nothing was ever read. A frame with nowhere to go is dropped
           here, which is what an unattached interface should do anyway. */
        if (g_socket < 0) {
            continue;
        }
        if (send(g_socket, buffer, packet.vm_pkt_size, 0) < 0) {
            ++g_send_errors;
            if (g_send_errors <= 3UL) {
                fprintf(stderr, "vmnet-helper: sendto: %s\n", strerror(errno));
                fflush(stderr);
            }
        } else {
            ++g_to_guest;
        }
        if ((g_from_vmnet % 10UL) == 0UL) report("progress");
    }
}

static void relay_to_vmnet(int client) {
    for (;;) {
        /* A datagram socketpair reports no end-of-file when the far end goes
           away, so a blocking receive here would serve a departed guest for
           ever and never take the next one. The rendezvous stream does report
           it, so watch both and leave when that closes. */
        struct pollfd watch[2];
        watch[0].fd = g_socket;
        watch[0].events = POLLIN;
        watch[0].revents = 0;
        watch[1].fd = client;
        /* Ask for readability rather than relying on POLLHUP alone: a poll
           that requests no events is not obliged to report a hangup, and one
           that never notices the guest leaving wedges the helper for good. */
        watch[1].events = POLLIN;
        watch[1].revents = 0;
        if (poll(watch, 2, -1) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if ((watch[1].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            return;
        }
        if ((watch[1].revents & POLLIN) != 0) {
            char discard;
            if (recv(client, &discard, 1, 0) <= 0) {
                return;
            }
        }
        if ((watch[0].revents & POLLIN) == 0) {
            continue;
        }
        char buffer[65550];
        ssize_t length = recv(g_socket, buffer, sizeof(buffer), 0);
        if (length <= 0) {
            if (length < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            return;
        }
        struct iovec iov = {buffer, (size_t)length};
        struct vmpktdesc packet = {0};
        packet.vm_pkt_size = (size_t)length;
        packet.vm_pkt_iov = &iov;
        packet.vm_pkt_iovcnt = 1;
        int count = 1;
        ++g_from_guest;
        if (vmnet_write(g_interface, &packet, &count) == VMNET_SUCCESS) {
            ++g_to_vmnet;
        }
    }
}

int main(int argc, char **argv) {
    const char *path = NULL;
    const char *subnet = NULL;
    uint64_t mode = VMNET_SHARED_MODE;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            ++i;
            mode = strcmp(argv[i], "host") == 0 ? VMNET_HOST_MODE
                                                : VMNET_SHARED_MODE;
        } else if (strcmp(argv[i], "--subnet") == 0 && i + 1 < argc) {
            subnet = argv[++i];
        } else {
            fprintf(stderr,
                    "usage: vmnet-helper --socket <path> [--mode shared|host] "
                    "[--subnet A.B.C]\n");
            return 2;
        }
    }
    struct sockaddr_un address_limit;
    if (subnet == NULL) subnet = XAIOS_VMNET_DEFAULT_SUBNET;
    if (path == NULL || strlen(path) + sizeof(HELPER_SUFFIX) >
                            sizeof(address_limit.sun_path)) {
        fprintf(stderr, "vmnet-helper: a usable --socket path is required\n");
        return 2;
    }

    xpc_object_t description = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(description, vmnet_operation_mode_key, mode);
    /* Ask for a subnet nobody is likely to be using. Left to choose, vmnet
       picked 192.168.18.0/24 on this machine and took 192.168.18.1 for the
       bridge -- which was also the address of the real router on the operator's
       own LAN. The host then had two interfaces on one subnet, resolved the
       guest through the physical one, and every packet went out to the real
       network and died there. Nothing in the guest or the helper looked wrong:
       the guest took a DHCP lease and answered router advertisements, while
       ping and ssh from the host simply never arrived. */
    if (subnet != NULL) {
      char start[32];
      char end[32];
      snprintf(start, sizeof(start), "%s.2", subnet);
      snprintf(end, sizeof(end), "%s.254", subnet);
      xpc_dictionary_set_string(description, vmnet_start_address_key, start);
      xpc_dictionary_set_string(description, vmnet_end_address_key, end);
      xpc_dictionary_set_string(description, vmnet_subnet_mask_key,
                                "255.255.255.0");
    }
    g_queue = dispatch_queue_create("xaios.vmnet", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t started = dispatch_semaphore_create(0);
    __block vmnet_return_t status = VMNET_FAILURE;
    static char mac[64];
    g_interface = vmnet_start_interface(
        description, g_queue, ^(vmnet_return_t result, xpc_object_t params) {
            status = result;
            if (result == VMNET_SUCCESS && params != NULL) {
                const char *address =
                    xpc_dictionary_get_string(params, vmnet_mac_address_key);
                if (address != NULL) {
                    snprintf(mac, sizeof(mac), "%s", address);
                }
                g_max_packet =
                    xpc_dictionary_get_uint64(params, vmnet_max_packet_size_key);
                if (g_max_packet == 0U || g_max_packet > 65538U) {
                    g_max_packet = 1518U;
                }
            }
            dispatch_semaphore_signal(started);
        });
    if (g_interface == NULL) {
        fprintf(stderr, "vmnet-helper: vmnet_start_interface refused\n");
        return 1;
    }
    dispatch_semaphore_wait(started, DISPATCH_TIME_FOREVER);
    if (status != VMNET_SUCCESS) {
        fprintf(stderr,
                "vmnet-helper: vmnet did not start status=%d (root required)\n",
                (int)status);
        return 1;
    }

    /* Virtualization.framework wants a genuine connected datagram socket. A
       pair of sockets that merely bind paths and connect to each other looks
       equivalent and is not: it delivers the first few frames into the guest
       and then stops being read, while the guest's own traffic still flows
       out. Create a socketpair here and pass one end over, which measured
       3159 of 3160 frames delivered where the named pair managed four. */
    int rendezvous = socket(AF_UNIX, SOCK_STREAM, 0);
    if (rendezvous < 0) {
        perror("vmnet-helper: socket");
        return 1;
    }
    struct sockaddr_un local = {0};
    local.sun_family = AF_UNIX;
    snprintf(local.sun_path, sizeof(local.sun_path), "%s", path);
    (void)unlink(local.sun_path);
    if (bind(rendezvous, (struct sockaddr *)&local,
             (socklen_t)SUN_LEN(&local)) < 0 ||
        listen(rendezvous, 8) < 0) {
        perror("vmnet-helper: bind");
        return 1;
    }
    /* The harness runs unprivileged and must be able to collect its end. */
    (void)chmod(local.sun_path, 0666);
    open_log(path);
    note("listening");

    printf("vmnet-helper: %s mode ready mac=%s mtu=%llu socket=%s\n",
           mode == VMNET_HOST_MODE ? "host" : "shared", mac,
           (unsigned long long)g_max_packet, path);
    fflush(stdout);

    vmnet_interface_set_event_callback(
        g_interface, VMNET_INTERFACE_PACKETS_AVAILABLE, g_queue,
        ^(interface_event_t events, xpc_object_t event) {
            (void)events;
            (void)event;
            relay_to_socket();
        });

    /* Serve one virtual machine at a time and any number of them in turn: a
       helper that accepted once left every later boot hanging on a handover
       that would never come. */
    for (;;) {
        int client = accept(rendezvous, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("vmnet-helper: accept");
            return 1;
        }

        int pair[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0) {
            perror("vmnet-helper: socketpair");
            close(client);
            continue;
        }
        /* The attachment requires the receive buffer to be at least double the
           send buffer, and recommends four times. */
        int send_buffer = 1 << 18;
        int receive_buffer = send_buffer * 4;
        for (int index = 0; index < 2; ++index) {
            (void)setsockopt(pair[index], SOL_SOCKET, SO_SNDBUF, &send_buffer,
                             sizeof(send_buffer));
            (void)setsockopt(pair[index], SOL_SOCKET, SO_RCVBUF,
                             &receive_buffer, sizeof(receive_buffer));
        }

        /* The guest must present the address vmnet assigned this interface.
           vmnet learns which port owns which address, and a guest answering on
           an address the switch never saw here receives multicast, which is
           flooded, but no broadcast or unicast aimed at it. Hand the address
           over with the socket. */
        struct msghdr message = {0};
        char control[CMSG_SPACE(sizeof(int))] = {0};
        char address[32];
        snprintf(address, sizeof(address), "%s", mac);
        struct iovec payload = {address, sizeof(address)};
        message.msg_iov = &payload;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &pair[0], sizeof(int));
        if (sendmsg(client, &message, 0) < 0) {
            perror("vmnet-helper: sendmsg");
            close(pair[0]);
            close(pair[1]);
            close(client);
            continue;
        }
        close(pair[0]);

        g_socket = pair[1];
        note("guest attached");
        relay_to_vmnet(client);
        report("guest detached");
        g_socket = -1;
        close(pair[1]);
        close(client);
    }
    return 0;
}
