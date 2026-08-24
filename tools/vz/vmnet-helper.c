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
#include <sys/un.h>
#include <unistd.h>
#include <vmnet/vmnet.h>
#include <xpc/xpc.h>

#define HELPER_SUFFIX ".vm"

static interface_ref g_interface;
static dispatch_queue_t g_queue;
static int g_socket = -1;
static uint64_t g_max_packet = 1518;
static struct sockaddr_un g_peer;
static unsigned long g_from_vmnet, g_to_guest, g_from_guest, g_to_vmnet,
    g_send_errors, g_read_errors;

static void report(const char *reason) {
    fprintf(stderr,
            "vmnet-helper: %s vmnet->guest read=%lu sent=%lu send_err=%lu "
            "read_err=%lu | guest->vmnet recv=%lu written=%lu\n",
            reason, g_from_vmnet, g_to_guest, g_send_errors, g_read_errors,
            g_from_guest, g_to_vmnet);
    fflush(stderr);
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
        if (sendto(g_socket, buffer, packet.vm_pkt_size, 0,
                   (struct sockaddr *)&g_peer,
                   (socklen_t)SUN_LEN(&g_peer)) < 0) {
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

static void relay_to_vmnet(void) {
    for (;;) {
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
    uint64_t mode = VMNET_SHARED_MODE;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            ++i;
            mode = strcmp(argv[i], "host") == 0 ? VMNET_HOST_MODE
                                                : VMNET_SHARED_MODE;
        } else {
            fprintf(stderr,
                    "usage: vmnet-helper --socket <path> [--mode shared|host]\n");
            return 2;
        }
    }
    if (path == NULL || strlen(path) + sizeof(HELPER_SUFFIX) >
                            sizeof(g_peer.sun_path)) {
        fprintf(stderr, "vmnet-helper: a usable --socket path is required\n");
        return 2;
    }

    xpc_object_t description = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(description, vmnet_operation_mode_key, mode);
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

    g_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_socket < 0) {
        perror("vmnet-helper: socket");
        return 1;
    }
    struct sockaddr_un local = {0};
    local.sun_family = AF_UNIX;
    snprintf(local.sun_path, sizeof(local.sun_path), "%s", path);
    (void)unlink(local.sun_path);
    if (bind(g_socket, (struct sockaddr *)&local, (socklen_t)SUN_LEN(&local)) <
        0) {
        perror("vmnet-helper: bind");
        return 1;
    }
    /* The harness binds the same path with a suffix, so each side knows where
       to send without either having to be started first. */
    memset(&g_peer, 0, sizeof(g_peer));
    g_peer.sun_family = AF_UNIX;
    snprintf(g_peer.sun_path, sizeof(g_peer.sun_path), "%s%s", path,
             HELPER_SUFFIX);
    /* The harness runs unprivileged and must be able to reach this socket. */
    (void)chmod(local.sun_path, 0666);

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

    relay_to_vmnet();
    return 0;
}
