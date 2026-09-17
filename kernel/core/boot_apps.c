/* Userspace launch: the application half of the boot path.
 * See boot_apps_internal.h. The launch helpers and the capability masks move
 * verbatim; the boot order stays in kmain, which calls these stages at the
 * same points in the sequence.
 */

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/boot_ui.h>
#include <xaios/dhcpv6.h>
#include <xaios/dns.h>
#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/network_stack.h>
#include <xaios/service.h>
#include <xaios/setup_apply.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>
#include <xaios/user.h>
#include <xaios/xaiboot_fs.h>

#include "boot_apps_internal.h"
#include "boot_storage_internal.h"

/* Run an application to completion and return its exit code. `expected` is
   the code that means it did its job -- zero for nearly everything, and
   something else for a probe whose job is to exit that way -- and is what
   the process table judges it by. */
static int run_user_app_expecting(const char *path, uint32_t pid,
                                  uint64_t capabilities, int expected) {
  const xaios_initramfs_file_t *file = 0;
  xaios_user_process_t process;
  if (initramfs_lookup(path, &file) != XAIOS_OK) {
    /* Named, because the assertion alone says only that some application is
       missing from an image holding twenty of them. */
    klog("kernel: %s is not in the initial filesystem\n", path);
  }
  kassert(initramfs_lookup(path, &file) == XAIOS_OK);
  kassert(user_load_process(file, pid, capabilities, &process) == XAIOS_OK);
  kassert(user_process_expect_exit_code(pid, expected) == XAIOS_OK);
  int exit_code = user_process_run(&process);
  if (exit_code != expected) {
    klog("kernel: WARNING %s exited with status=%d, expected %d\n",
         path, exit_code, expected);
  }
  klog("kernel: %s returned to kernel exit_code=%d\n",
       path, exit_code);
  user_process_reclaim_address_space(&process);
  return exit_code;
}

static int run_user_app(const char *path, uint32_t pid, uint64_t capabilities) {
  return run_user_app_expecting(path, pid, capabilities, 0);
}

/* /init and the service manager run to completion here, then the persistent
   network stack comes up -- and whether it did decides whether sshd is ever
   started. `worker_file' is looked up by kmain and used by the boot-test
   dispatch below, so it does not cross this function. */
void boot_apps_launch_init(const xaios_initramfs_file_t *init_file,
                           const xaios_initramfs_file_t *manager_file,
                           const xaios_initramfs_config_t *init_config,
                           xaios_status_t persistent_status,
                           uint32_t *network_ready) {
  xaios_user_process_t init_process;
  xaios_user_process_t manager_process;
  kassert(user_load_init(init_file, &init_process) == XAIOS_OK);
  int init_exit_code = user_process_run(&init_process);
  kassert(init_exit_code == 0);
  klog("kernel: /init returned to kernel exit_code=%u\n",
       (unsigned)init_exit_code);
  user_process_reclaim_address_space(&init_process);

  kassert(user_load_process(manager_file, 2,
                            XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_SERVICE_CONTROL |
                                XAIOS_CAP_ADMIN | XAIOS_CAP_FS_WRITE,
                            &manager_process) == XAIOS_OK);
  kassert(service_start(init_config->service_manager_path) == XAIOS_OK);
  int manager_exit_code = user_process_run(&manager_process);
  if (manager_exit_code != 0 && persistent_status != XAIOS_OK) {
    klog("kernel: service-manager deferred exit_code=%u no writable persistent storage status=%d\n",
         (unsigned)manager_exit_code, (int)persistent_status);
  } else {
    kassert(manager_exit_code == 0);
    klog("kernel: /bin/service-manager returned to kernel exit_code=%u\n",
         (unsigned)manager_exit_code);
  }
  user_process_reclaim_address_space(&manager_process);

  /* Initialize persistent network for real TX/RX */
  if (network_device_init_persistent() == XAIOS_OK) {
    /* Ask the network for an address before falling back to the compiled-in
       one. That default is QEMU user-mode networking's, and a guest that
       assumes it is simply off-net anywhere else: Virtualization.framework
       hands out a different subnet entirely. QEMU answers DHCP with the same
       address it always did, so nothing changes there. */
    /* Six seconds left room for barely two attempts once retransmission
       backs off, and a server that is slow rather than absent was being
       written off as absent. Fifteen costs nothing when a lease arrives on
       the first try, and is only ever paid in full where there is no DHCP
       server at all. */
    if (network_config_dhcp(UINT64_C(30000000000)) != XAIOS_OK) {
      if (network_device_kind() == XAIOS_NETWORK_DEVICE_E1000E) {
        klog("kernel: DHCP configuration failed for e1000e\n");
        boot_ui_error("network DHCP", XAIOS_ERR_IO);
        goto persistent_network_done;
      }
      klog("kernel: DHCP unanswered; keeping the compiled-in address\n");
    }
    network_init_persistent();
    (void)network_wait_for_ipv6_slaac(UINT64_C(3000000000));
    /* Ask for a lease as well. SLAAC and DHCPv6 answer different questions --
       one derives an address from an announced prefix, the other has a server
       assign and record one -- and a guest does not get to choose which its
       network offers. A network with no DHCPv6 server simply never answers,
       which is why this is not allowed to fail the boot: the budget is short
       and the outcome is logged either way. */
    {
      xaios_dhcpv6_lease_t lease;
      if (dhcpv6_acquire(UINT64_C(4000000000), &lease) == XAIOS_OK &&
          lease.have_address != 0U) {
        (void)network_stack_adopt_dhcpv6(&lease.address,
                                         lease.valid_lifetime_s);
      } else {
        klog("kernel: no DHCPv6 lease; IPv6 stays as router advertisement "
             "configured it\n");
      }
    }
    dns_init();
    dns_configure(network_config_dns_server());
    klog("kernel: persistent network stack enabled device=%s\n",
         network_device_name());
    *network_ready = 1U;
    boot_ui_update(80U, "network stack", "scheduler", 2U);
  } else {
    klog("kernel: persistent network init skipped\n");
    boot_ui_error("network-stack", XAIOS_ERR_IO);
  }
persistent_network_done:;
}

#if XAIOS_BOOT_TEST_APPS
void boot_apps_run_test_dispatch(const xaios_initramfs_file_t *worker_file) {
  /* One process dispatched as a *task* rather than as a call, which is
     what makes an EL0 process preemptible: it owns its kernel stack, the
     timer can take the CPU away from it, and the switch count across the
     window says whether that happened. The three workers below keep the
     sequential path, so a failure here is isolated to this dispatch. */
  {
    const xaios_initramfs_file_t *scheduled_file = 0;
    xaios_user_process_t scheduled_process;
    xaios_user_dispatch_result_t scheduled;
    kassert(initramfs_lookup("/bin/hello", &scheduled_file) == XAIOS_OK);
    kassert(user_load_process(scheduled_file, 6U,
                              XAIOS_CAP_LOG | XAIOS_CAP_EXIT,
                              &scheduled_process) == XAIOS_OK);
    int scheduled_exit =
        user_process_run_scheduled(&scheduled_process, 0, &scheduled);
    kassert(scheduled_exit == 0);
    klog("kernel: /bin/hello scheduled dispatch pid=6 switches=%lu "
         "exit_code=%d\n",
         (unsigned long)scheduled.switches, scheduled_exit);
    user_process_reclaim_address_space(&scheduled_process);
  }
  /* The EL0 preemption proof and its control, in one boot.
   *
   * `/bin/spin` never blocks: it loops in EL0 for a fixed wall-clock span, so
   * the only thing that can take the CPU away from it is the timer. With the
   * dispatching context left runnable at the same priority and moved behind
   * the process, the two alternate and the switch count *is* the preemption.
   * With the dispatcher blocked the process is the only runnable task, so the
   * count stops at the dispatch and the hand-back -- which is exactly what an
   * earlier measurement misread as EL0 not being preemptible. Running both is
   * what makes the positive number mean something: same process, same span,
   * one difference. A port that cannot start a task in kernel mode never
   * reaches either run and says so rather than passing a test it cannot
   * take (B-132). */
  if (user_process_scheduled_dispatch_supported() != 0) {
    const xaios_initramfs_file_t *spin_file = 0;
    const uint64_t spin_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME;
    kassert(initramfs_lookup("/bin/spin", &spin_file) == XAIOS_OK);

    xaios_user_process_t preempted_process;
    xaios_user_dispatch_result_t preempted;
    kassert(user_load_process(spin_file, 7U, spin_caps,
                              &preempted_process) == XAIOS_OK);
    int preempted_exit =
        user_process_run_scheduled(&preempted_process, 0, &preempted);
    kassert(preempted_exit == 0);
    kassert(preempted.as_task != 0);
    klog("kernel: /bin/spin preempted pid=7 switches=%lu exit_code=%d "
         "as_task=%d\n",
         (unsigned long)preempted.switches, preempted_exit, preempted.as_task);
    /* Two switches are the dispatch and the hand-back. Four or more can only
       be the timer taking the CPU from EL0 and giving it back more than once,
       because nothing else in this window can switch this CPU. */
    kassert(preempted.switches >= 4U);
    user_process_reclaim_address_space(&preempted_process);

    xaios_user_process_t blocked_process;
    xaios_user_dispatch_result_t blocked;
    kassert(user_load_process(spin_file, 8U, spin_caps,
                              &blocked_process) == XAIOS_OK);
    int blocked_exit =
        user_process_run_scheduled(&blocked_process, 1, &blocked);
    kassert(blocked_exit == 0);
    kassert(blocked.as_task != 0);
    klog("kernel: /bin/spin blocked dispatcher pid=8 switches=%lu "
         "exit_code=%d as_task=%d\n",
         (unsigned long)blocked.switches, blocked_exit, blocked.as_task);
    /* The control: the same process over the same span, strictly fewer
       switches because the dispatcher gave the CPU up instead of competing
       for it. */
    kassert(blocked.switches < preempted.switches);
    user_process_reclaim_address_space(&blocked_process);
  } else {
    klog("kernel: /bin/spin preemption proof not applicable -- this port "
         "cannot start a task in kernel mode\n");
  }
  for (uint32_t pid = 3; pid <= 5; ++pid) {
    xaios_user_process_t worker_process;
    kassert(user_load_process(worker_file, pid, XAIOS_CAP_LOG | XAIOS_CAP_EXIT,
                              &worker_process) == XAIOS_OK);
    kassert(user_process_make_runnable(pid, 2) == XAIOS_OK);
    kassert(user_process_snapshot(pid, &worker_process) == XAIOS_OK);
    kassert(service_start("/bin/xaios-worker") == XAIOS_OK);
    int worker_exit_code = user_process_run(&worker_process);
    kassert(worker_exit_code == 0);
    /* A user exit leaves through the port's own return path, and what it
       restores is part of its contract: this kernel called `xaios_enter_user`
       with interrupts on and gets them back on. RISC-V returned with them off
       until this check existed, which is invisible until the kernel has to wait
       for a tick -- a scheduled task handing the CPU back, for one. */
    uint32_t resumed_interrupts = (uint32_t)xaios_interrupts_enabled();
    klog("kernel: /bin/xaios-worker pid=%u returned to kernel exit_code=%u "
         "interrupts=%u\n",
         pid, (unsigned)worker_exit_code, (unsigned)resumed_interrupts);
#if defined(__riscv)
    kassert(resumed_interrupts != 0U);
#endif
    user_process_reclaim_address_space(&worker_process);
  }
}
#endif

void boot_apps_run_profile(void) {
#if XAIOS_BOOT_TEST_APPS
  /* Deterministic QEMU gate profile: execute diagnostic applications once. */
  const uint64_t shell_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
      XAIOS_CAP_FS_WRITE | XAIOS_CAP_OSCTL | XAIOS_CAP_TIME |
      XAIOS_CAP_NET | XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t hello_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT;
  const uint64_t c99_demo_caps = XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT;
  const uint64_t xaiosctl_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_TIME | XAIOS_CAP_CONTROL_QUERY | XAIOS_CAP_STORAGE_READ;
  const uint64_t sysinfo_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME;
  const uint64_t systest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE;
  const uint64_t smptest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_OSCTL | XAIOS_CAP_SMP | XAIOS_CAP_THREADS;
  const uint64_t nettest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_OSCTL | XAIOS_CAP_NET | XAIOS_CAP_TIME;
  const uint64_t lstm_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
      XAIOS_CAP_ML;
  const uint64_t sshtest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_NET |
      XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t mltest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
      XAIOS_CAP_ML;
  const uint64_t posix_shell_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t agenttest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_AGENT |
      XAIOS_CAP_CPU_AI | XAIOS_CAP_ML;
  run_user_app("/bin/xaios-shell", 6, shell_caps);
  run_user_app("/bin/xaiosctl", 7, xaiosctl_caps);
  run_user_app("/bin/hello", 8, hello_caps);
  run_user_app("/bin/sysinfo", 9, sysinfo_caps);
  run_user_app("/bin/systest", 10, systest_caps);
  run_user_app("/bin/smptest", 11, smptest_caps);
  /* B-02's window, entered on purpose: a user process waiting in
     xaios_thread_join with a thread pending on its own CPU, so the join has
     to run that thread nested inside its own syscall. Needs the same
     capabilities as smptest and nothing else -- it checks that the CPU it
     borrowed came back by using two of them after the nested run. It costs
     one boot two threads and no soak time, so it runs wherever the test apps
     run rather than behind the stress flag. */
  run_user_app("/bin/joinnest", 11, smptest_caps | XAIOS_CAP_TIME);
#if XAIOS_STRESS_TEST
  run_user_app("/bin/smpstress", 11, smptest_caps | XAIOS_CAP_TIME);
  /* Measurement rather than a check: it reports cost and asserts nothing, so
     it runs where the stress app runs and nowhere else. */
  /* NET as well as NET_SOCKET. The socket measurement needs only the socket
     capability, but the poll-path arm calls net_udp_echo, which the syscall
     table guards with XAIOS_CAP_NET -- without it every poll worker is
     refused and the mixed measurement silently has nothing on one side. */
  run_user_app("/bin/perfbench", 11,
               smptest_caps | XAIOS_CAP_TIME | XAIOS_CAP_NET_SOCKET |
               XAIOS_CAP_NET);
#endif
  run_user_app("/bin/nettest", 12, nettest_caps);
  /* Two pinned senders on separate CPUs, which is the only way the
     per-CPU transmit-pair selector is exercised at all: a boot sends
     from one CPU, so every frame correctly lands on pair zero and the
     selector is never asked a second question. Needs THREADS on top of
     the network capabilities, and SMP to place threads by CPU. */
  /* NET_SOCKET as well: the sender binds a UDP socket and sends through it,
     which is the only path that reaches network_device_tx. Without it every
     bind is refused, no frame is transmitted, and the fan-out this exists to
     show cannot happen -- which is exactly what the first run on a four-queue
     tap did. The app counts its own failures and says so, but the driver's
     frames_by_pair line is what the claim rests on. */
  run_user_app("/bin/netmqtest", 12,
               nettest_caps | XAIOS_CAP_THREADS | XAIOS_CAP_SMP |
               XAIOS_CAP_NET_SOCKET);
  /* WT-35: a datagram socket the kernel names, which is what a QUIC client
     has before its first packet. Only NET_SOCKET is needed -- the whole
     surface is open_udp, sendto and close, none of which reads a socket
     option or a network-wide setting that CAP_NET guards, and the app asserts
     nothing, so it cannot fail a boot on a number it disagrees with. */
  run_user_app("/bin/netsocktest", 12, XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
                                           XAIOS_CAP_NET_SOCKET);
  run_user_app("/bin/lstm-xor", 13, lstm_caps);
  run_user_app("/bin/sshtest", 14, sshtest_caps);
  run_user_app("/bin/mltest", 15, mltest_caps);
  run_user_app("/bin/posix-shell", 16, posix_shell_caps);
  run_user_app("/bin/agenttest", 17, agenttest_caps);
#if XAIOS_CLUSTER_TEST
  /* The cluster data plane, which needs a socket rather than a simulated one.
     
     Behind a flag rather than in every boot, because it dials a peer, and a
     machine that is not in a cluster should not open a connection to one on
     every start. It did briefly, and the cost was not the connection: the
     network suite pins exact telemetry counters -- resets, closes, queue
     enqueues -- and an extra dial moved all of them, so a test of the TCP
     state machine failed because something unrelated had used the network.
     make qemu-cluster-gate builds with this set. */
  run_user_app("/bin/clustertest", 18, nettest_caps | XAIOS_CAP_NET_SOCKET);
#endif
  kassert(run_user_app("/bin/helloworldc99", 23U, c99_demo_caps) == 0);
#if XAIOS_WT_HANDSHAKE_TEST
  /* The port's own client, on a booted guest: the vendored library driven by
     this repository's BearSSL backend, its XAIOS socket seam, and a pinned
     certificate (B-131). It prints `wtqtest: WT-HANDSHAKE-OK` itself, which is
     what the gate reads -- the kernel's own line says only that it exited. */
  kassert(run_user_app("/bin/wtqtest", 25U,
                       XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT | XAIOS_CAP_TIME |
                           XAIOS_CAP_NET_SOCKET | XAIOS_CAP_RANDOM) == 0);
#endif
#else
  klog("kernel: boot diagnostics disabled; utilities are SSH on-demand\n");
#endif

#if XAIOS_LIBC_TEST
  const uint64_t libc_test_caps =
      XAIOS_CAP_EXIT | XAIOS_CAP_CONSOLE | XAIOS_CAP_TIME |
      XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE | XAIOS_CAP_THREADS;
  kassert(run_user_app("/bin/c99-runtime-smoke", 19U, libc_test_caps) == 0);
  kassert(run_user_app("/bin/c99-main-void", 20U, libc_test_caps) == 0);
  kassert(run_user_app_expecting("/bin/c99-exit-probe", 21U, libc_test_caps,
                                 23) == 23);
  kassert(run_user_app_expecting("/bin/c99-abort-probe", 22U, libc_test_caps,
                                 134) == 134);
  /* The thread-context probe places a thread on a CPU other than the one it
     is running on, and there is no such CPU on a uniprocessor machine: the
     scheduler refuses, correctly, and the probe cannot test what it exists to
     test. Run where it means something and say so where it does not, rather
     than asserting a result the machine cannot produce. */
  if (smp_online_count() > 1U) {
    kassert(run_user_app("/bin/c99-thread-context", 24U, libc_test_caps) == 0);
  } else {
    klog("C99-THREAD-CONTEXT-SKIPPED: one CPU, nowhere to place a thread\n");
  }
  klog("C99-TERMINATION-PROBES-PASS\n");
#endif
}

void boot_apps_run_tail(void) {
  const uint64_t sshd_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
      XAIOS_CAP_FS_WRITE | XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN |
      XAIOS_CAP_NET | XAIOS_CAP_TIME | XAIOS_CAP_RANDOM |
      XAIOS_CAP_CONSOLE | XAIOS_CAP_CONTROL_QUERY |
      XAIOS_CAP_CONTROL_ADMIN | XAIOS_CAP_STORAGE_READ |
      XAIOS_CAP_STORAGE_MOUNT | XAIOS_CAP_STORAGE_FORMAT |
      XAIOS_CAP_STORAGE_PARTITION | XAIOS_CAP_STORAGE_REPAIR |
      XAIOS_CAP_STORAGE_RESIZE | XAIOS_CAP_STORAGE_TRIM |
      XAIOS_CAP_MODEL_STAGE | XAIOS_CAP_MODEL_ACTIVATE |
      XAIOS_CAP_OSCTL | XAIOS_CAP_SERVICE_CONTROL | XAIOS_CAP_UPDATE |
      XAIOS_CAP_ADMIN;
  /* A machine with no user database has no account, so nobody can log into
     it -- the login prompt would ask for a username that does not exist. Run
     setup first and let the person make one.

     Before sshd, not beside it: the console is a single shared ring and
     whoever reads it takes the keystroke, so two programs on it would race
     for every character. Setup runs to completion and exits.

     An image that packages credentials never gets here, which is every gate
     image and every development build. */
  /* Only when there is no way in at all.

     "No password account" is not the same question. An image that ships
     authorized keys and no password database is a configured machine -- it is
     how a fleet is built, and how the interoperability gates build theirs --
     and running setup on it stops the boot at a prompt nobody is standing in
     front of, so its SSH server never starts and the machine hangs. That is
     what happened to three CI jobs.

     A machine with either credential can be reached by whoever has it, and is
     not this program's business. */
  xaios_xbfs_stat_t credential;
  int has_password_account =
      xaiboot_fs_stat("/etc/xaios_sshd_users", &credential) == XAIOS_OK;
  int has_authorized_keys =
      xaiboot_fs_stat("/etc/xaios_authorized_keys", &credential) == XAIOS_OK;
  if (has_password_account == 0 && has_authorized_keys == 0) {
    /* Setup offers to install, and an install copies from the partition this
       machine booted. Only the kernel knows which that is -- it is found
       while walking the boot disk's partition table -- so record it where
       setup can read it rather than asking a person to work it out from a
       device list. A machine booted from something with no EFI System
       Partition records nothing, and setup then has to ask. */
    char boot_esp[XAIOS_BLOCK_DEVICE_ID_MAX];
    if (boot_storage_esp_copy(boot_esp, sizeof(boot_esp)) != 0U) {
      char line[XAIOS_BLOCK_DEVICE_ID_MAX + 2U];
      uint64_t used = 0U;
      while (boot_esp[used] != '\0' && used + 2U < sizeof(line)) {
        line[used] = boot_esp[used];
        ++used;
      }
      line[used++] = '\n';
      if (xaiboot_fs_write("/state/boot-esp", line, used) != XAIOS_OK) {
        klog("kernel: could not record the boot ESP for setup\n");
      }
    }
    klog("kernel: no account on this machine; starting /bin/xaios-setup\n");
    const uint64_t setup_caps =
        XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CONSOLE |
        XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE | XAIOS_CAP_RANDOM |
        XAIOS_CAP_TIME | XAIOS_CAP_NET | XAIOS_CAP_CONTROL_QUERY |
        XAIOS_CAP_CONTROL_ADMIN | XAIOS_CAP_STORAGE_READ |
        XAIOS_CAP_STORAGE_MOUNT | XAIOS_CAP_STORAGE_FORMAT |
        XAIOS_CAP_STORAGE_PARTITION | XAIOS_CAP_ADMIN;
    (void)run_user_app("/bin/xaios-setup", 2U, setup_caps);
    /* Setup cannot write /etc -- no userspace process can -- so it leaves
       what it collected under /state and this installs it. */
    setup_apply_pending();
  }

  /* OD-011 needs a way to save the interrupt mask and put it back, and a
     primitive nothing exercises is a primitive nobody has tested.
     It reports three verdicts rather than one, because on the machines this has
     run on it cannot test what it was written to test: interrupts are masked
     here, so `before` is 0, the disable masks nothing that was not already
     masked, and a "passed" would be a claim about a round trip that did not
     happen. The first version of this asserted `before == 1` and halted the
     machine, which is how the masked state was found. What that state means is
     recorded in OD-011 rather than worked around here. */
  {
    int before = xaios_interrupts_enabled();
    xaios_interrupt_state_t saved = xaios_interrupts_disable();
    int masked = xaios_interrupts_enabled();
    xaios_interrupts_restore(saved);
    int after = xaios_interrupts_enabled();
    kassert(masked == 0);
    kassert(after == before);
    if (before == 0) {
      klog("interrupts: save/restore self-test inconclusive before=0 masked=0 "
           "after=0; the enabling direction was never exercised\n");
    } else {
      klog("interrupts: save/restore self-test passed before=%d masked=%d "
           "after=%d\n",
           before, masked, after);
    }
  }

  klog("kernel: starting persistent /bin/sshd service\n");
  int sshd_exit =
      run_user_app("/bin/sshd", XAIOS_BOOT_TEST_APPS ? 18U : 3U, sshd_caps);
  boot_ui_error("sshd", sshd_exit);

  for (;;) {
    xaios_cpu_wait();
  }
}
