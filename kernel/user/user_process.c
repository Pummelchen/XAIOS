/*
 * The user process table, its identity, lifecycle and reaping.
 *
 * Split out of kernel/user/user.c, which was 1512 lines. The table and the
 * transitions over it are one state machine; they move together, and the locks
 * and per-process counters stay beside them.
 */

#include "user_internal.h"

/* Monotonic, never reused. Zero is reserved for "no owner", so the counter
   skips it on wrap. */
static uint32_t g_owner_token_next = 1U;

uint32_t user_process_next_owner_token(void) {
  uint32_t token = g_owner_token_next++;
  if (g_owner_token_next == 0U) g_owner_token_next = 1U;
  return token;
}

xaios_user_process_t g_user_process_table[XAIOS_MAX_USER_PROCESSES];
xaios_user_process_t **g_user_current_process_by_cpu;
uint32_t g_user_current_process_capacity;
xaios_user_process_t *g_user_boot_current_process;

uint64_t g_user_process_transition_count;
uint64_t g_user_process_loaded_count;
uint64_t g_user_process_runnable_count;
uint64_t g_user_process_running_count;
uint64_t g_user_process_waiting_count;
uint64_t g_user_process_exited_count;
uint64_t g_user_process_failed_count;
uint64_t g_user_process_reclaim_count;
uint64_t g_user_process_scheduled_count;
uint64_t g_user_process_wait_count;
uint64_t g_user_process_wake_count;

static uint32_t g_transient_process_busy;
static uint32_t g_transient_process_owner_cpu;
static uint32_t g_transient_process_depth;

void user_process_reset_slot(xaios_user_process_t *process) {
  process->pid = 0;
  process->parent_pid = 0;
  process->name = 0;
  process->state = XAIOS_USER_PROCESS_EMPTY;
  process->exit_code = 0;
  process->expected_exit_code = 0;
  process->capability_mask = 0;
  process->syscall_count = 0;
  process->rejected_syscall_count = 0;
  process->entry = 0;
  process->stack_top = 0;
  process->argv_user = 0;
  process->argc = 0;
  process->reserved_args = 0;
  process->stack_guard_low = 0;
  process->stack_guard_high = 0;
  process->mapped_low = 0;
  process->mapped_high = 0;
  process->scheduler_ticks = 0;
  process->started_ns = 0;
  process->runtime_ns = 0;
  process->running_since_ns = 0;
  process->resident_pages = 0;
  process->running_cpu_id = UINT32_MAX;
  process->runtime_sequence = 0;
  bytes_zero(&process->aspace, sizeof(xaios_process_aspace_t));
}

static xaios_status_t validate_process_transition(xaios_user_process_state_t from,
                                                 xaios_user_process_state_t to) {
  if (from == XAIOS_USER_PROCESS_EMPTY && to == XAIOS_USER_PROCESS_LOADED) {
    return XAIOS_OK;
  }
  if (from == XAIOS_USER_PROCESS_LOADED &&
      (to == XAIOS_USER_PROCESS_RUNNABLE || to == XAIOS_USER_PROCESS_RUNNING)) {
    return XAIOS_OK;
  }
  if (from == XAIOS_USER_PROCESS_RUNNABLE &&
      (to == XAIOS_USER_PROCESS_RUNNING || to == XAIOS_USER_PROCESS_WAITING ||
       to == XAIOS_USER_PROCESS_FAILED)) {
    return XAIOS_OK;
  }
  if (from == XAIOS_USER_PROCESS_WAITING &&
      (to == XAIOS_USER_PROCESS_RUNNABLE || to == XAIOS_USER_PROCESS_FAILED)) {
    return XAIOS_OK;
  }
  if (from == XAIOS_USER_PROCESS_RUNNING &&
      (to == XAIOS_USER_PROCESS_RUNNABLE || to == XAIOS_USER_PROCESS_WAITING ||
       to == XAIOS_USER_PROCESS_EXITED || to == XAIOS_USER_PROCESS_FAILED)) {
    return XAIOS_OK;
  }
  return XAIOS_ERR_INVALID;
}

/* These totals are incremented from whichever CPU the process is running on,
   and this file already keeps the per-process counters beside them atomic. A
   plain increment loses counts when two CPUs transition at once, which now
   actually happens; the boot gates check these totals against thresholds, so
   an undercount reads as a failure that never occurred. */
void user_process_transition(xaios_user_process_t *process,
                             xaios_user_process_state_t state,
                             int exit_code) {
  kassert(process != 0);
  if (process->state == state && process->exit_code == exit_code) {
    return;
  }
  kassert(validate_process_transition(process->state, state) == XAIOS_OK);

  process->state = state;
  process->exit_code = exit_code;
  __sync_fetch_and_add(&g_user_process_transition_count, 1U);

  switch (state) {
  case XAIOS_USER_PROCESS_LOADED:
    __sync_fetch_and_add(&g_user_process_loaded_count, 1U);
    break;
  case XAIOS_USER_PROCESS_RUNNABLE:
    __sync_fetch_and_add(&g_user_process_runnable_count, 1U);
    break;
  case XAIOS_USER_PROCESS_RUNNING:
    __sync_fetch_and_add(&g_user_process_running_count, 1U);
    break;
  case XAIOS_USER_PROCESS_WAITING:
    __sync_fetch_and_add(&g_user_process_waiting_count, 1U);
    break;
  case XAIOS_USER_PROCESS_EXITED:
    __sync_fetch_and_add(&g_user_process_exited_count, 1U);
    break;
  case XAIOS_USER_PROCESS_FAILED:
    __sync_fetch_and_add(&g_user_process_failed_count, 1U);
    break;
  default:
    break;
  }

  klog("user: process pid=%u name=%s state=%s exit_code=%u transitions=%lu\n",
       process->pid, process->name != 0 ? process->name : "(none)",
       process_state_name(state), (unsigned)exit_code,
       g_user_process_transition_count);
}

void user_process_table_init(void) {
  for (uint32_t i = 0; i < XAIOS_MAX_USER_PROCESSES; ++i) {
    user_process_reset_slot(&g_user_process_table[i]);
  }
  g_user_current_process_capacity = smp_capacity();
  g_user_current_process_by_cpu = (xaios_user_process_t **)kheap_calloc(
      (uint64_t)g_user_current_process_capacity *
          sizeof(*g_user_current_process_by_cpu),
      64U);
  /* A capacity of zero is not a machine with no CPUs; it is this running
     before the CPU count is known. The per-CPU bindings then fall back to a
     single global, which works until two things want different ones -- and
     then a worker finishing on any CPU clears the binding of the process
     running on every other. Said out loud rather than tolerated. */
  klog("user: process table for %u cpus, storage=%s\n",
       g_user_current_process_capacity,
       g_user_current_process_by_cpu != 0 ? "allocated" : "none");
  kassert(g_user_current_process_capacity != 0U);
  kassert(g_user_current_process_by_cpu != 0);
  g_user_boot_current_process = 0;
  g_user_process_transition_count = 0;
  g_user_process_loaded_count = 0;
  g_user_process_runnable_count = 0;
  g_user_process_running_count = 0;
  g_user_process_waiting_count = 0;
  g_user_process_exited_count = 0;
  g_user_process_failed_count = 0;
  g_user_process_reclaim_count = 0;
  g_user_process_scheduled_count = 0;
  g_user_process_wait_count = 0;
  g_user_process_wake_count = 0;
  g_transient_process_busy = 0U;
  g_transient_process_owner_cpu = UINT32_MAX;
  g_transient_process_depth = 0U;
  /* The CPU-usage records this process table is reported through; the records
     and their storage are the accounting module's, the slots above are this
     one's. */
  user_cpu_usage_init();
}

void user_process_lifecycle_self_test(void) {
  kassert(validate_process_transition(XAIOS_USER_PROCESS_EMPTY,
                                      XAIOS_USER_PROCESS_LOADED) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_LOADED,
                                      XAIOS_USER_PROCESS_RUNNABLE) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_RUNNABLE,
                                      XAIOS_USER_PROCESS_RUNNING) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_RUNNING,
                                      XAIOS_USER_PROCESS_WAITING) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_WAITING,
                                      XAIOS_USER_PROCESS_RUNNABLE) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_RUNNING,
                                      XAIOS_USER_PROCESS_EXITED) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_RUNNING,
                                      XAIOS_USER_PROCESS_FAILED) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_EMPTY,
                                      XAIOS_USER_PROCESS_RUNNING) ==
          XAIOS_ERR_INVALID);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_RUNNABLE,
                                      XAIOS_USER_PROCESS_EXITED) ==
          XAIOS_ERR_INVALID);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_EXITED,
                                      XAIOS_USER_PROCESS_RUNNING) ==
          XAIOS_ERR_INVALID);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_FAILED,
                                      XAIOS_USER_PROCESS_RUNNING) ==
          XAIOS_ERR_INVALID);
  klog("user: process lifecycle invalid/failed transition self-test passed\n");
}

void user_scheduler_self_test(void) {
  kassert(validate_process_transition(XAIOS_USER_PROCESS_LOADED,
                                      XAIOS_USER_PROCESS_RUNNABLE) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_RUNNABLE,
                                      XAIOS_USER_PROCESS_WAITING) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_WAITING,
                                      XAIOS_USER_PROCESS_RUNNABLE) == XAIOS_OK);
  kassert(validate_process_transition(XAIOS_USER_PROCESS_EMPTY,
                                      XAIOS_USER_PROCESS_WAITING) ==
          XAIOS_ERR_INVALID);
  klog("scheduler: lifecycle self-test passed\n");
}

xaios_status_t user_process_make_runnable(uint32_t pid, uint32_t parent_pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES || parent_pid == pid) {
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  if (process->pid != pid) {
    return XAIOS_ERR_INVALID;
  }

  process->parent_pid = parent_pid;
  user_process_transition(process, XAIOS_USER_PROCESS_RUNNABLE, 0);
  klog("scheduler: process pid=%u parent=%u runnable name=%s\n", process->pid,
       process->parent_pid, process->name != 0 ? process->name : "(none)");
  return XAIOS_OK;
}

xaios_status_t user_process_wait(uint32_t pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES) {
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  if (process->pid != pid) {
    return XAIOS_ERR_INVALID;
  }

  user_process_transition(process, XAIOS_USER_PROCESS_WAITING,
                          process->exit_code);
  __sync_fetch_and_add(&g_user_process_wait_count, 1U);
  klog("scheduler: process pid=%u waiting waits=%lu\n", pid,
       g_user_process_wait_count);
  return XAIOS_OK;
}

xaios_status_t user_process_wake(uint32_t pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES) {
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  if (process->pid != pid) {
    return XAIOS_ERR_INVALID;
  }

  user_process_transition(process, XAIOS_USER_PROCESS_RUNNABLE,
                          process->exit_code);
  __sync_fetch_and_add(&g_user_process_wake_count, 1U);
  klog("scheduler: process pid=%u woken wakes=%lu\n", pid,
       g_user_process_wake_count);
  return XAIOS_OK;
}

void user_process_reclaim_address_space(const xaios_user_process_t *process) {
  if (process == 0) {
    return;
  }
  if (process->pid != 0U &&
      xaios_user_thread_drain(process->pid, UINT64_C(5000000000)) !=
          XAIOS_OK) {
    klog("user: address-space reclaim deferred pid=%u active threads remain\n",
         process->pid);
    return;
  }
  syscall_release_process_resources(process->owner_token);

  /* Use ELF loader reclaim for processes with per-process address spaces */
  if (process->aspace.l3_count > 0) {
    uint32_t reclaimed_pages = process->aspace.page_count;
    elf_loader_reclaim((xaios_process_aspace_t *)&process->aspace,
                       process->mapped_low, process->mapped_high);
    if (process->pid != 0U && process->pid <= XAIOS_MAX_USER_PROCESSES &&
        g_user_process_table[process->pid - 1U].pid == process->pid) {
      xaios_user_process_t *slot = &g_user_process_table[process->pid - 1U];
      slot->resident_pages = 0U;
      bytes_zero(&slot->aspace, sizeof(slot->aspace));
    }
    __sync_fetch_and_add(&g_user_process_reclaim_count, 1U);
    klog("user: reclaimed aspace pid=%u pages=%u\n",
         process->pid, reclaimed_pages);
    return;
  }

  /* Legacy reclaim: walk mapped range and free pages from global tables */
  if (process->mapped_low == 0 ||
      process->mapped_high <= process->mapped_low) {
    return;
  }

  for (uint64_t va = process->mapped_low; va < process->mapped_high;
       va += PAGE_SIZE) {
    uint64_t physical = 0;
    uint32_t flags = 0;
    if (vmm_translate(va, &physical, &flags) == XAIOS_OK &&
        (flags & XAIOS_VMM_USER) != 0) {
      kassert(vmm_unmap_page(va) == XAIOS_OK);
      pmm_free_page((void *)(uintptr_t)physical);
    }
  }
  __sync_fetch_and_add(&g_user_process_reclaim_count, 1U);
  klog("user: reclaimed address space pid=%u range=[0x%lx,0x%lx)\n",
       process->pid, process->mapped_low, process->mapped_high);
}

xaios_status_t user_process_reap(uint32_t pid) {
  xaios_user_process_t *process;
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES) {
    return XAIOS_ERR_INVALID;
  }
  process = &g_user_process_table[pid - 1U];
  if (process->pid != pid || process->aspace.l3_count != 0U ||
      (process->state != XAIOS_USER_PROCESS_LOADED &&
       process->state != XAIOS_USER_PROCESS_EXITED &&
       process->state != XAIOS_USER_PROCESS_FAILED)) {
    return XAIOS_ERR_INVALID;
  }
  if (g_current_process == process) {
    return XAIOS_ERR_BUSY;
  }
  user_process_reset_slot(process);
  klog("user: reaped transient process pid=%u\n", pid);
  return XAIOS_OK;
}

xaios_status_t user_process_expect_exit_code(uint32_t pid, int exit_code) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES) return XAIOS_ERR_INVALID;
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  if (process->pid != pid) return XAIOS_ERR_NOT_FOUND;
  process->expected_exit_code = exit_code;
  return XAIOS_OK;
}

xaios_status_t user_process_terminate(uint32_t pid, int exit_code) {
  xaios_user_process_t snapshot;
  xaios_user_process_t *process;
  if (pid <= 2U || pid > XAIOS_MAX_USER_PROCESSES) return XAIOS_ERR_INVALID;
  process = &g_user_process_table[pid - 1U];
  if (process->pid != pid || process == user_current_process())
    return XAIOS_ERR_BUSY;
  if (process->state != XAIOS_USER_PROCESS_LOADED &&
      process->state != XAIOS_USER_PROCESS_RUNNABLE &&
      process->state != XAIOS_USER_PROCESS_WAITING)
    return XAIOS_ERR_BUSY;
  copy_process(&snapshot, process);
  if (process->state == XAIOS_USER_PROCESS_RUNNABLE ||
      process->state == XAIOS_USER_PROCESS_WAITING)
    user_process_transition(process, XAIOS_USER_PROCESS_FAILED, exit_code);
  user_process_reclaim_address_space(&snapshot);
  return user_process_reap(pid);
}

void user_switch_address_space(uint32_t pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES) {
    vmm_switch_user_aspace(0, 0);
    return;
  }
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  if (process->aspace.l3_count > 0) {
    vmm_switch_user_aspace(process->aspace.l3_phys, process->aspace.l3_count);
  }
}

xaios_status_t user_process_run_transient_args(
    const xaios_initramfs_file_t *file, uint64_t capability_mask,
    uint32_t argc, const char *const argv[], int *exit_code) {
  const xaios_user_process_t *parent = user_current_process();
  xaios_user_process_t child;
  uint32_t child_pid = 0U;
  uint32_t parent_pid;
  uint32_t cpu_id;
  uint32_t owns_transient_lock = 0U;
  xaios_status_t status = XAIOS_ERR_NO_MEMORY;

  if (file == 0 || exit_code == 0 || parent == 0 || parent->pid == 0U ||
      argc == 0U || argv == 0) {
    return XAIOS_ERR_INVALID;
  }
  parent_pid = parent->pid;
  cpu_id = smp_cpu_id();
  if (__sync_lock_test_and_set(&g_transient_process_busy, 1U) == 0U) {
    g_transient_process_owner_cpu = cpu_id;
    g_transient_process_depth = 1U;
    owns_transient_lock = 1U;
  } else if (g_transient_process_owner_cpu == cpu_id &&
             g_transient_process_depth < XAIOS_MAX_USER_PROCESSES) {
    ++g_transient_process_depth;
  } else {
    return XAIOS_ERR_BUSY;
  }
  for (uint32_t pid = XAIOS_TRANSIENT_PID_FIRST;
       pid <= XAIOS_MAX_USER_PROCESSES; ++pid) {
    if (g_user_process_table[pid - 1U].state == XAIOS_USER_PROCESS_EMPTY) {
      child_pid = pid;
      break;
    }
  }
  if (child_pid == 0U) {
    goto out;
  }

  status = user_load_process(file, child_pid, capability_mask, &child);
  if (status != XAIOS_OK) {
    user_switch_address_space(parent_pid);
    goto out;
  }
  status = user_process_set_arguments(&child, argc, argv);
  if (status != XAIOS_OK) {
    user_process_reclaim_address_space(&child);
    user_switch_address_space(parent_pid);
    (void)user_process_reap(child_pid);
    goto out;
  }
  status = user_process_make_runnable(child_pid, parent_pid);
  if (status != XAIOS_OK) {
    user_process_reclaim_address_space(&child);
    user_switch_address_space(parent_pid);
    (void)user_process_reap(child_pid);
    goto out;
  }
  kassert(user_process_snapshot(child_pid, &child) == XAIOS_OK);

  user_process_runtime_stop(parent_pid, cpu_id, timer_now_ns());
  *exit_code = user_process_run(&child);

  user_process_reclaim_address_space(&child);
  kassert(user_bind_current_process(parent_pid) == XAIOS_OK);
  user_switch_address_space(parent_pid);
  user_process_runtime_start(parent_pid, cpu_id, timer_now_ns());

  kassert(user_process_reap(child_pid) == XAIOS_OK);
  status = XAIOS_OK;

out:
  kassert(g_transient_process_owner_cpu == cpu_id &&
          g_transient_process_depth != 0U);
  --g_transient_process_depth;
  if (owns_transient_lock != 0U) {
    kassert(g_transient_process_depth == 0U);
    g_transient_process_owner_cpu = UINT32_MAX;
    __sync_lock_release(&g_transient_process_busy);
  }
  return status;
}

xaios_status_t user_process_run_transient(
    const xaios_initramfs_file_t *file, uint64_t capability_mask,
    int *exit_code) {
  const char *argv[1];
  if (file == 0) {
    return XAIOS_ERR_INVALID;
  }
  argv[0] = file->path;
  return user_process_run_transient_args(file, capability_mask, 1U, argv,
                                         exit_code);
}
