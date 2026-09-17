/*
 * User process loading, EL0 argument marshalling and task dispatch.
 *
 * Split out of kernel/user/user.c, which was 1512 lines. The loading, argument
 * and dispatch paths are the ones that touch the EL0 ABI; they hand everything
 * else to the process-table and accounting modules.
 */

#include "user_internal.h"

/* In the port's assembly, and named for the system rather than for the one
   port that had it first -- see kernel/arch/aarch64/entry.S (B-109). */
extern uint64_t xaios_enter_user(uint64_t entry, uint64_t stack,
                                   uint64_t argc, uint64_t argv);

typedef struct xaios_async_process_context {
  xaios_user_process_t process;
  xaios_user_process_async_complete_fn complete;
  void *opaque;
} xaios_async_process_context_t;

#define USER_TASK_STACK_BYTES (16U * 1024U)
/* The pid a dispatching context adopts while it waits. Above the process table
 * on purpose: the scheduler's per-pid runtime accounting is a process table
 * lookup, and a runner is not a process. */
#define USER_TASK_RUNNER_PID_BASE UINT32_C(20000)
#define USER_TASK_WAIT_NS UINT64_C(2000000000)

static uint64_t argument_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) {
    return UINT64_MAX;
  }
  while (text[length] != '\0') {
    if (length == XAIOS_USER_ARG_BYTES_MAX) {
      return UINT64_MAX;
    }
    ++length;
  }
  return length;
}

xaios_status_t user_process_set_arguments(xaios_user_process_t *process,
                                          uint32_t argc,
                                          const char *const argv[]) {
  uint64_t pointers[XAIOS_USER_ARG_MAX + 1U];
  uint64_t cursor;
  uint64_t lower_bound;
  uint64_t string_bytes = 0U;

  if (process == 0 || argc == 0U || argc > XAIOS_USER_ARG_MAX || argv == 0 ||
      process->stack_guard_high == 0U) {
    return XAIOS_ERR_INVALID;
  }
  cursor = process->stack_guard_high;
  lower_bound = process->stack_guard_low + PAGE_SIZE;
  for (uint32_t i = argc; i != 0U; --i) {
    uint64_t length = argument_length(argv[i - 1U]);
    if (length == UINT64_MAX || length + 1U > XAIOS_USER_ARG_BYTES_MAX -
                                                 string_bytes ||
        cursor < lower_bound + length + 1U) {
      return XAIOS_ERR_INVALID;
    }
    cursor -= length + 1U;
    if (elf_loader_write_user(&process->aspace, cursor, argv[i - 1U],
                              length + 1U) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    pointers[i - 1U] = cursor;
    string_bytes += length + 1U;
  }
  pointers[argc] = 0U;

  uint64_t pointer_bytes = ((uint64_t)argc + 1U) * sizeof(uint64_t);
  if (cursor < lower_bound + pointer_bytes + 15U) {
    return XAIOS_ERR_INVALID;
  }
  cursor = (cursor - pointer_bytes) & ~UINT64_C(15);
  if (elf_loader_write_user(&process->aspace, cursor, pointers,
                            pointer_bytes) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  process->stack_top = cursor;
  process->argv_user = cursor;
  process->argc = argc;
  if (process->pid != 0U && process->pid <= XAIOS_MAX_USER_PROCESSES) {
    xaios_user_process_t *slot = &g_user_process_table[process->pid - 1U];
    if (slot->pid == process->pid &&
        slot->state != XAIOS_USER_PROCESS_EMPTY) {
      slot->stack_top = process->stack_top;
      slot->argv_user = process->argv_user;
      slot->argc = process->argc;
    }
  }
  return XAIOS_OK;
}

static void track_process_mapping(xaios_user_process_t *process, uint64_t start,
                                  uint64_t end) {
  if (process->mapped_low == 0 || start < process->mapped_low) {
    process->mapped_low = start;
  }
  if (end > process->mapped_high) {
    process->mapped_high = end;
  }
}

xaios_status_t user_load_process(const xaios_initramfs_file_t *file,
                                uint32_t pid, uint64_t capability_mask,
                                xaios_user_process_t *process) {
  if (process == 0 || pid == 0 || pid > XAIOS_MAX_USER_PROCESSES ||
      file == 0 || file->base == 0 || file->path == 0 ||
      file->executable == 0) {
    return XAIOS_ERR_INVALID;
  }

  user_process_reset_slot(process);
  process->pid = pid;
  process->owner_token = user_process_next_owner_token();
  process->name = file->path;
  process->capability_mask = capability_mask;

  /* Use ELF loader for per-process address space isolation */
  uint64_t entry = 0;
  if (elf_loader_load(file, &process->aspace, &entry) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  process->entry = entry;
  process->state = XAIOS_USER_PROCESS_LOADED;
  process->exit_code = 0;
  process->expected_exit_code = 0;
  process->syscall_count = 0;
  process->rejected_syscall_count = 0;
  process->started_ns = timer_now_ns();

  /* Track mappings from ELF segments */
  for (uint32_t i = 0; i < process->aspace.page_count; ++i) {
    track_process_mapping(process, process->aspace.pages[i].va,
                          process->aspace.pages[i].va + PAGE_SIZE);
  }

  /* Map stack */
  uint64_t guard_high = XAIOS_USER_STACK_TOP - PAGE_SIZE;
  uint64_t stack = guard_high - (USER_STACK_PAGES * PAGE_SIZE);
  uint64_t guard_low = stack - PAGE_SIZE;
  if (elf_loader_map_stack(&process->aspace, stack, guard_low,
                           guard_high) != XAIOS_OK) {
    elf_loader_reclaim(&process->aspace, process->mapped_low,
                       process->mapped_high);
    return XAIOS_ERR_INVALID;
  }
  process->stack_top = guard_high;
  process->stack_guard_low = guard_low;
  process->stack_guard_high = guard_high;
  track_process_mapping(process, stack, guard_high);
  process->resident_pages = process->aspace.page_count;

  const char *default_argv[] = {file->path};
  if (user_process_set_arguments(process, 1U, default_argv) != XAIOS_OK) {
    elf_loader_reclaim(&process->aspace, process->mapped_low,
                       process->mapped_high);
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *slot = &g_user_process_table[pid - 1U];
  copy_process(slot, process);
  slot->state = XAIOS_USER_PROCESS_EMPTY;
  user_process_transition(slot, XAIOS_USER_PROCESS_LOADED, 0);
  copy_process(process, slot);
  klog("user: loaded %s ELF pid=%u caps=0x%lx entry=0x%lx stack=0x%lx aspace_pages=%u\n",
       process->name, process->pid, process->capability_mask, process->entry,
       process->stack_top, process->aspace.page_count);
  return XAIOS_OK;
}

xaios_status_t user_load_init(const xaios_initramfs_file_t *file,
                             xaios_user_process_t *process) {
  return user_load_process(file, 1,
                           XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL,
                           process);
}

int user_process_run(const xaios_user_process_t *process) {
  kassert(process != 0);
  kassert(process->pid != 0 && process->pid <= XAIOS_MAX_USER_PROCESSES);
  g_current_process = &g_user_process_table[process->pid - 1U];
  if (g_current_process->pid != process->pid ||
      g_current_process->state == XAIOS_USER_PROCESS_EMPTY) {
    copy_process(g_current_process, process);
  }
  uint64_t entry = g_current_process->entry;
  uint64_t stack = g_current_process->stack_top;
  user_process_transition(g_current_process, XAIOS_USER_PROCESS_RUNNING, 0);
  ++g_current_process->scheduler_ticks;
  __sync_fetch_and_add(&g_user_process_scheduled_count, 1U);
  user_process_runtime_start(g_current_process->pid, smp_cpu_id(),
                             timer_now_ns());

  klog("scheduler: dispatch pid=%u parent=%u name=%s ticks=%lu scheduled=%lu\n",
       g_current_process->pid, g_current_process->parent_pid,
       g_current_process->name != 0 ? g_current_process->name : "(none)",
       g_current_process->scheduler_ticks, g_user_process_scheduled_count);

  klog("user: entering EL0 %s pid=%u entry=0x%lx stack=0x%lx\n",
       g_current_process->name, g_current_process->pid, entry, stack);

  user_switch_address_space(g_current_process->pid);
  uint64_t encoded = xaios_enter_user(entry, stack, g_current_process->argc,
                                        g_current_process->argv_user);
  kassert((encoded & XAIOS_USER_EXIT_RETURN_MASK) ==
          XAIOS_USER_EXIT_RETURN_MAGIC);
  int exit_code = (int)(uint32_t)encoded;

  klog("user: kernel resumed after EL0 pid=%u state=%s exit_code=%u transitions=%lu\n",
       g_current_process->pid, process_state_name(g_current_process->state),
       (unsigned)exit_code, g_user_process_transition_count);
  return exit_code;
}

/* The kernel continuation of a user task.
 *
 * It runs on the task's own kernel stack, binds and enters the process, and
 * when the process exits it hands the CPU back to the context that dispatched
 * it rather than returning: there is nothing on this stack to return to, and
 * the dispatcher's context is not this task's to unwind. */
static void user_task_kernel_entry(void) {
  uint32_t pid = scheduler_current_pid();
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES) {
    klog("user: task entry pid=%u is outside the process table\n",
         (unsigned)pid);
    scheduler_unregister(pid);
    for (;;) xaios_cpu_relax();
  }
  xaios_user_process_t *process = &g_user_process_table[pid - 1U];
  uint32_t runner_pid = USER_TASK_RUNNER_PID_BASE + pid;

  if (user_bind_current_process(pid) != XAIOS_OK) {
    klog("user: task entry could not bind pid=%u\n", (unsigned)pid);
  }
  user_switch_address_space(pid);
  klog("user: scheduled task entering EL0 pid=%u name=%s entry=0x%lx "
       "stack=0x%lx\n",
       (unsigned)pid, process->name != 0 ? process->name : "(none)",
       (unsigned long)process->entry, (unsigned long)process->stack_top);

  uint64_t encoded = xaios_enter_user(process->entry, process->stack_top,
                                      process->argc, process->argv_user);
  kassert((encoded & XAIOS_USER_EXIT_RETURN_MASK) ==
          XAIOS_USER_EXIT_RETURN_MAGIC);
  int exit_code = (int)(uint32_t)encoded;
  user_process_transition(process, XAIOS_USER_PROCESS_EXITED, exit_code);
  klog("user: scheduled task exited pid=%u exit_code=%d\n", (unsigned)pid,
       exit_code);

  /* Hand the CPU back, in this order: the dispatcher has to be runnable before
     this task stops being, or the tick that follows finds nothing to pick. */
  (void)scheduler_set_runnable(runner_pid);
  (void)scheduler_set_blocked(pid);
  klog("user: scheduled task handed the CPU back pid=%u runner=%u\n",
       (unsigned)pid, (unsigned)runner_pid);
  for (;;) xaios_cpu_relax();
}

int user_process_scheduled_dispatch_supported(void) {
  xaios_context_frame_t probe;
  bytes_zero(&probe, sizeof(probe));
  return xaios_context_frame_kernel_entry(&probe, user_task_kernel_entry,
                                          UINT64_C(0x1000)) != 0;
}

int user_process_run_scheduled(const xaios_user_process_t *process,
                               int dispatcher_blocked,
                               xaios_user_dispatch_result_t *result) {
  if (result != 0) {
    bytes_zero(result, sizeof(*result));
    result->dispatcher_blocked = dispatcher_blocked != 0;
  }
  kassert(process != 0);
  kassert(process->pid != 0 && process->pid <= XAIOS_MAX_USER_PROCESSES);
  uint32_t cpu = smp_cpu_id();
  uint32_t pid = process->pid;
  uint32_t runner_pid = USER_TASK_RUNNER_PID_BASE + pid;

  g_current_process = &g_user_process_table[pid - 1U];
  if (g_current_process->pid != pid ||
      g_current_process->state == XAIOS_USER_PROCESS_EMPTY) {
    copy_process(g_current_process, process);
  }
  user_process_transition(g_current_process, XAIOS_USER_PROCESS_RUNNING, 0);
  __sync_fetch_and_add(&g_user_process_scheduled_count, 1U);
  user_process_runtime_start(pid, cpu, timer_now_ns());

  void *stack = kheap_alloc(USER_TASK_STACK_BYTES, 16U);
  if (stack == 0) {
    klog("user: no kernel stack for scheduled pid=%u; running it on the "
         "caller's stack\n",
         (unsigned)pid);
    int fallback_exit = user_process_run(process);
    if (result != 0) result->exit_code = fallback_exit;
    return fallback_exit;
  }
  uint64_t stack_top =
      ((uint64_t)(uintptr_t)stack + USER_TASK_STACK_BYTES) & ~UINT64_C(0xf);

  /* The process and the dispatching context run at the *same* priority; the
     ordering between them is the run queue's, not the priority's. */
  if (scheduler_register_kernel_task(pid, user_task_kernel_entry, stack_top,
                                     XAIOS_PRIORITY_NORMAL) != XAIOS_OK) {
    kheap_free(stack);
    klog("user: scheduled dispatch unavailable for pid=%u; running it on the "
         "caller's stack\n",
         (unsigned)pid);
    int fallback_exit = user_process_run(process);
    if (result != 0) result->exit_code = fallback_exit;
    return fallback_exit;
  }
  if (scheduler_adopt_this_context(runner_pid, XAIOS_PRIORITY_NORMAL) !=
          XAIOS_OK ||
      scheduler_set_runnable(pid) != XAIOS_OK) {
    scheduler_unregister(pid);
    kheap_free(stack);
    klog("user: could not adopt a dispatcher for pid=%u; running it on the "
         "caller's stack\n",
         (unsigned)pid);
    int fallback_exit = user_process_run(process);
    if (result != 0) result->exit_code = fallback_exit;
    return fallback_exit;
  }

  user_clear_current_process();
  uint64_t switches_before = scheduler_context_switch_count();
  uint64_t wait_start = timer_now_ns();
  klog("user: dispatcher waiting pid=%u runner=%u cpu=%u blocked=%d\n",
       (unsigned)pid, (unsigned)runner_pid, (unsigned)cpu,
       dispatcher_blocked != 0 ? 1 : 0);

  if (dispatcher_blocked != 0) {
    /* The control, kept because an earlier measurement misread it as a
       property of EL0. With the dispatcher blocked the process is the only
       runnable task, so the tick puts it back, `rq_pick_best` picks it again,
       finds `next_pid == current_pid` and returns without a switch -- and the
       count stops at the dispatch and the hand-back. That is a correct
       scheduler with nothing to switch to, not an unpreemptible EL0
       context. */
    (void)scheduler_set_blocked(runner_pid);
  } else {
    /* Queue order, not priority: both are RUNNABLE at the same priority and
       the process is placed *ahead* of the dispatcher in the run queue, so the
       two alternate. `rq_pick_best` takes the highest priority and then the
       first entry, and the tick puts the task it is running back into the
       queue before it chooses -- so with the process ahead, the pick hands the
       process the CPU, and on the next tick the process is what is left
       waiting while the dispatcher is chosen, and so on for as long as the
       process runs. Blocking and re-adding the runner is how it moves to the
       back of the queue; its state does not stay blocked. Making the process
       the only runnable task instead (the branch above) is what stops that
       alternation, which is why the two runs are the measurement and its
       control. */
    (void)scheduler_set_blocked(runner_pid);
    (void)scheduler_set_runnable(runner_pid);
  }

  int exit_code = 0;
  uint64_t deadline = wait_start + USER_TASK_WAIT_NS;
  for (;;) {
    xaios_user_process_t snapshot;
    if (user_process_snapshot(pid, &snapshot) != XAIOS_OK) break;
    if (snapshot.state == XAIOS_USER_PROCESS_EXITED ||
        snapshot.state == XAIOS_USER_PROCESS_FAILED) {
      exit_code = snapshot.exit_code;
      break;
    }
    if (timer_now_ns() >= deadline) {
      klog("user: scheduled pid=%u did not finish within %lu ns\n",
           (unsigned)pid, (unsigned long)USER_TASK_WAIT_NS);
      exit_code = -1;
      break;
    }
    /* Either design brings this context back through the timer: blocked, a
       tick that finds the current task not runnable reschedules and picks the
       process -- which is the only runnable task -- and the process's own
       expiry brings the dispatcher back; runnable, the two alternate on their
       slices. Neither path sleeps, so this loop is where the dispatcher spends
       the wait either way. */
    xaios_cpu_relax();
  }

  uint64_t switches = scheduler_context_switch_count() - switches_before;
  scheduler_unregister(pid);
  scheduler_unregister(runner_pid);
  kheap_free(stack);
  user_clear_current_process();
  user_process_runtime_stop(pid, cpu, timer_now_ns());
  klog("user: scheduled dispatch pid=%u switches=%lu exit_code=%d "
       "waited_ns=%lu blocked=%d\n",
       (unsigned)pid, (unsigned long)switches, exit_code,
       (unsigned long)(timer_now_ns() - wait_start),
       dispatcher_blocked != 0 ? 1 : 0);
  if (result != 0) {
    result->as_task = 1;
    result->switches = switches;
    result->exit_code = exit_code;
  }
  return exit_code;
}

static uint64_t async_process_worker(void *opaque) {
  xaios_async_process_context_t *context =
      (xaios_async_process_context_t *)opaque;
  if (context == 0) return UINT64_MAX;
  uint32_t pid = context->process.pid;
  int exit_code = user_process_run(&context->process);
  user_process_reclaim_address_space(&context->process);
  user_clear_current_process();
  vmm_activate_kernel();
  if (context->complete != 0) {
    context->complete(pid, exit_code, context->opaque);
  }
  (void)user_process_reap(pid);
  kheap_free(context);
  return (uint64_t)(uint32_t)exit_code;
}

xaios_status_t user_process_start_async(
    const xaios_initramfs_file_t *file, uint64_t capability_mask,
    uint32_t argc, const char *const argv[], uint32_t parent_pid,
    xaios_user_process_async_ready_fn ready,
    xaios_user_process_async_complete_fn complete, void *opaque,
    uint32_t *child_pid, uint64_t *thread_id) {
  if (file == 0 || argc == 0U || argv == 0 || parent_pid == 0U ||
      child_pid == 0 || thread_id == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t pid = 0U;
  for (uint32_t candidate = XAIOS_TRANSIENT_PID_FIRST;
       candidate <= XAIOS_MAX_USER_PROCESSES; ++candidate) {
    if (g_user_process_table[candidate - 1U].state ==
        XAIOS_USER_PROCESS_EMPTY) {
      pid = candidate;
      break;
    }
  }
  if (pid == 0U) return XAIOS_ERR_BUSY;

  xaios_async_process_context_t *context =
      (xaios_async_process_context_t *)kheap_calloc(sizeof(*context), 16U);
  if (context == 0) return XAIOS_ERR_NO_MEMORY;
  xaios_status_t status = user_load_process(file, pid, capability_mask,
                                            &context->process);
  if (status == XAIOS_OK) {
    status = user_process_set_arguments(&context->process, argc, argv);
  }
  if (status == XAIOS_OK) {
    status = user_process_make_runnable(pid, parent_pid);
  }
  if (status != XAIOS_OK) {
    user_process_reclaim_address_space(&context->process);
    (void)user_process_reap(pid);
    kheap_free(context);
    return status;
  }
  context->complete = complete;
  context->opaque = opaque;
  if (ready != 0 && ready(pid, opaque) != XAIOS_OK) {
    user_process_reclaim_address_space(&context->process);
    (void)user_process_reap(pid);
    kheap_free(context);
    return XAIOS_ERR_INVALID;
  }
  status = xaios_thread_create_detached_off_current_cpu(async_process_worker,
                                                         context);
  if (status != XAIOS_OK) {
    user_process_reclaim_address_space(&context->process);
    (void)user_process_reap(pid);
    kheap_free(context);
    return status;
  }
  *thread_id = 0U;
  *child_pid = pid;
  klog("user: async child pid=%u parent=%u thread=%lu name=%s\n", pid,
       parent_pid, *thread_id, context->process.name);
  return XAIOS_OK;
}
