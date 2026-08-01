#include <xaios/assert.h>
#include <xaios/context.h>
#include <xaios/elf_loader.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/vmm.h>

#define PAGE_SIZE UINT64_C(4096)

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static xaios_user_process_t g_process_table[XAIOS_MAX_USER_PROCESSES];
static xaios_user_process_t *g_current_process;

typedef struct xaios_cpu_usage_record {
  uint32_t cpu_id;
  uint32_t active_pid;
  uint32_t sequence;
  uint32_t reserved;
  uint64_t busy_ns;
  uint64_t active_since_ns;
} xaios_cpu_usage_record_t;

static xaios_cpu_usage_record_t *g_cpu_usage;
static uint32_t g_cpu_usage_count;
static uint64_t g_cpu_usage_started_ns;
static uint64_t g_process_transition_count;
static uint64_t g_process_loaded_count;
static uint64_t g_process_runnable_count;
static uint64_t g_process_running_count;
static uint64_t g_process_waiting_count;
static uint64_t g_process_exited_count;
static uint64_t g_process_failed_count;
static uint64_t g_process_reclaim_count;
static uint64_t g_process_scheduled_count;
static uint64_t g_process_wait_count;
static uint64_t g_process_wake_count;

extern uint64_t aarch64_enter_user(uint64_t entry, uint64_t stack);

static void copy_process(xaios_user_process_t *dst,
                         const xaios_user_process_t *src) {
  dst->pid = src->pid;
  dst->parent_pid = src->parent_pid;
  dst->name = src->name;
  dst->state = src->state;
  dst->exit_code = src->exit_code;
  dst->capability_mask = src->capability_mask;
  dst->syscall_count = src->syscall_count;
  dst->rejected_syscall_count = src->rejected_syscall_count;
  dst->entry = src->entry;
  dst->stack_top = src->stack_top;
  dst->stack_guard_low = src->stack_guard_low;
  dst->stack_guard_high = src->stack_guard_high;
  dst->mapped_low = src->mapped_low;
  dst->mapped_high = src->mapped_high;
  dst->scheduler_ticks = src->scheduler_ticks;
  dst->started_ns = src->started_ns;
  dst->runtime_ns = src->runtime_ns;
  dst->running_since_ns = src->running_since_ns;
  dst->resident_pages = src->resident_pages;
  dst->running_cpu_id = src->running_cpu_id;
  dst->runtime_sequence = src->runtime_sequence;
  bytes_copy(&dst->aspace, &src->aspace, sizeof(xaios_process_aspace_t));
}

static const char *process_state_name(xaios_user_process_state_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_EMPTY:
    return "empty";
  case XAIOS_USER_PROCESS_LOADED:
    return "loaded";
  case XAIOS_USER_PROCESS_RUNNABLE:
    return "runnable";
  case XAIOS_USER_PROCESS_RUNNING:
    return "running";
  case XAIOS_USER_PROCESS_WAITING:
    return "waiting";
  case XAIOS_USER_PROCESS_EXITED:
    return "exited";
  case XAIOS_USER_PROCESS_FAILED:
    return "failed";
  default:
    return "unknown";
  }
}

static void reset_process_slot(xaios_user_process_t *process) {
  process->pid = 0;
  process->parent_pid = 0;
  process->name = 0;
  process->state = XAIOS_USER_PROCESS_EMPTY;
  process->exit_code = 0;
  process->capability_mask = 0;
  process->syscall_count = 0;
  process->rejected_syscall_count = 0;
  process->entry = 0;
  process->stack_top = 0;
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

static xaios_cpu_usage_record_t *find_cpu_usage(uint32_t cpu_id) {
  uint32_t low = 0;
  uint32_t high = g_cpu_usage_count;
  while (low < high) {
    uint32_t middle = low + ((high - low) / 2U);
    uint32_t found = g_cpu_usage[middle].cpu_id;
    if (found == cpu_id) {
      return &g_cpu_usage[middle];
    }
    if (found < cpu_id) {
      low = middle + 1U;
    } else {
      high = middle;
    }
  }
  return 0;
}

static void process_runtime_write_begin(xaios_user_process_t *process) {
  __sync_fetch_and_add(&process->runtime_sequence, 1U);
  __sync_synchronize();
}

static void process_runtime_write_end(xaios_user_process_t *process) {
  __sync_synchronize();
  __sync_fetch_and_add(&process->runtime_sequence, 1U);
}

static void cpu_usage_write_begin(xaios_cpu_usage_record_t *usage) {
  __sync_fetch_and_add(&usage->sequence, 1U);
  __sync_synchronize();
}

static void cpu_usage_write_end(xaios_cpu_usage_record_t *usage) {
  __sync_synchronize();
  __sync_fetch_and_add(&usage->sequence, 1U);
}

static uint64_t process_runtime_read(const xaios_user_process_t *process,
                                     uint64_t now_ns) {
  uint64_t runtime;
  uint64_t running_since;
  uint32_t before;
  uint32_t after;
  do {
    before = __atomic_load_n(&process->runtime_sequence, __ATOMIC_ACQUIRE);
    if ((before & 1U) != 0U) {
      continue;
    }
    runtime = process->runtime_ns;
    running_since = process->running_since_ns;
    after = __atomic_load_n(&process->runtime_sequence, __ATOMIC_ACQUIRE);
  } while (before != after || (after & 1U) != 0U);
  if (running_since != 0U && now_ns > running_since) {
    runtime += now_ns - running_since;
  }
  return runtime;
}

static uint64_t cpu_usage_read(const xaios_cpu_usage_record_t *usage,
                               uint64_t now_ns, uint32_t *active_pid) {
  uint64_t busy;
  uint64_t active_since;
  uint32_t active;
  uint32_t before;
  uint32_t after;
  do {
    before = __atomic_load_n(&usage->sequence, __ATOMIC_ACQUIRE);
    if ((before & 1U) != 0U) {
      continue;
    }
    busy = usage->busy_ns;
    active_since = usage->active_since_ns;
    active = usage->active_pid;
    after = __atomic_load_n(&usage->sequence, __ATOMIC_ACQUIRE);
  } while (before != after || (after & 1U) != 0U);
  if (active_since != 0U && now_ns > active_since) {
    busy += now_ns - active_since;
  }
  if (active_pid != 0) {
    *active_pid = active;
  }
  return busy;
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

static void transition_process(xaios_user_process_t *process,
                               xaios_user_process_state_t state,
                               int exit_code) {
  kassert(process != 0);
  if (process->state == state && process->exit_code == exit_code) {
    return;
  }
  kassert(validate_process_transition(process->state, state) == XAIOS_OK);

  process->state = state;
  process->exit_code = exit_code;
  ++g_process_transition_count;

  switch (state) {
  case XAIOS_USER_PROCESS_LOADED:
    ++g_process_loaded_count;
    break;
  case XAIOS_USER_PROCESS_RUNNABLE:
    ++g_process_runnable_count;
    break;
  case XAIOS_USER_PROCESS_RUNNING:
    ++g_process_running_count;
    break;
  case XAIOS_USER_PROCESS_WAITING:
    ++g_process_waiting_count;
    break;
  case XAIOS_USER_PROCESS_EXITED:
    ++g_process_exited_count;
    break;
  case XAIOS_USER_PROCESS_FAILED:
    ++g_process_failed_count;
    break;
  default:
    break;
  }

  klog("user: process pid=%u name=%s state=%s exit_code=%u transitions=%lu\n",
       process->pid, process->name != 0 ? process->name : "(none)",
       process_state_name(state), (unsigned)exit_code,
       g_process_transition_count);
}

void user_process_table_init(void) {
  for (uint32_t i = 0; i < XAIOS_MAX_USER_PROCESSES; ++i) {
    reset_process_slot(&g_process_table[i]);
  }
  g_current_process = 0;
  g_process_transition_count = 0;
  g_process_loaded_count = 0;
  g_process_runnable_count = 0;
  g_process_running_count = 0;
  g_process_waiting_count = 0;
  g_process_exited_count = 0;
  g_process_failed_count = 0;
  g_process_reclaim_count = 0;
  g_process_scheduled_count = 0;
  g_process_wait_count = 0;
  g_process_wake_count = 0;
  g_cpu_usage_count = smp_online_count();
  g_cpu_usage = (xaios_cpu_usage_record_t *)kheap_calloc(
      (uint64_t)g_cpu_usage_count * sizeof(xaios_cpu_usage_record_t), 64U);
  kassert(g_cpu_usage_count == 0U || g_cpu_usage != 0);
  for (uint32_t ordinal = 0; ordinal < g_cpu_usage_count; ++ordinal) {
    uint32_t cpu_id = 0;
    kassert(smp_cpu_id_at(ordinal, &cpu_id) == XAIOS_OK);
    g_cpu_usage[ordinal].cpu_id = cpu_id;
  }
  g_cpu_usage_started_ns = timer_now_ns();
  klog("user: process table initialized slots=%u cpu_usage_records=%u\n",
       XAIOS_MAX_USER_PROCESSES, g_cpu_usage_count);
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

const xaios_user_process_t *user_current_process(void) {
  return g_current_process;
}

xaios_status_t user_process_has_capability(uint64_t capability) {
  if (g_current_process == 0 ||
      (g_current_process->capability_mask & capability) != capability) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

void user_process_note_syscall(uint32_t rejected) {
  if (g_current_process != 0) {
    ++g_current_process->syscall_count;
    if (rejected != 0) {
      ++g_current_process->rejected_syscall_count;
    }
  }
}

uint64_t user_process_note_exit(int exit_code) {
  if (g_current_process != 0) {
    user_process_runtime_stop(g_current_process->pid, smp_cpu_id(),
                              timer_now_ns());
    transition_process(g_current_process,
                       exit_code == 0 ? XAIOS_USER_PROCESS_EXITED
                                      : XAIOS_USER_PROCESS_FAILED,
                       exit_code);
  }
  return XAIOS_USER_EXIT_RETURN_MAGIC | ((uint64_t)(uint32_t)exit_code);
}

void user_process_runtime_start(uint32_t pid, uint32_t cpu_id,
                                uint64_t now_ns) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES || now_ns == 0U) {
    return;
  }
  xaios_user_process_t *process = &g_process_table[pid - 1U];
  xaios_cpu_usage_record_t *usage = find_cpu_usage(cpu_id);
  if (process->pid != pid || usage == 0) {
    return;
  }

  process_runtime_write_begin(process);
  if (process->running_since_ns == 0U) {
    process->running_since_ns = now_ns;
    process->running_cpu_id = cpu_id;
  }
  process_runtime_write_end(process);

  cpu_usage_write_begin(usage);
  if (usage->active_pid == 0U) {
    usage->active_pid = pid;
    usage->active_since_ns = now_ns;
  }
  cpu_usage_write_end(usage);
}

void user_process_runtime_stop(uint32_t pid, uint32_t cpu_id,
                               uint64_t now_ns) {
  if (pid == 0U || pid > XAIOS_MAX_USER_PROCESSES || now_ns == 0U) {
    return;
  }
  xaios_user_process_t *process = &g_process_table[pid - 1U];
  xaios_cpu_usage_record_t *usage = find_cpu_usage(cpu_id);
  if (process->pid != pid || usage == 0) {
    return;
  }

  process_runtime_write_begin(process);
  if (process->running_since_ns != 0U && now_ns > process->running_since_ns) {
    process->runtime_ns += now_ns - process->running_since_ns;
  }
  process->running_since_ns = 0U;
  process->running_cpu_id = cpu_id;
  process_runtime_write_end(process);

  cpu_usage_write_begin(usage);
  if (usage->active_pid == pid) {
    if (usage->active_since_ns != 0U && now_ns > usage->active_since_ns) {
      usage->busy_ns += now_ns - usage->active_since_ns;
    }
    usage->active_pid = 0U;
    usage->active_since_ns = 0U;
  }
  cpu_usage_write_end(usage);
}

uint32_t user_cpu_usage_count(void) {
  return g_cpu_usage_count;
}

xaios_status_t user_cpu_usage_snapshot(
    uint32_t ordinal, uint64_t now_ns,
    xaios_cpu_usage_snapshot_t *snapshot) {
  if (snapshot == 0 || ordinal >= g_cpu_usage_count || now_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }
  const xaios_cpu_usage_record_t *usage = &g_cpu_usage[ordinal];
  snapshot->cpu_id = usage->cpu_id;
  snapshot->busy_ns = cpu_usage_read(usage, now_ns, &snapshot->active_pid);
  snapshot->elapsed_ns = now_ns > g_cpu_usage_started_ns
                             ? now_ns - g_cpu_usage_started_ns
                             : 0U;
  return XAIOS_OK;
}

uint64_t user_cpu_busy_total(uint64_t now_ns) {
  uint64_t total = 0U;
  for (uint32_t ordinal = 0; ordinal < g_cpu_usage_count; ++ordinal) {
    uint64_t busy = cpu_usage_read(&g_cpu_usage[ordinal], now_ns, 0);
    if (UINT64_MAX - total < busy) {
      return UINT64_MAX;
    }
    total += busy;
  }
  return total;
}

xaios_status_t user_load_process(const xaios_initramfs_file_t *file,
                                uint32_t pid, uint64_t capability_mask,
                                xaios_user_process_t *process) {
  if (process == 0 || pid == 0 || pid > XAIOS_MAX_USER_PROCESSES ||
      file == 0 || file->base == 0 || file->executable == 0) {
    return XAIOS_ERR_INVALID;
  }

  reset_process_slot(process);
  process->pid = pid;
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
  process->syscall_count = 0;
  process->rejected_syscall_count = 0;
  process->started_ns = timer_now_ns();

  /* Track mappings from ELF segments */
  for (uint32_t i = 0; i < process->aspace.page_count; ++i) {
    track_process_mapping(process, process->aspace.page_va[i],
                          process->aspace.page_va[i] + PAGE_SIZE);
  }

  /* Map stack */
  uint64_t guard_low = XAIOS_USER_STACK_TOP - (3U * PAGE_SIZE);
  uint64_t stack = XAIOS_USER_STACK_TOP - (2U * PAGE_SIZE);
  uint64_t guard_high = XAIOS_USER_STACK_TOP - PAGE_SIZE;
  if (elf_loader_map_stack(&process->aspace, stack, guard_low,
                           guard_high) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  process->stack_top = stack + PAGE_SIZE;
  process->stack_guard_low = guard_low;
  process->stack_guard_high = guard_high;
  track_process_mapping(process, stack, stack + PAGE_SIZE);
  process->resident_pages = process->aspace.page_count;

  xaios_user_process_t *slot = &g_process_table[pid - 1U];
  copy_process(slot, process);
  slot->state = XAIOS_USER_PROCESS_EMPTY;
  transition_process(slot, XAIOS_USER_PROCESS_LOADED, 0);
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

xaios_status_t user_process_snapshot_at(uint32_t pid, uint64_t now_ns,
                                        xaios_user_process_t *process) {
  if (process == 0 || pid == 0 || pid > XAIOS_MAX_USER_PROCESSES ||
      now_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }

  const xaios_user_process_t *slot = &g_process_table[pid - 1U];
  if (slot->pid != pid || slot->state == XAIOS_USER_PROCESS_EMPTY) {
    return XAIOS_ERR_INVALID;
  }

  copy_process(process, slot);
  process->runtime_ns = process_runtime_read(slot, now_ns);
  return XAIOS_OK;
}

xaios_status_t user_process_snapshot(uint32_t pid,
                                     xaios_user_process_t *process) {
  return user_process_snapshot_at(pid, timer_now_ns(), process);
}

xaios_status_t user_process_make_runnable(uint32_t pid, uint32_t parent_pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES || parent_pid == pid) {
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *process = &g_process_table[pid - 1U];
  if (process->pid != pid) {
    return XAIOS_ERR_INVALID;
  }

  process->parent_pid = parent_pid;
  transition_process(process, XAIOS_USER_PROCESS_RUNNABLE, 0);
  klog("scheduler: process pid=%u parent=%u runnable name=%s\n", process->pid,
       process->parent_pid, process->name != 0 ? process->name : "(none)");
  return XAIOS_OK;
}

xaios_status_t user_process_wait(uint32_t pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES) {
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *process = &g_process_table[pid - 1U];
  if (process->pid != pid) {
    return XAIOS_ERR_INVALID;
  }

  transition_process(process, XAIOS_USER_PROCESS_WAITING, process->exit_code);
  ++g_process_wait_count;
  klog("scheduler: process pid=%u waiting waits=%lu\n", pid,
       g_process_wait_count);
  return XAIOS_OK;
}

xaios_status_t user_process_wake(uint32_t pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES) {
    return XAIOS_ERR_INVALID;
  }

  xaios_user_process_t *process = &g_process_table[pid - 1U];
  if (process->pid != pid) {
    return XAIOS_ERR_INVALID;
  }

  transition_process(process, XAIOS_USER_PROCESS_RUNNABLE, process->exit_code);
  ++g_process_wake_count;
  klog("scheduler: process pid=%u woken wakes=%lu\n", pid,
       g_process_wake_count);
  return XAIOS_OK;
}

int user_process_run(const xaios_user_process_t *process) {
  kassert(process != 0);
  kassert(process->pid != 0 && process->pid <= XAIOS_MAX_USER_PROCESSES);
  g_current_process = &g_process_table[process->pid - 1U];
  if (g_current_process->pid != process->pid ||
      g_current_process->state == XAIOS_USER_PROCESS_EMPTY) {
    copy_process(g_current_process, process);
  }
  uint64_t entry = g_current_process->entry;
  uint64_t stack = g_current_process->stack_top;
  transition_process(g_current_process, XAIOS_USER_PROCESS_RUNNING, 0);
  ++g_current_process->scheduler_ticks;
  ++g_process_scheduled_count;
  user_process_runtime_start(g_current_process->pid, smp_cpu_id(),
                             timer_now_ns());

  klog("scheduler: dispatch pid=%u parent=%u name=%s ticks=%lu scheduled=%lu\n",
       g_current_process->pid, g_current_process->parent_pid,
       g_current_process->name != 0 ? g_current_process->name : "(none)",
       g_current_process->scheduler_ticks, g_process_scheduled_count);

  klog("user: entering EL0 %s pid=%u entry=0x%lx stack=0x%lx\n",
       g_current_process->name, g_current_process->pid, entry, stack);

  uint64_t encoded = aarch64_enter_user(entry, stack);
  kassert((encoded & XAIOS_USER_EXIT_RETURN_MASK) ==
          XAIOS_USER_EXIT_RETURN_MAGIC);
  int exit_code = (int)(uint32_t)encoded;

  klog("user: kernel resumed after EL0 pid=%u state=%s exit_code=%u transitions=%lu\n",
       g_current_process->pid, process_state_name(g_current_process->state),
       (unsigned)exit_code, g_process_transition_count);
  return exit_code;
}

int user_process_run_concurrent(const xaios_user_process_t *process) {
  kassert(process != 0);
  kassert(process->pid != 0 && process->pid <= XAIOS_MAX_USER_PROCESSES);
  g_current_process = &g_process_table[process->pid - 1U];
  if (g_current_process->pid != process->pid ||
      g_current_process->state == XAIOS_USER_PROCESS_EMPTY) {
    copy_process(g_current_process, process);
  }
  uint64_t entry = g_current_process->entry;
  uint64_t stack = g_current_process->stack_top;
  transition_process(g_current_process, XAIOS_USER_PROCESS_RUNNING, 0);
  ++g_process_scheduled_count;
  user_process_runtime_start(g_current_process->pid, smp_cpu_id(),
                             timer_now_ns());

  /* Register with preemptive scheduler */
  kassert(scheduler_register(g_current_process->pid) == XAIOS_OK);
  kassert(scheduler_set_runnable(g_current_process->pid) == XAIOS_OK);

  /* Initialize context frame for first entry to user mode */
  xaios_context_frame_t *frame = scheduler_task_frame(g_current_process->pid);
  kassert(frame != 0);
  for (uint32_t i = 0; i < XAIOS_CONTEXT_FRAME_REGS; ++i) {
    ((uint64_t *)frame)[i] = 0;
  }
  frame->elr_el1 = entry;
  frame->sp_el0 = stack;
  frame->spsr_el1 = 0; /* EL0, interrupts enabled */

  klog("scheduler: concurrent dispatch pid=%u parent=%u name=%s entry=0x%lx stack=0x%lx\n",
       g_current_process->pid, g_current_process->parent_pid,
       g_current_process->name != 0 ? g_current_process->name : "(none)",
       entry, stack);

  /* Enter user mode for initial execution */
  uint64_t encoded = aarch64_enter_user(entry, stack);
  kassert((encoded & XAIOS_USER_EXIT_RETURN_MASK) ==
          XAIOS_USER_EXIT_RETURN_MAGIC);
  int exit_code = (int)(uint32_t)encoded;

  /* Unregister from scheduler */
  scheduler_unregister(g_current_process->pid);

  klog("user: concurrent exited pid=%u exit_code=%u\n",
       g_current_process->pid, (unsigned)exit_code);
  return exit_code;
}

void user_process_reclaim_address_space(const xaios_user_process_t *process) {
  if (process == 0) {
    return;
  }

  /* Use ELF loader reclaim for processes with per-process address spaces */
  if (process->aspace.l3_count > 0) {
    elf_loader_reclaim((xaios_process_aspace_t *)&process->aspace,
                       process->mapped_low, process->mapped_high);
    if (process->pid != 0U && process->pid <= XAIOS_MAX_USER_PROCESSES &&
        g_process_table[process->pid - 1U].pid == process->pid) {
      g_process_table[process->pid - 1U].resident_pages = 0U;
    }
    ++g_process_reclaim_count;
    klog("user: reclaimed aspace pid=%u pages=%u\n",
         process->pid, process->aspace.page_count);
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
  ++g_process_reclaim_count;
  klog("user: reclaimed address space pid=%u range=[0x%lx,0x%lx)\n",
       process->pid, process->mapped_low, process->mapped_high);
}

void user_switch_address_space(uint32_t pid) {
  if (pid == 0 || pid > XAIOS_MAX_USER_PROCESSES) {
    vmm_switch_user_aspace(0, 0);
    return;
  }
  xaios_user_process_t *process = &g_process_table[pid - 1U];
  if (process->aspace.l3_count > 0) {
    vmm_switch_user_aspace(process->aspace.l3_phys, process->aspace.l3_count);
  }
}

uint64_t user_process_transition_count(void) {
  return g_process_transition_count;
}

uint64_t user_process_loaded_count(void) {
  return g_process_loaded_count;
}

uint64_t user_process_runnable_count(void) {
  return g_process_runnable_count;
}

uint64_t user_process_running_count(void) {
  return g_process_running_count;
}

uint64_t user_process_waiting_count(void) {
  return g_process_waiting_count;
}

uint64_t user_process_exited_count(void) {
  return g_process_exited_count;
}

uint64_t user_process_failed_count(void) {
  return g_process_failed_count;
}

uint64_t user_process_reclaim_count(void) {
  return g_process_reclaim_count;
}

uint64_t user_process_scheduled_count(void) {
  return g_process_scheduled_count;
}

uint64_t user_process_wait_count(void) {
  return g_process_wait_count;
}

uint64_t user_process_wake_count(void) {
  return g_process_wake_count;
}

uint64_t user_process_active_count(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < XAIOS_MAX_USER_PROCESSES; ++i) {
    xaios_user_process_state_t state = g_process_table[i].state;
    if (state == XAIOS_USER_PROCESS_LOADED ||
        state == XAIOS_USER_PROCESS_RUNNABLE ||
        state == XAIOS_USER_PROCESS_RUNNING ||
        state == XAIOS_USER_PROCESS_WAITING) {
      ++active;
    }
  }
  return active;
}
