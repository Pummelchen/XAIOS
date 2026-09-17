/*
 * The AI cell boot self-test, moved out of ai_cell.c. It drives the public
 * ai_cell.h lifecycle exactly as before and builds its fixtures through the
 * descriptor ABI in ai_cell_descriptor.c (ai_cell_fill_descriptor,
 * ai_cell_copy_descriptor, ai_cell_descriptor_checksum). Every assertion,
 * expected value and log line is the one the unsplit file contained.
 */

#include "ai_cell_internal.h"

#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/klog.h>
#include <xaios/smp.h>

static int str_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint32_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

/* A core this machine actually has, rather than the one numbered 1.
 *
 * The mask maps bit N to CPU id N, and this test used 0x2 -- CPU 1 -- which
 * is right on a machine whose ids run 0,1,2,3 and wrong on one where a
 * middle id is missing. That is not hypothetical: booting RISC-V through
 * UEFI can leave a hart already started by firmware, which the kernel cannot
 * take over, so the machine comes up with ids 0,2,3 and every lease of "core
 * 1" fails. The boot then died on an assertion in this self-test, which is a
 * test asserting an identity firmware never promised. */
static uint32_t self_test_worker_mask(uint32_t wanted) {
  uint32_t current = smp_cpu_id();
  uint32_t online = smp_online_count();
  uint32_t seen = 0U;
  for (uint32_t ordinal = 0U; ordinal < online; ++ordinal) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at(ordinal, &cpu_id) != XAIOS_OK) continue;
    if (cpu_id == current || cpu_id == 0U || cpu_id >= 32U) continue;
    if (seen++ != wanted) continue;
    return UINT32_C(1) << cpu_id;
  }
  return 0U;
}

void ai_cell_self_test(void) {
  ai_cell_runtime_init();
  uint32_t core_mask = self_test_worker_mask(0U);
  uint32_t second_mask = self_test_worker_mask(1U);
  if (smp_online_count() < 2U || core_mask == 0U) {
    klog("ai-cell: lifecycle self-test skipped (no leasable worker core)\n");
    return;
  }
  xaios_ai_cell_manifest_t invalid;
  invalid.name = "invalid";
  invalid.core_mask = 0;
  invalid.model_arena_id = 2;
  invalid.kv_cache_bytes = 4096;
  invalid.source_index_bytes = 4096;
  invalid.nic_queue_id = 1;
  invalid.git_workspace_id = 1;
  kassert(ai_cell_create(0, &invalid) == XAIOS_ERR_INVALID);

  invalid.core_mask = 0x8;
  invalid.model_arena_id = 99;
  invalid.git_workspace_id = 1;
  kassert(ai_cell_create(3, &invalid) == XAIOS_ERR_INVALID);

  invalid.model_arena_id = 2;
  invalid.git_workspace_id = 99;
  kassert(ai_cell_create(3, &invalid) == XAIOS_ERR_INVALID);

  xaios_ai_cell_descriptor_v1_t descriptor;
  xaios_ai_cell_descriptor_v1_t bad_descriptor;
  ai_cell_fill_descriptor(&descriptor, 0, "codex-app-agent", core_mask, 2, 1, 1,
                          64 * 1024, 128 * 1024);

  ai_cell_copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.checksum ^= UINT64_C(1);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  ai_cell_copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.version = 99;
  bad_descriptor.checksum = ai_cell_descriptor_checksum(&bad_descriptor);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  ai_cell_copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.flags &= ~XAIOS_AI_CELL_DESCRIPTOR_FLAG_PRIVATE_KV;
  bad_descriptor.checksum = ai_cell_descriptor_checksum(&bad_descriptor);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  ai_cell_copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.cell_id = 3;
  bad_descriptor.model_arena_id = 99;
  bad_descriptor.checksum = ai_cell_descriptor_checksum(&bad_descriptor);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  kassert(ai_cell_create_from_descriptor(&descriptor) == XAIOS_OK);
  kassert(ai_cell_prepare(0) == XAIOS_OK);
  kassert(ai_cell_start(0) == XAIOS_OK);
  char output[32];
  uint64_t out = 0;
  const uint8_t piece[] = {'A', 'B', 'C', 'D'};
  kassert(cpu_ai_runtime_fixture_decode_piece(0, piece, sizeof(piece), output,
                                             sizeof(output), &out) ==
          XAIOS_OK);
  kassert(cpu_ai_runtime_decode_count(0) == 1);
  kassert(output[0] == '1');
  kassert(output[1] == 'B');
  kassert(output[2] == '1');
  kassert(output[3] == 'F');
  kassert(output[4] == '2');
  kassert(output[5] == '3');
  kassert(output[6] == '2');
  kassert(output[7] == '7');
  kassert(output[8] == '\0');

  xaios_ai_cell_descriptor_v1_t conflict;
  ai_cell_fill_descriptor(&conflict, 1, "core-conflict-agent", core_mask, 2, 2, 2,
                          64 * 1024, 128 * 1024);
  kassert(ai_cell_create_from_descriptor(&conflict) == XAIOS_OK);
  kassert(ai_cell_prepare(1) == XAIOS_ERR_INVALID);

  /* Two leasable workers, by whether this machine has two -- not by counting
     to three and assuming their ids. */
  uint32_t multi_worker = second_mask != 0U;
  if (multi_worker != 0U) {
    xaios_ai_cell_descriptor_v1_t nic_conflict;
    ai_cell_fill_descriptor(&nic_conflict, 2, "nic-conflict-agent", second_mask,
                            2, 1, 2, 64 * 1024, 128 * 1024);
    kassert(ai_cell_create_from_descriptor(&nic_conflict) == XAIOS_OK);
    kassert(ai_cell_prepare(2) == XAIOS_ERR_INVALID);

    xaios_ai_cell_descriptor_v1_t workspace_conflict;
    ai_cell_fill_descriptor(&workspace_conflict, 4, "workspace-conflict-agent",
                            second_mask, 2, 2, 1, 64 * 1024, 128 * 1024);
    kassert(ai_cell_create_from_descriptor(&workspace_conflict) == XAIOS_OK);
    kassert(ai_cell_prepare(4) == XAIOS_ERR_INVALID);

    xaios_ai_cell_descriptor_v1_t shared;
    ai_cell_fill_descriptor(&shared, 3, "shared-weight-agent", second_mask, 2, 2,
                            2, 64 * 1024, 128 * 1024);
    kassert(ai_cell_create_from_descriptor(&shared) == XAIOS_OK);
    kassert(ai_cell_prepare(3) == XAIOS_OK);
    kassert(ai_cell_start(3) == XAIOS_OK);
    kassert(cpu_ai_runtime_fixture_decode_piece(3, piece, sizeof(piece), output,
                                               sizeof(output), &out) ==
            XAIOS_OK);
    kassert(str_equal(output, "1B1F2327"));
    kassert(ai_cell_arena_pages_reserved() == 160);
    kassert(ai_cell_arena_bytes_reserved() == 655360);
    kassert(ai_cell_arena_pages_peak() == 160);
    kassert(ai_cell_arena_bytes_peak() == 655360);
    kassert(ai_cell_stop(3) == XAIOS_OK);
    kassert(ai_cell_arena_pages_reserved() == 80);
    kassert(ai_cell_arena_bytes_reserved() == 327680);
    klog("ai-cell: multi-cell shared model/private kv self-test passed\n");
  } else {
    klog("ai-cell: multi-worker sharing self-test skipped cpus=%u\n",
         smp_online_count());
  }

  kassert(ai_cell_stop(0) == XAIOS_OK);
  kassert(ai_cell_arena_pages_reserved() == 0);
  kassert(ai_cell_arena_bytes_reserved() == 0);
  kassert(ai_cell_descriptor_accept_count() ==
          (multi_worker != 0U ? 5U : 2U));
  kassert(ai_cell_descriptor_reject_count() == 4);
  kassert(ai_cell_resource_admission_count() ==
          (multi_worker != 0U ? 2U : 1U));
  kassert(ai_cell_resource_reject_count() >=
          (multi_worker != 0U ? 10U : 4U));
  kassert(ai_cell_queue_bind_count() ==
          (multi_worker != 0U ? 3U : 1U));
  kassert(ai_cell_queue_release_count() ==
          (multi_worker != 0U ? 3U : 1U));
  kassert(ai_cell_workspace_bind_count() ==
          (multi_worker != 0U ? 2U : 1U));
  kassert(ai_cell_workspace_release_count() ==
          (multi_worker != 0U ? 2U : 1U));
  kassert(ai_cell_conflict_count() ==
          (multi_worker != 0U ? 3U : 1U));
  klog("ai-cell: descriptor ABI self-test passed accepts=%lu rejects=%lu checksum=0x%lx\n",
       ai_cell_descriptor_accept_count(), ai_cell_descriptor_reject_count(),
       descriptor.checksum);
  klog("ai-cell: resource contract self-test passed admissions=%lu rejects=%lu arena_pages=%lu arena_bytes=%lu queue_binds=%lu queue_releases=%lu workspace_binds=%lu workspace_releases=%lu conflicts=%lu\n",
       ai_cell_resource_admission_count(), ai_cell_resource_reject_count(),
       ai_cell_arena_pages_peak(), ai_cell_arena_bytes_peak(),
       ai_cell_queue_bind_count(), ai_cell_queue_release_count(),
       ai_cell_workspace_bind_count(), ai_cell_workspace_release_count(),
       ai_cell_conflict_count());
  klog("ai-cell: lifecycle self-test passed\n");
}
