// This file contains the code and map definitions for the tracepoint on the scheduler to
// report the stopping a process.

#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"

bpf_map_def SEC("maps") pid_cgroup_info = {
  .type        = BPF_MAP_TYPE_LRU_HASH,
  .key_size    = sizeof(s32),
  .value_size  = sizeof(CgroupInfo),
  .max_entries = 65536,
};

struct cgroup_attach_task_args {
  u64 _reserved;
  s32 dst_root;
  s32 dst_level;
  u64 dst_id;
  s32 pid;
};

SEC("tracepoint/cgroup/cgroup_attach_task")
int tracepoint__cgroup_attach_task(void *ctx)
{
  struct cgroup_attach_task_args *args = (struct cgroup_attach_task_args *)ctx;
  s32 pid = args->pid;

  if (args->dst_root >= MAX_CGROUP_ROOTS || args->dst_root < 0) {
    DEBUG_PRINT("cgroup root(%d) is out of range(max %d)", args->dst_root, MAX_CGROUP_ROOTS);
    return ERR_CGROUP_OUT_OF_RANGE;
  }

  DEBUG_PRINT("update pid(%d) to cgroup: root(%d)", args->pid, args->dst_root);
  DEBUG_PRINT("                  cgroup: level(%d), id(%llu)", args->dst_level, args->dst_id);

  CgroupInfo *cgroup = bpf_map_lookup_elem(&pid_cgroup_info, &pid);
  if (cgroup) {
    for (int i = 0; i < MAX_CGROUP_ROOTS; i++) {
      if (i == args->dst_root) {
        cgroup->id[i] = args->dst_id;
      }
    }
  } else {
    CgroupInfo initval;
    for (int i = 0; i < MAX_CGROUP_ROOTS; i++) {
      if (i == args->dst_root) {
        initval.id[i] = args->dst_id;
      } else {
        initval.id[i] = 0;
      }
    }
    if (bpf_map_update_elem(&pid_cgroup_info, &pid, &initval, BPF_ANY) < 0) {
      DEBUG_PRINT("cgroup update failed");
      return ERR_CGROUP_UPDATE;
    }
  }
  return 0;
}
