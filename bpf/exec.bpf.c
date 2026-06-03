// SPDX-License-Identifier: GPL-2.0
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256

// 内核态采集的进程 exec 事件,字段顺序必须与 pkg/event/event.go 对齐
struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 _pad;
    __u64 cgroup_id;
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
};

// 内核态 -> 用户态的高性能无锁队列(16MB),用户态通过 ringbuf reader 消费
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// 挂在 sched_process_exec tracepoint 上:每次任意进程 execve 成功都会触发
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // 在 ringbuf 中预留一块事件空间,失败说明缓冲区满,直接丢弃
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 采集进程基本信息:pid / uid / cgroup / 父进程 pid / comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->uid       = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->_pad      = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // tracepoint 中 filename 是变长字段,通过 __data_loc 偏移定位后再读出
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    // 提交事件,用户态可见
    bpf_ringbuf_submit(e, 0);
    return 0;
}
