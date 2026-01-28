// SPDX-License-Identifier: GPL-2.0
// observoor - eBPF programs for Ethereum node observability.
//
// All BPF programs are in this single file sharing maps defined
// in maps.h. Programs are PID-filtered via the tracked_pids map.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "observoor.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Force BTF type emission for event structs used with bpf_ringbuf_reserve.
 * These are never accessed at runtime; they exist solely so that
 * clang emits named BTF entries that bpf2go can reference with -type.
 */
const struct syscall_event    *__unused_syscall_ev    __attribute__((unused));
const struct disk_io_event    *__unused_disk_io_ev    __attribute__((unused));
const struct net_io_event     *__unused_net_io_ev     __attribute__((unused));
const struct sched_event      *__unused_sched_ev      __attribute__((unused));
const struct page_fault_event *__unused_page_fault_ev __attribute__((unused));
const struct fd_event         *__unused_fd_ev         __attribute__((unused));

// =========================================================
// Syscall tracers: read, write, futex, mmap, epoll_wait
// =========================================================

// --- read ---
SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val val = {
        .ts = bpf_ktime_get_ns(),
        .fd = (int)ctx->args[0],
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_SYSCALL_READ, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = 0; // read
    e->fd = val->fd;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// --- write ---
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val val = {
        .ts = bpf_ktime_get_ns(),
        .fd = (int)ctx->args[0],
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_SYSCALL_WRITE, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = 1; // write
    e->fd = val->fd;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// --- futex ---
SEC("tracepoint/syscalls/sys_enter_futex")
int trace_sys_enter_futex(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val val = {
        .ts = bpf_ktime_get_ns(),
        .fd = 0,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int trace_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_SYSCALL_FUTEX, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = 202; // futex
    e->fd = 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// --- mmap ---
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val val = {
        .ts = bpf_ktime_get_ns(),
        .fd = 0,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_sys_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_SYSCALL_MMAP, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = 9; // mmap
    e->fd = 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// --- epoll_wait ---
SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int trace_sys_enter_epoll_wait(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val val = {
        .ts = bpf_ktime_get_ns(),
        .fd = (int)ctx->args[0],
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int trace_sys_exit_epoll_wait(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_SYSCALL_EPOLL_WAIT, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = 232; // epoll_wait
    e->fd = val->fd;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// =========================================================
// FD tracers: openat, close
// =========================================================

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct openat_val val = { .ts = bpf_ktime_get_ns() };

    const char *fname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(val.filename, sizeof(val.filename), fname);

    bpf_map_update_elem(&openat_names, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct openat_val *val = bpf_map_lookup_elem(&openat_names, &key);
    if (!val)
        return 0;

    struct fd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_FD_OPEN, ct);
    e->fd = (int)ctx->ret;
    __builtin_memcpy(e->filename, val->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&openat_names, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct fd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_FD_CLOSE, ct);
    e->fd = (int)ctx->args[0];
    __builtin_memset(e->filename, 0, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =========================================================
// Disk I/O tracers
// =========================================================

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    // Use the sector as a pseudo-request identifier.
    struct req_key key = { .req = ctx->sector };
    struct req_val val = {
        .ts = bpf_ktime_get_ns(),
        .pid = pid,
        .client_type = ct,
    };
    bpf_map_update_elem(&req_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq *ctx)
{
    struct req_key key = { .req = ctx->sector };
    struct req_val *val = bpf_map_lookup_elem(&req_start, &key);
    if (!val)
        return 0;

    struct disk_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_DISK_IO, val->client_type);
    e->hdr.pid = val->pid;
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->bytes = ctx->nr_sector * 512;
    e->rw = (ctx->rwbs[0] == 'W') ? 1 : 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&req_start, &key);
    return 0;
}

// =========================================================
// Network tracers
// =========================================================

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_TX, ct);
    e->bytes = (__u32)size;
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->direction = 0; // TX

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct net_recv_val val = {};
    val.ts = bpf_ktime_get_ns();
    val.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    val.dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    val.pid = pid;
    val.client_type = ct;
    bpf_map_update_elem(&net_recv_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };

    struct net_recv_val *val = bpf_map_lookup_elem(&net_recv_start, &key);
    if (!val)
        return 0;

    if (ret <= 0)
        goto cleanup;

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_NET_RX, val->client_type);
    e->hdr.pid = val->pid;
    e->bytes = (__u32)ret;
    e->sport = val->sport;
    e->dport = val->dport;
    e->direction = 1; // RX

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&net_recv_start, &key);
    return 0;
}

// =========================================================
// Scheduler tracer
// =========================================================

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u8 ct;

    // Path A: Record sched-ON timestamp for incoming thread.
    __u32 next_tid = ctx->next_pid;
    if (is_tracked_tid(next_tid, &ct)) {
        bpf_map_update_elem(&sched_on_ts, &next_tid, &now, BPF_ANY);
    }

    // Path B: Emit event for outgoing (prev) thread.
    // The tracepoint's prev_pid is a TID (thread ID), not the TGID
    // (thread group ID) we store in tracked_pids. Use the current
    // task's TGID for the PID filter check.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (!is_tracked(pid, &ct))
        return 0;

    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.timestamp_ns = now;
    e->hdr.pid = pid;
    e->hdr.tid = tid;
    e->hdr.event_type = EVENT_SCHED_SWITCH;
    e->hdr.client_type = ct;
    __builtin_memset(e->hdr.pad, 0, sizeof(e->hdr.pad));

    // Compute on-CPU duration from sched_on_ts entry.
    __u64 *on_ts = bpf_map_lookup_elem(&sched_on_ts, &tid);
    if (on_ts && *on_ts > 0 && now > *on_ts) {
        e->on_cpu_ns = now - *on_ts;
    } else {
        e->on_cpu_ns = 0;
    }
    bpf_map_delete_elem(&sched_on_ts, &tid);

    // prev_state > 0 means the task was preempted (involuntary),
    // prev_state == 0 means the task voluntarily yielded.
    e->voluntary = (ctx->prev_state == 0) ? 0 : 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =========================================================
// Memory tracers
// =========================================================

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(kprobe_handle_mm_fault, struct vm_area_struct *vma,
               unsigned long address)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct fault_val val = {
        .ts = bpf_ktime_get_ns(),
        .address = address,
    };
    bpf_map_update_elem(&fault_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(kretprobe_handle_mm_fault, unsigned long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct fault_val *val = bpf_map_lookup_elem(&fault_start, &key);
    if (!val)
        return 0;

    struct page_fault_event *e = bpf_ringbuf_reserve(
        &events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_PAGE_FAULT, ct);
    e->address = val->address;
    // VM_FAULT_MAJOR is typically bit 2 (0x04).
    e->major = (ret & 0x04) ? 1 : 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&fault_start, &key);
    return 0;
}
