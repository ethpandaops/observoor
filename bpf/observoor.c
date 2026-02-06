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
const struct sched_runqueue_event *__unused_sched_rq_ev __attribute__((unused));
const struct block_merge_event *__unused_block_merge_ev __attribute__((unused));
const struct tcp_retransmit_event *__unused_tcp_retx_ev __attribute__((unused));
const struct tcp_state_event *__unused_tcp_state_ev __attribute__((unused));
const struct tcp_metrics_event *__unused_tcp_metrics_ev __attribute__((unused));
const struct mem_latency_event *__unused_mem_latency_ev __attribute__((unused));
const struct swap_event *__unused_swap_ev __attribute__((unused));
const struct oom_kill_event *__unused_oom_kill_ev __attribute__((unused));
const struct process_exit_event *__unused_proc_exit_ev __attribute__((unused));

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

// --- fsync ---
SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_sys_enter_fsync(struct trace_event_raw_sys_enter *ctx)
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

SEC("tracepoint/syscalls/sys_exit_fsync")
int trace_sys_exit_fsync(struct trace_event_raw_sys_exit *ctx)
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

    fill_header(&e->hdr, EVENT_SYSCALL_FSYNC, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = (u32)ctx->id;
    e->fd = val->fd;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// --- fdatasync ---
SEC("tracepoint/syscalls/sys_enter_fdatasync")
int trace_sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx)
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

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int trace_sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx)
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

    fill_header(&e->hdr, EVENT_SYSCALL_FDATASYNC, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = (u32)ctx->id;
    e->fd = val->fd;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
    return 0;
}

// --- pwrite64 ---
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
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

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int trace_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
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

    fill_header(&e->hdr, EVENT_SYSCALL_PWRITE, ct);
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->ret = ctx->ret;
    e->syscall_nr = (u32)ctx->id;
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
int trace_block_rq_issue(struct trace_event_raw_block_rq_local *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    __u32 dev = 0;
    __u64 sector = 0;
    __u32 nr_sector = 0;
    char rwbs[8] = {};

    bpf_probe_read_kernel(&dev, sizeof(dev), &ctx->dev);
    bpf_probe_read_kernel(&sector, sizeof(sector), &ctx->sector);
    bpf_probe_read_kernel(&nr_sector, sizeof(nr_sector), &ctx->nr_sector);
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);

    __u8 rw = (rwbs[0] == 'W') ? 1 : 0;
    struct req_key key = {};
    key.dev = dev;
    key.nr_sector = nr_sector;
    key.sector = sector;
    key.rw = rw;

    struct req_key *keyp = &key;
    asm volatile("" : "+r"(keyp));

    struct req_val val = {};
    val.ts = bpf_ktime_get_ns();
    val.pid = pid;
    val.tid = tid;
    val.client_type = ct;
    bpf_map_update_elem(&req_start, keyp, &val, BPF_ANY);

    // Track per-device in-flight depth.
    __u32 depth = 0;
    __u32 *depthp = bpf_map_lookup_elem(&dev_inflight, &dev);
    if (depthp)
        depth = *depthp;
    depth++;
    bpf_map_update_elem(&dev_inflight, &dev, &depth, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq_local *ctx)
{
    __u32 dev = 0;
    __u64 sector = 0;
    __u32 nr_sector = 0;
    __u32 bytes = 0;
    char rwbs[8] = {};

    bpf_probe_read_kernel(&dev, sizeof(dev), &ctx->dev);
    bpf_probe_read_kernel(&sector, sizeof(sector), &ctx->sector);
    bpf_probe_read_kernel(&nr_sector, sizeof(nr_sector), &ctx->nr_sector);
    bpf_probe_read_kernel(&bytes, sizeof(bytes), &ctx->bytes);
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);

    __u8 rw = (rwbs[0] == 'W') ? 1 : 0;
    struct req_key key = {};
    key.dev = dev;
    key.nr_sector = nr_sector;
    key.sector = sector;
    key.rw = rw;

    struct req_key *keyp = &key;
    asm volatile("" : "+r"(keyp));

    struct req_val *val = bpf_map_lookup_elem(&req_start, keyp);
    if (!val)
        return 0;

    __u32 depth = 0;
    __u32 *depthp = bpf_map_lookup_elem(&dev_inflight, &dev);
    if (depthp && *depthp > 0)
        depth = *depthp - 1;
    if (depthp)
        bpf_map_update_elem(&dev_inflight, &dev, &depth, BPF_ANY);

    struct disk_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_DISK_IO, val->client_type);
    e->hdr.pid = val->pid;
    e->hdr.tid = val->tid;
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->bytes = bytes;
    e->rw = rw;
    e->queue_depth = depth;
    e->dev = dev;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&req_start, keyp);
    return 0;
}

SEC("tracepoint/block/block_rq_merge")
int trace_block_rq_merge(struct trace_event_raw_block_rq_local *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    __u32 bytes = 0;
    char rwbs[8] = {};

    bpf_probe_read_kernel(&bytes, sizeof(bytes), &ctx->bytes);
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);

    struct block_merge_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_BLOCK_MERGE, ct);
    e->bytes = bytes;
    e->rw = (rwbs[0] == 'W') ? 1 : 0;

    bpf_ringbuf_submit(e, 0);
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
    __u32 tid = (__u32)pid_tgid;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    __u64 sk_key = (unsigned long)sk;
    struct sock_owner_val sval = {
        .pid = pid,
        .tid = tid,
        .client_type = ct,
    };
    bpf_map_update_elem(&sock_owner, &sk_key, &sval, BPF_ANY);

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_TX, ct);
    e->bytes = (__u32)size;
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->direction = 0; // TX

    // Inline TCP metrics into the net_tx event (saves a separate ring buffer entry).
    e->has_metrics = 1;
    {
        __u32 srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);
        e->srtt_us = srtt >> 3;
    }
    e->snd_cwnd = BPF_CORE_READ((struct tcp_sock *)sk, snd_cwnd);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    __u64 sk_key = (unsigned long)sk;
    struct sock_owner_val sval = {
        .pid = pid,
        .tid = tid,
        .client_type = ct,
    };
    bpf_map_update_elem(&sock_owner, &sk_key, &sval, BPF_ANY);

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
    e->has_metrics = 0;
    e->srtt_us = 0;
    e->snd_cwnd = 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&net_recv_start, &key);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(kprobe_tcp_retransmit_skb, struct sock *sk,
               struct sk_buff *skb)
{
    __u64 sk_key = (unsigned long)sk;
    struct sock_owner_val *sval =
        bpf_map_lookup_elem(&sock_owner, &sk_key);
    if (!sval)
        return 0;

    struct tcp_retransmit_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.timestamp_ns = bpf_ktime_get_ns();
    e->hdr.pid = sval->pid;
    e->hdr.tid = sval->tid;
    e->hdr.event_type = EVENT_TCP_RETRANSMIT;
    e->hdr.client_type = sval->client_type;
    __builtin_memset(e->hdr.pad, 0, sizeof(e->hdr.pad));

    e->bytes = BPF_CORE_READ(skb, len);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(kprobe_tcp_set_state, struct sock *sk, int state)
{
    __u64 sk_key = (unsigned long)sk;
    struct sock_owner_val *sval =
        bpf_map_lookup_elem(&sock_owner, &sk_key);
    if (!sval)
        return 0;

    struct tcp_state_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.timestamp_ns = bpf_ktime_get_ns();
    e->hdr.pid = sval->pid;
    e->hdr.tid = sval->tid;
    e->hdr.event_type = EVENT_TCP_STATE;
    e->hdr.client_type = sval->client_type;
    __builtin_memset(e->hdr.pad, 0, sizeof(e->hdr.pad));

    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->new_state = (__u8)state;
    e->old_state = BPF_CORE_READ(sk, __sk_common.skc_state);

    bpf_ringbuf_submit(e, 0);

    if (state == 7) { // TCP_CLOSE
        bpf_map_delete_elem(&sock_owner, &sk_key);
    }

    return 0;
}

// =========================================================
// Scheduler tracer
// =========================================================

SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct trace_event_raw_sched_wakeup_local *ctx)
{
    __u32 tid = ctx->pid;
    __u8 ct;

    if (!is_tracked_tid(tid, &ct))
        return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &tid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int trace_sched_wakeup_new(struct trace_event_raw_sched_wakeup_local *ctx)
{
    __u32 tid = ctx->pid;
    __u8 ct;

    if (!is_tracked_tid(tid, &ct))
        return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &tid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u8 ct;

    // Path A: Record sched-ON timestamp for incoming thread.
    __u32 next_tid = ctx->next_pid;
    struct tracked_tid_val *next_info = lookup_tracked_tid(next_tid);
    if (next_info) {
        bpf_map_update_elem(&sched_on_ts, &next_tid, &now, BPF_ANY);
    }

    // Emit runqueue/off-CPU latency event for incoming thread.
    if (next_info) {
        __u64 runqueue_ns = 0;
        __u64 offcpu_ns = 0;

        __u64 *wake_ts = bpf_map_lookup_elem(&wakeup_ts, &next_tid);
        if (wake_ts && now > *wake_ts)
            runqueue_ns = now - *wake_ts;
        if (wake_ts)
            bpf_map_delete_elem(&wakeup_ts, &next_tid);

        __u64 *off_ts = bpf_map_lookup_elem(&offcpu_ts, &next_tid);
        if (off_ts && now > *off_ts)
            offcpu_ns = now - *off_ts;
        if (off_ts)
            bpf_map_delete_elem(&offcpu_ts, &next_tid);

        struct sched_runqueue_event *rq =
            bpf_ringbuf_reserve(&events, sizeof(*rq), 0);
        if (rq) {
            rq->hdr.timestamp_ns = now;
            rq->hdr.pid = next_info->pid;
            rq->hdr.tid = next_tid;
            rq->hdr.event_type = EVENT_SCHED_RUNQUEUE;
            rq->hdr.client_type = next_info->client_type;
            __builtin_memset(rq->hdr.pad, 0, sizeof(rq->hdr.pad));
            rq->runqueue_ns = runqueue_ns;
            rq->off_cpu_ns = offcpu_ns;
            bpf_ringbuf_submit(rq, 0);
        }
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

    // Record off-CPU timestamp for outgoing thread.
    if (lookup_tracked_tid(tid)) {
        bpf_map_update_elem(&offcpu_ts, &tid, &now, BPF_ANY);
    }

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
    e->voluntary = (ctx->prev_state == 0) ? 1 : 0;

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

// =========================================================
// Memory pressure tracers
// =========================================================

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int trace_reclaim_begin(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&reclaim_start, &pid_tgid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int trace_reclaim_end(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    __u64 *start = bpf_map_lookup_elem(&reclaim_start, &pid_tgid);
    if (!start)
        return 0;

    if (!is_tracked(pid, &ct))
        goto cleanup;

    struct mem_latency_event *e = bpf_ringbuf_reserve(
        &events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_MEM_RECLAIM, ct);
    e->duration_ns = bpf_ktime_get_ns() - *start;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&reclaim_start, &pid_tgid);
    return 0;
}

SEC("tracepoint/compaction/compaction_begin")
int trace_compaction_begin(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&compaction_start, &pid_tgid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/compaction/compaction_end")
int trace_compaction_end(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    __u64 *start = bpf_map_lookup_elem(&compaction_start, &pid_tgid);
    if (!start)
        return 0;

    if (!is_tracked(pid, &ct))
        goto cleanup;

    struct mem_latency_event *e = bpf_ringbuf_reserve(
        &events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    fill_header(&e->hdr, EVENT_MEM_COMPACTION, ct);
    e->duration_ns = bpf_ktime_get_ns() - *start;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&compaction_start, &pid_tgid);
    return 0;
}

SEC("tracepoint/swap/swapin")
int trace_swapin(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct swap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_SWAP_IN, ct);
    e->pages = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/swap/swapout")
int trace_swapout(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct swap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_SWAP_OUT, ct);
    e->pages = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/oom/oom_kill")
int trace_oom_kill(struct trace_event_raw_oom_kill_local *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 target_pid = 0;
    __u8 ct;

    target_pid = ctx->tgid;
    if (target_pid == 0)
        target_pid = ctx->pid;

    if (!is_tracked(target_pid, &ct))
        return 0;

    struct oom_kill_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_OOM_KILL, ct);
    e->hdr.pid = target_pid;
    e->hdr.tid = tid;
    e->target_pid = target_pid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe_do_exit, long code)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct process_exit_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_PROCESS_EXIT, ct);
    e->exit_code = (u32)code;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
