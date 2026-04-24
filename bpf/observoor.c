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
const struct mem_latency_event *__unused_mem_latency_ev __attribute__((unused));
const struct swap_event *__unused_swap_ev __attribute__((unused));
const struct oom_kill_event *__unused_oom_kill_ev __attribute__((unused));
const struct process_exit_event *__unused_proc_exit_ev __attribute__((unused));

// block_rq_* tracepoint field layouts vary by kernel. Derive bytes from
// nr_sector (always 512-byte sectors) to avoid relying on ctx->bytes offsets.
static __always_inline __u32 sectors_to_bytes(__u32 nr_sector)
{
    __u64 bytes = ((__u64)nr_sector) << 9;
    if (bytes > 0xFFFFFFFFULL)
        return 0xFFFFFFFFU;
    return (__u32)bytes;
}

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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_READ))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_READ, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_WRITE))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_WRITE, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int trace_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_FUTEX))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_FUTEX, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_sys_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_MMAP))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_MMAP, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int trace_sys_exit_epoll_wait(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_EPOLL_WAIT))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_EPOLL_WAIT, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int trace_sys_exit_fsync(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_FSYNC))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_FSYNC, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int trace_sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_FDATASYNC))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_FDATASYNC, val->client_type);
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int trace_sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_SYSCALL_PWRITE))
        goto cleanup;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_SYSCALL_PWRITE, val->client_type);
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
// FD tracers: open/openat/openat2/creat, close
// =========================================================

static __always_inline int trace_fd_open_enter(const char *fname)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct openat_val val = {
        .ts = bpf_ktime_get_ns(),
        .client_type = ct,
    };

    bpf_probe_read_user_str(val.filename, sizeof(val.filename), fname);

    bpf_map_update_elem(&openat_names, &key, &val, BPF_ANY);
    return 0;
}

static __always_inline int trace_fd_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct openat_val *val = bpf_map_lookup_elem(&openat_names, &key);
    if (!val)
        return 0;

    if (ctx->ret < 0)
        goto cleanup;

    if (!should_emit_event(EVENT_FD_OPEN))
        goto cleanup;

    struct fd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_FD_OPEN, val->client_type);
    e->fd = (int)ctx->ret;
    __builtin_memset(e->pad, 0, sizeof(e->pad));
    __builtin_memcpy(e->filename, val->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&openat_names, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    return trace_fd_open_enter((const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    return trace_fd_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
    return trace_fd_open_enter((const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
    return trace_fd_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
    return trace_fd_open_enter((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_sys_exit_open(struct trace_event_raw_sys_exit *ctx)
{
    return trace_fd_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_sys_enter_creat(struct trace_event_raw_sys_enter *ctx)
{
    return trace_fd_open_enter((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_creat")
int trace_sys_exit_creat(struct trace_event_raw_sys_exit *ctx)
{
    return trace_fd_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
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
        .client_type = ct,
    };
    bpf_map_update_elem(&syscall_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_sys_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct syscall_val *val = bpf_map_lookup_elem(&syscall_start, &key);
    if (!val)
        return 0;

    if (ctx->ret != 0)
        goto cleanup;

    if (!should_emit_event(EVENT_FD_CLOSE))
        goto cleanup;

    struct fd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_FD_CLOSE, val->client_type);
    e->fd = val->fd;
    __builtin_memset(e->pad, 0, sizeof(e->pad));
    __builtin_memset(e->filename, 0, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&syscall_start, &key);
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
    char rwbs[10] = {};

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
    if (bpf_map_update_elem(&req_start, keyp, &val, BPF_ANY) != 0)
        return 0;

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
    char rwbs[10] = {};

    bpf_probe_read_kernel(&dev, sizeof(dev), &ctx->dev);
    bpf_probe_read_kernel(&sector, sizeof(sector), &ctx->sector);
    bpf_probe_read_kernel(&nr_sector, sizeof(nr_sector), &ctx->nr_sector);
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);
    bytes = sectors_to_bytes(nr_sector);

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

    if (!should_emit_event(EVENT_DISK_IO))
        goto cleanup;

    struct disk_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_DISK_IO, val->client_type);
    e->hdr.pid = val->pid;
    e->hdr.tid = val->tid;
    e->latency_ns = bpf_ktime_get_ns() - val->ts;
    e->bytes = bytes;
    e->rw = rw;
    __builtin_memset(e->pad, 0, sizeof(e->pad));
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
    __u32 dev = 0;
    __u64 sector = 0;
    __u32 nr_sector = 0;
    __u32 bytes = 0;
    char rwbs[10] = {};

    bpf_probe_read_kernel(&dev, sizeof(dev), &ctx->dev);
    bpf_probe_read_kernel(&sector, sizeof(sector), &ctx->sector);
    bpf_probe_read_kernel(&nr_sector, sizeof(nr_sector), &ctx->nr_sector);
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);
    bytes = sectors_to_bytes(nr_sector);

    __u8 rw = (rwbs[0] == 'W') ? 1 : 0;

    // Clean up the merged request's entry from req_start.
    // When a request is merged into another, it will never receive its own
    // block_rq_complete event. Without cleanup, the stale timestamp causes
    // latency calculations to produce values equal to system uptime.
    struct req_key key = {};
    key.dev = dev;
    key.nr_sector = nr_sector;
    key.sector = sector;
    key.rw = rw;

    struct req_key *keyp = &key;
    asm volatile("" : "+r"(keyp));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u8 ct;

    struct req_val *val = bpf_map_lookup_elem(&req_start, keyp);
    if (val) {
        pid = val->pid;
        tid = val->tid;
        ct = val->client_type;
        bpf_map_delete_elem(&req_start, keyp);

        // Decrement in-flight depth since this request was absorbed.
        __u32 *depthp = bpf_map_lookup_elem(&dev_inflight, &dev);
        if (depthp && *depthp > 0) {
            __u32 depth = *depthp - 1;
            bpf_map_update_elem(&dev_inflight, &dev, &depth, BPF_ANY);
        }
    } else if (!is_tracked(pid, &ct)) {
        return 0;
    }

    if (!should_emit_event(EVENT_BLOCK_MERGE))
        return 0;

    struct block_merge_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

    fill_header(&e->hdr, EVENT_BLOCK_MERGE, ct);
    e->hdr.pid = pid;
    e->hdr.tid = tid;
    e->bytes = bytes;
    e->dev = dev;
    e->rw = rw;
    __builtin_memset(e->pad, 0, sizeof(e->pad));

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

    // Stash socket metadata + TCP metrics for the kretprobe.
    // We capture TCP metrics here because sk is only available on entry.
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct net_send_val val = {};
    val.ts = bpf_ktime_get_ns();
    val.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    val.dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    val.pid = pid;
    val.client_type = ct;
    val.transport = NET_TRANSPORT_TCP;
    {
        __u32 srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);
        val.srtt_us = srtt >> 3;
    }
    val.snd_cwnd = BPF_CORE_READ((struct tcp_sock *)sk, snd_cwnd);
    bpf_map_update_elem(&net_send_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe_tcp_sendmsg, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };

    struct net_send_val *val = bpf_map_lookup_elem(&net_send_start, &key);
    if (!val)
        return 0;

    if (ret <= 0)
        goto cleanup;

    if (!should_emit_event(EVENT_NET_TX))
        goto cleanup;

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_NET_TX, val->client_type);
    e->hdr.pid = val->pid;
    e->bytes = (__u32)ret;
    e->sport = val->sport;
    e->dport = val->dport;
    e->direction = 0; // TX
    e->has_metrics = 1;
    e->transport = val->transport;
    e->pad[0] = 0;
    e->srtt_us = val->srtt_us;
    e->snd_cwnd = val->snd_cwnd;
    __builtin_memset(e->tail_pad, 0, sizeof(e->tail_pad));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&net_send_start, &key);
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
    val.transport = NET_TRANSPORT_TCP;
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

    if (!should_emit_event(EVENT_NET_RX))
        goto cleanup;

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_NET_RX, val->client_type);
    e->hdr.pid = val->pid;
    e->bytes = (__u32)ret;
    e->sport = val->sport;
    e->dport = val->dport;
    e->direction = 1; // RX
    e->has_metrics = 0;
    e->transport = val->transport;
    e->pad[0] = 0;
    e->srtt_us = 0;
    e->snd_cwnd = 0;
    __builtin_memset(e->tail_pad, 0, sizeof(e->tail_pad));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&net_recv_start, &key);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct net_send_val val = {};
    val.ts = bpf_ktime_get_ns();
    val.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    val.dport = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    val.pid = pid;
    val.client_type = ct;
    val.transport = NET_TRANSPORT_UDP;
    val.srtt_us = 0;
    val.snd_cwnd = 0;
    bpf_map_update_elem(&net_send_udp_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(kretprobe_udp_sendmsg, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };

    struct net_send_val *val = bpf_map_lookup_elem(&net_send_udp_start, &key);
    if (!val)
        return 0;

    if (ret <= 0)
        goto cleanup;

    if (!should_emit_event(EVENT_NET_TX))
        goto cleanup;

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_NET_TX, val->client_type);
    e->hdr.pid = val->pid;
    e->bytes = (__u32)ret;
    e->sport = val->sport;
    e->dport = val->dport;
    e->direction = 0; // TX
    e->has_metrics = 0;
    e->transport = val->transport;
    e->pad[0] = 0;
    e->srtt_us = 0;
    e->snd_cwnd = 0;
    __builtin_memset(e->tail_pad, 0, sizeof(e->tail_pad));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&net_send_udp_start, &key);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe_udp_recvmsg, struct sock *sk)
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
    val.transport = NET_TRANSPORT_UDP;
    bpf_map_update_elem(&net_recv_udp_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe_udp_recvmsg, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };

    struct net_recv_val *val = bpf_map_lookup_elem(&net_recv_udp_start, &key);
    if (!val)
        return 0;

    if (ret <= 0)
        goto cleanup;

    if (!should_emit_event(EVENT_NET_RX))
        goto cleanup;

    struct net_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_NET_RX, val->client_type);
    e->hdr.pid = val->pid;
    e->bytes = (__u32)ret;
    e->sport = val->sport;
    e->dport = val->dport;
    e->direction = 1; // RX
    e->has_metrics = 0;
    e->transport = val->transport;
    e->pad[0] = 0;
    e->srtt_us = 0;
    e->snd_cwnd = 0;
    __builtin_memset(e->tail_pad, 0, sizeof(e->tail_pad));

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&net_recv_udp_start, &key);
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

    if (!should_emit_event(EVENT_TCP_RETRANSMIT))
        return 0;

    struct tcp_retransmit_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

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
    __builtin_memset(e->pad, 0, sizeof(e->pad));

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

    if (!should_emit_event(EVENT_TCP_STATE)) {
        if (state == 7) { // TCP_CLOSE
            bpf_map_delete_elem(&sock_owner, &sk_key);
        }
        return 0;
    }

    struct tcp_state_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        if (state == 7) { // TCP_CLOSE
            bpf_map_delete_elem(&sock_owner, &sk_key);
        }
        return 0;
    }

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
    __builtin_memset(e->pad, 0, sizeof(e->pad));

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

    // Path A: Record sched-ON timestamp for incoming thread unconditionally.
    // We cannot filter by TGID here because ctx->next_pid is a TID and
    // bpf_get_current_pid_tgid() returns the *outgoing* task's TGID.
    // The LRU map auto-evicts stale entries from irrelevant threads.
    __u32 next_tid = ctx->next_pid;
    bpf_map_update_elem(&sched_on_ts, &next_tid, &now, BPF_ANY);

    struct tracked_tid_val *next_info = lookup_tracked_tid(next_tid);

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

        if (should_emit_event(EVENT_SCHED_RUNQUEUE)) {
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
                rq->cpu_id = bpf_get_smp_processor_id();
                __builtin_memset(rq->pad, 0, sizeof(rq->pad));
                bpf_ringbuf_submit(rq, 0);
            } else {
                record_ringbuf_drop();
            }
        }
    }

    // Path B: Emit event for outgoing (prev) thread.
    //
    // The tracepoint already provides prev_pid (the outgoing TID). Prefer the
    // tracked_tids map for PID/client resolution instead of assuming
    // bpf_get_current_pid_tgid() still refers to the outgoing task on every
    // kernel. That assumption can drift across kernels and lead to stale
    // sched_on_ts lookups being charged to the wrong process.
    __u32 tid = ctx->prev_pid;
    __u32 pid = 0;

    struct tracked_tid_val *prev_info = lookup_tracked_tid(tid);
    if (prev_info) {
        pid = prev_info->pid;
        ct = prev_info->client_type;
    } else {
        // Fallback for threads created between userspace TID refreshes: only
        // trust current_pid_tgid when the kernel still reports the outgoing TID
        // as current. Otherwise skip rather than risk misattributing CPU time.
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        if ((__u32)pid_tgid != tid)
            return 0;

        pid = pid_tgid >> 32;
        if (!is_tracked(pid, &ct))
            return 0;
    }

    // Record off-CPU timestamp for the outgoing tracked thread. The LRU map
    // auto-evicts stale entries from dead threads.
    bpf_map_update_elem(&offcpu_ts, &tid, &now, BPF_ANY);

    // Consume sched_on_ts exactly once even if the event is sampled out or the
    // ring buffer is temporarily full. Leaving the old start timestamp behind
    // would make the next switch-out accumulate multiple slices into one
    // impossible on_cpu_ns value.
    __u64 on_cpu_ns = 0;
    __u64 *on_ts = bpf_map_lookup_elem(&sched_on_ts, &tid);
    if (on_ts && *on_ts > 0 && now > *on_ts)
        on_cpu_ns = now - *on_ts;
    bpf_map_delete_elem(&sched_on_ts, &tid);

    if (!should_emit_event(EVENT_SCHED_SWITCH))
        return 0;

    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

    e->hdr.timestamp_ns = now;
    e->hdr.pid = pid;
    e->hdr.tid = tid;
    e->hdr.event_type = EVENT_SCHED_SWITCH;
    e->hdr.client_type = ct;
    __builtin_memset(e->hdr.pad, 0, sizeof(e->hdr.pad));
    e->on_cpu_ns = on_cpu_ns;

    // prev_state > 0 means the task was preempted (involuntary),
    // prev_state == 0 means the task voluntarily yielded.
    e->voluntary = (ctx->prev_state == 0) ? 1 : 0;
    __builtin_memset(e->pad, 0, sizeof(e->pad));
    e->cpu_id = bpf_get_smp_processor_id();

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
        .client_type = ct,
    };
    bpf_map_update_elem(&fault_start, &key, &val, BPF_ANY);
    return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(kretprobe_handle_mm_fault, unsigned long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_key key = { .pid_tgid = pid_tgid };
    struct fault_val *val = bpf_map_lookup_elem(&fault_start, &key);
    if (!val)
        return 0;

    if (!should_emit_event(EVENT_PAGE_FAULT))
        goto cleanup;

    struct page_fault_event *e = bpf_ringbuf_reserve(
        &events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_PAGE_FAULT, val->client_type);
    e->address = val->address;
    // VM_FAULT_MAJOR is typically bit 2 (0x04).
    e->major = (ret & 0x04) ? 1 : 0;
    __builtin_memset(e->pad, 0, sizeof(e->pad));

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

    if (!should_emit_event(EVENT_MEM_RECLAIM))
        goto cleanup;

    struct mem_latency_event *e = bpf_ringbuf_reserve(
        &events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

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

    if (!should_emit_event(EVENT_MEM_COMPACTION))
        goto cleanup;

    struct mem_latency_event *e = bpf_ringbuf_reserve(
        &events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        goto cleanup;
    }

    fill_header(&e->hdr, EVENT_MEM_COMPACTION, ct);
    e->duration_ns = bpf_ktime_get_ns() - *start;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&compaction_start, &pid_tgid);
    return 0;
}

SEC("kprobe/swap_read_folio")
int BPF_KPROBE(kprobe_swap_read, void *page_or_folio)
{
    (void)page_or_folio;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    if (!should_emit_event(EVENT_SWAP_IN))
        return 0;

    struct swap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

    fill_header(&e->hdr, EVENT_SWAP_IN, ct);
    e->pages = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/swap_writepage")
int BPF_KPROBE(kprobe_swap_write, void *page_or_folio)
{
    (void)page_or_folio;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u8 ct;

    if (!is_tracked(pid, &ct))
        return 0;

    if (!should_emit_event(EVENT_SWAP_OUT))
        return 0;

    struct swap_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

    fill_header(&e->hdr, EVENT_SWAP_OUT, ct);
    e->pages = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/oom/mark_victim")
int trace_oom_mark_victim(struct trace_event_raw_oom_mark_victim_local *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 target_pid = ctx->pid;
    __u8 ct;

    if (!is_tracked(target_pid, &ct))
        return 0;

    if (!should_emit_event(EVENT_OOM_KILL))
        return 0;

    struct oom_kill_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

    fill_header(&e->hdr, EVENT_OOM_KILL, ct);
    e->hdr.pid = target_pid;
    e->hdr.tid = tid;
    e->target_pid = target_pid;
    __builtin_memset(e->pad, 0, sizeof(e->pad));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe_do_exit, long code)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u8 ct;

    // Always clean scheduler/TID state. sched_switch timestamps are tracked for
    // all threads, and fast TID reuse can otherwise turn stale entries into
    // impossible on/off-CPU durations for the next thread owner.
    cleanup_tid_scheduler_state(tid);

    if (!is_tracked(pid, &ct))
        return 0;

    if (!should_emit_event(EVENT_PROCESS_EXIT))
        return 0;

    struct process_exit_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_ringbuf_drop();
        return 0;
    }

    fill_header(&e->hdr, EVENT_PROCESS_EXIT, ct);
    e->exit_code = (u32)code;
    __builtin_memset(e->pad, 0, sizeof(e->pad));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
