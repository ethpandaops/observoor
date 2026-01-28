#ifndef __MAPS_H
#define __MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "observoor.h"

// tracked_pids: PIDs to trace, value is client_type.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

// events: Ring buffer for all events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4MB default
} events SEC(".maps");

// syscall_start: Entry timestamps per thread.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct syscall_key);
    __type(value, struct syscall_val);
} syscall_start SEC(".maps");

// openat_names: Filename capture during openat.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct syscall_key);
    __type(value, struct openat_val);
} openat_names SEC(".maps");

// req_start: Block I/O request tracking.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct req_key);
    __type(value, struct req_val);
} req_start SEC(".maps");

// net_recv_start: Socket info during recvmsg.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syscall_key);
    __type(value, struct net_recv_val);
} net_recv_start SEC(".maps");

// fault_start: Page fault entry timestamps.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syscall_key);
    __type(value, struct fault_val);
} fault_start SEC(".maps");

// tracked_tids: TIDs to trace for on-CPU time, value is client_type.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} tracked_tids SEC(".maps");

// sched_on_ts: Per-TID on-CPU timestamp (ktime_ns when scheduled on).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} sched_on_ts SEC(".maps");

// Helper: Check if PID is tracked and return client_type.
static __always_inline int is_tracked(__u32 pid, __u8 *client_type) {
    __u8 *ct = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!ct)
        return 0;
    *client_type = *ct;
    return 1;
}

// Helper: Check if TID is tracked and return client_type.
static __always_inline int is_tracked_tid(
    __u32 tid, __u8 *client_type
) {
    __u8 *ct = bpf_map_lookup_elem(&tracked_tids, &tid);
    if (!ct)
        return 0;
    *client_type = *ct;
    return 1;
}

// Helper: Fill common event header.
static __always_inline void fill_header(
    struct event_header *hdr,
    __u8 event_type,
    __u8 client_type
) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->pid = pid_tgid >> 32;
    hdr->tid = (__u32)pid_tgid;
    hdr->event_type = event_type;
    hdr->client_type = client_type;
    __builtin_memset(hdr->pad, 0, sizeof(hdr->pad));
}

#endif /* __MAPS_H */
