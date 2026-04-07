#ifndef __OBSERVOOR_H
#define __OBSERVOOR_H

// Event types - must match Go EventType constants.
enum event_type {
    EVENT_SYSCALL_READ       = 1,
    EVENT_SYSCALL_WRITE      = 2,
    EVENT_SYSCALL_FUTEX      = 3,
    EVENT_SYSCALL_MMAP       = 4,
    EVENT_SYSCALL_EPOLL_WAIT = 5,
    EVENT_DISK_IO            = 6,
    EVENT_NET_TX             = 7,
    EVENT_NET_RX             = 8,
    EVENT_SCHED_SWITCH       = 9,
    EVENT_PAGE_FAULT         = 10,
    EVENT_FD_OPEN            = 11,
    EVENT_FD_CLOSE           = 12,
    EVENT_SYSCALL_FSYNC      = 13,
    EVENT_SYSCALL_FDATASYNC  = 14,
    EVENT_SYSCALL_PWRITE     = 15,
    EVENT_SCHED_RUNQUEUE     = 16,
    EVENT_BLOCK_MERGE        = 17,
    EVENT_TCP_RETRANSMIT     = 18,
    EVENT_TCP_STATE          = 19,
    EVENT_MEM_RECLAIM        = 20,
    EVENT_MEM_COMPACTION     = 21,
    EVENT_SWAP_IN            = 22,
    EVENT_SWAP_OUT           = 23,
    EVENT_OOM_KILL           = 24,
    EVENT_PROCESS_EXIT       = 25,
};

// Network transport protocol for net_io_event.
enum net_transport {
    NET_TRANSPORT_TCP = 0,
    NET_TRANSPORT_UDP = 1,
};

// Common event header (24 bytes, 8-byte aligned).
struct event_header {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u8  event_type;
    __u8  client_type;
    __u8  pad[6];
} __attribute__((packed));

// Compact syscall event (10-byte populated prefix).
// The aggregated pipeline only needs pid + client + syscall type + latency,
// so skip timestamp/tid on the hottest event family to cut ring-buffer copy
// and userspace parse work.
struct syscall_event {
    __u32 pid;
    __u32 latency_ns;
    __u8  event_type;
    __u8  client_type;
} __attribute__((packed));

// Compact generic network I/O event (23-byte populated prefix).
// Aggregation uses timestamp + pid + client + transport + ports + bytes but
// never reads tid, so keep the hot UDP/TCP RX paths smaller on the ring buffer.
struct compact_net_io_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u8  event_type;
    __u8  client_type;
    __u8  transport;
};

// Compact disk I/O event (35-byte populated prefix).
// Aggregation uses timestamp + pid + client + latency + device + queue depth
// but never reads tid, so disk completions can drop it from the hot record.
struct compact_disk_io_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u32 pid;
    __u32 bytes;
    __u32 queue_depth;
    __u32 dev; // Block device ID (major:minor encoded)
    __u8  rw;
    __u8  event_type;
    __u8  client_type;
};

// Disk I/O event (44 bytes total).
// read/write is stored in hdr.pad[0] to avoid payload padding.
struct disk_io_event {
    struct event_header hdr;
    __u64 latency_ns;
    __u32 bytes;
    __u32 queue_depth;
    __u32 dev; // Block device ID (major:minor encoded)
};

// Common network I/O event (32 bytes total).
// transport is stored in hdr.pad[0] to keep the payload small.
struct net_io_event {
    struct event_header hdr;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
};

// TCP TX network I/O event with inline metrics (40 bytes total).
// Transport is implicitly TCP for this specialized event type.
struct net_io_metrics_event {
    struct event_header hdr;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u32 srtt_us;      // Smoothed RTT
    __u32 snd_cwnd;     // Congestion window
};

// Scheduler event (32 bytes total).
// voluntary is stored in hdr.pad[0], cpu_id in hdr.pad[1..4] (little-endian).
struct sched_event {
    struct event_header hdr;
    __u64 on_cpu_ns;
};

// Combined scheduler switch + switch-in event (56 bytes total).
// Shares EVENT_SCHED_SWITCH; userspace detects the extended payload length.
// voluntary is stored in hdr.pad[0], cpu_id in hdr.pad[1..4] (little-endian),
// and next_client_type in hdr.pad[5].
struct sched_switch_runqueue_event {
    struct event_header hdr;
    __u64 on_cpu_ns;
    __u64 runqueue_ns;
    __u64 off_cpu_ns;
    __u32 next_pid;
    __u32 next_tid;
};

// Page fault event (24 bytes total).
// The major/minor flag is stored in hdr.pad[0] to keep this hot event header-only.
struct page_fault_event {
    struct event_header hdr;
};

// FD event (8 bytes total).
// Userspace only counts open/close events, so keep just the fields needed to
// reconstruct the BasicDimension and event tag.
struct fd_event {
    __u32 pid;
    __u8  event_type;
    __u8  client_type;
    __u8  pad[2];
};

// Scheduler runqueue event (40 bytes total).
// cpu_id is stored in hdr.pad[0..3] (little-endian).
struct sched_runqueue_event {
    struct event_header hdr;
    __u64 runqueue_ns;
    __u64 off_cpu_ns;
};

// Block merge event (32 bytes total).
struct block_merge_event {
    struct event_header hdr;
    __u32 bytes;
    __u8  rw; // 0=read, 1=write
    __u8  pad[3];
};

// TCP retransmit event (40 bytes total).
struct tcp_retransmit_event {
    struct event_header hdr;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u8  pad[8];
};

// TCP state change event (24 bytes total).
// The aggregated pipeline only counts transitions, so this stays header-only.
struct tcp_state_event {
    struct event_header hdr;
};

// Memory reclaim/compaction event (32 bytes total).
struct mem_latency_event {
    struct event_header hdr;
    __u64 duration_ns;
};

// Swap event (32 bytes total).
struct swap_event {
    struct event_header hdr;
    __u64 pages;
};

// OOM kill event (24 bytes total).
// The aggregated pipeline only counts OOM kills, so this stays header-only.
struct oom_kill_event {
    struct event_header hdr;
};

// Process exit event (24 bytes total).
// The aggregated pipeline only counts exits and uses the header TID for
// scheduler cleanup, so no extra payload is required.
struct process_exit_event {
    struct event_header hdr;
};

// Syscall entry tracking key.
struct syscall_key {
    __u64 pid_tgid;
};

// Syscall entry value.
struct syscall_val {
    __u64 ts;
    __u8  client_type;
    __u8  pad[7];
};

// Block I/O request tracking.
struct req_key {
    __u32 dev;
    __u32 nr_sector;
    __u64 sector;
    __u8  rw;
    __u8  pad[3];
};

struct req_val {
    __u64 ts;
    __u32 pid;
    __u32 tid;
    __u8  client_type;
    __u8  pad[3];
};

// Network socket metadata tracking (8 bytes).
// kretprobe handlers run on the same task, so pid/tid and timestamps can be
// recovered at return time instead of being copied through the map value.
struct net_recv_val {
    __u16 sport;
    __u16 dport;
    __u8  client_type;
    __u8  transport;
    __u8  pad[2];
};

// TCP send tracking (16 bytes).
struct net_send_val {
    __u16 sport;
    __u16 dport;
    __u8  client_type;
    __u8  transport;
    __u8  pad[2];
    __u32 srtt_us;
    __u32 snd_cwnd;
};

// Tracepoint context structs (non-CO-RE). Defined here (outside vmlinux.h)
// so they are NOT preserve_access_index.
struct trace_event_raw_block_rq_local {
    __u64 unused;
    __u32 dev;
    __u64 sector;
    __u32 nr_sector;
    __u32 bytes;
    char rwbs[8];
};

struct trace_event_raw_sched_wakeup_local {
    __u64 unused;
    char comm[16];
    int pid;
    int prio;
    int success;
    int target_cpu;
};

struct trace_event_raw_oom_kill_local {
    __u64 unused;
    char comm[16];
    int pid;
    int tgid;
    unsigned long totalpages;
};

#endif /* __OBSERVOOR_H */
