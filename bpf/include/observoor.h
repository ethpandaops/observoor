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
    EVENT_TCP_METRICS        = 20,
    EVENT_MEM_RECLAIM        = 21,
    EVENT_MEM_COMPACTION     = 22,
    EVENT_SWAP_IN            = 23,
    EVENT_SWAP_OUT           = 24,
    EVENT_OOM_KILL           = 25,
    EVENT_PROCESS_EXIT       = 26,
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

// Syscall event (48 bytes total).
struct syscall_event {
    struct event_header hdr;
    __u64 latency_ns;
    __s64 ret;
    __u32 syscall_nr;
    __s32 fd;
};

// Disk I/O event (48 bytes total).
struct disk_io_event {
    struct event_header hdr;
    __u64 latency_ns;
    __u32 bytes;
    __u8  rw; // 0=read, 1=write
    __u8  pad[3];
    __u32 queue_depth;
    __u32 dev; // Block device ID (major:minor encoded)
};

// Network I/O event (48 bytes total).
struct net_io_event {
    struct event_header hdr;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u8  direction;    // 0=TX, 1=RX
    __u8  has_metrics;  // 1 if srtt_us/snd_cwnd are populated
    __u8  pad[2];
    __u32 srtt_us;      // Smoothed RTT (0 when has_metrics==0)
    __u32 snd_cwnd;     // Congestion window (0 when has_metrics==0)
};

// Scheduler event (40 bytes total).
struct sched_event {
    struct event_header hdr;
    __u64 on_cpu_ns;
    __u8  voluntary;
    __u8  pad[7];
};

// Page fault event (40 bytes total).
struct page_fault_event {
    struct event_header hdr;
    __u64 address;
    __u8  major;
    __u8  pad[7];
};

// FD event (96 bytes total).
struct fd_event {
    struct event_header hdr;
    __s32 fd;
    __u8  pad[4];
    char  filename[64];
};

// Scheduler runqueue event (40 bytes total).
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

// TCP state change event (40 bytes total).
struct tcp_state_event {
    struct event_header hdr;
    __u16 sport;
    __u16 dport;
    __u8  new_state;
    __u8  old_state;
    __u8  pad[10];
};

// TCP metrics event (40 bytes total).
struct tcp_metrics_event {
    struct event_header hdr;
    __u32 srtt_us;
    __u32 snd_cwnd;
    __u16 sport;
    __u16 dport;
    __u8  pad[4];
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

// OOM kill event (32 bytes total).
struct oom_kill_event {
    struct event_header hdr;
    __u32 target_pid;
    __u8  pad[4];
};

// Process exit event (32 bytes total).
struct process_exit_event {
    struct event_header hdr;
    __u32 exit_code;
    __u8  pad[4];
};

// Syscall entry tracking key.
struct syscall_key {
    __u64 pid_tgid;
};

// Syscall entry value.
struct syscall_val {
    __u64 ts;
    __s32 fd;
    __u32 pad;
};

// Openat filename capture.
struct openat_val {
    __u64 ts;
    char  filename[64];
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

// Network recv tracking (24 bytes, 8-byte aligned).
struct net_recv_val {
    __u64 ts;
    __u16 sport;
    __u16 dport;
    __u32 pid;
    __u8  client_type;
    __u8  pad[7];
};

// Page fault tracking.
struct fault_val {
    __u64 ts;
    __u64 address;
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
