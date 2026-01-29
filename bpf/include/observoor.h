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

// Disk I/O event (40 bytes total).
struct disk_io_event {
    struct event_header hdr;
    __u64 latency_ns;
    __u32 bytes;
    __u8  rw; // 0=read, 1=write
    __u8  pad[3];
};

// Network I/O event (40 bytes total).
struct net_io_event {
    struct event_header hdr;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u8  direction; // 0=TX, 1=RX
    __u8  pad[3];
    __u32 pad2;
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

#endif /* __OBSERVOOR_H */
