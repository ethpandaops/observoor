/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux.h stub for development and CI.
 *
 * For production builds on a real Linux host, generate this from
 * the running kernel's BTF:
 *
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * Or use: ./scripts/generate-vmlinux.sh
 *
 * This stub provides only the types referenced by observoor.c.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

typedef unsigned char __u8;
typedef short int __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef _Bool bool;

typedef unsigned long size_t;

/* Architecture-specific pt_regs. */
#if defined(__TARGET_ARCH_x86)

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

#elif defined(__TARGET_ARCH_arm64)

struct pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

#else
#error "Unsupported target architecture. Define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64."
#endif

/* Socket common. */
struct __sk_common {
    unsigned short skc_family;
    unsigned char skc_state;
    unsigned short skc_num;       /* source port */
    unsigned short skc_dport;     /* destination port (network byte order) */
};

struct sock {
    struct __sk_common __sk_common;
    unsigned char sk_state;
};

struct sk_buff {
    unsigned int len;
};

struct tcp_sock {
    struct sock sk;
    unsigned int snd_cwnd;
    unsigned int srtt_us;
};

struct msghdr;
struct vm_area_struct;

/* Tracepoint structs. */
struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    unsigned long long unused;
    long id;
    long ret;
};

struct trace_event_raw_sched_switch {
    unsigned long long unused;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

struct trace_event_raw_sched_wakeup {
    unsigned long long unused;
    char comm[16];
    int pid;
    int prio;
    int success;
    int target_cpu;
};

struct trace_event_raw_block_rq {
    unsigned long long unused;
    unsigned int dev;
    unsigned long long sector;
    unsigned int nr_sector;
    unsigned int bytes;
    char rwbs[8];
};

struct trace_event_raw_oom_kill {
    unsigned long long unused;
    char comm[16];
    int pid;
    int tgid;
    unsigned long totalpages;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
