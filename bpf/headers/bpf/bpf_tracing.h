/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * BPF tracing helpers for observoor.
 *
 * Provides architecture-aware BPF_KPROBE and BPF_KRETPROBE macros
 * with proper argument extraction from pt_regs.
 */
#ifndef __BPF_TRACING_H__
#define __BPF_TRACING_H__

/* Architecture-specific register access. */
#if defined(__TARGET_ARCH_x86)

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x)   ((x)->sp)
#define PT_REGS_FP(x)    ((x)->bp)
#define PT_REGS_RC(x)    ((x)->ax)
#define PT_REGS_SP(x)    ((x)->sp)
#define PT_REGS_IP(x)    ((x)->ip)

#elif defined(__TARGET_ARCH_arm64)

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RET(x)   ((x)->regs[30])
#define PT_REGS_FP(x)    ((x)->regs[29])
#define PT_REGS_RC(x)    ((x)->regs[0])
#define PT_REGS_SP(x)    ((x)->sp)
#define PT_REGS_IP(x)    ((x)->pc)

#else
#error "Unsupported target architecture for BPF tracing."
#endif

/*
 * Variadic argument handling macros.
 */
#define ___bpf_concat(a, b) a ## b
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)

/* Count macro arguments (up to 12). */
#define ___bpf_narg(...) \
    ___bpf_narg_(__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define ___bpf_narg_(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, N, ...) N

/*
 * Argument casting from pt_regs for BPF_KPROBE.
 * Each macro passes ctx plus the extracted arguments.
 */
#define ___bpf_karg0()           ctx
#define ___bpf_karg1(x)          ___bpf_karg0(), (unsigned long long)PT_REGS_PARM1(ctx)
#define ___bpf_karg2(x, args...) ___bpf_karg1(args), (unsigned long long)PT_REGS_PARM2(ctx)
#define ___bpf_karg3(x, args...) ___bpf_karg2(args), (unsigned long long)PT_REGS_PARM3(ctx)
#define ___bpf_karg4(x, args...) ___bpf_karg3(args), (unsigned long long)PT_REGS_PARM4(ctx)
#define ___bpf_karg5(x, args...) ___bpf_karg4(args), (unsigned long long)PT_REGS_PARM5(ctx)
#define ___bpf_kargs(args...)    ___bpf_apply(___bpf_karg, ___bpf_narg(args))(args)

/*
 * BPF_KPROBE - kprobe with named function arguments.
 *
 * Usage:
 *   SEC("kprobe/tcp_sendmsg")
 *   int BPF_KPROBE(my_kprobe, struct sock *sk, struct msghdr *msg, size_t size)
 *   {
 *       // sk, msg, size are extracted from pt_regs automatically
 *   }
 */
#define BPF_KPROBE(name, args...)                                       \
name(struct pt_regs *ctx);                                              \
static __always_inline typeof(name(0))                                  \
____##name(struct pt_regs *ctx, ##args);                                \
typeof(name(0)) name(struct pt_regs *ctx)                               \
{                                                                       \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")              \
    return ____##name(___bpf_kargs(args));                              \
    _Pragma("GCC diagnostic pop")                                       \
}                                                                       \
static __always_inline typeof(name(0))                                  \
____##name(struct pt_regs *ctx, ##args)

/*
 * Return value extraction for BPF_KRETPROBE.
 */
#define ___bpf_kretarg0()        ctx
#define ___bpf_kretarg1(x)       ___bpf_kretarg0(), (unsigned long long)PT_REGS_RC(ctx)
#define ___bpf_kretargs(args...) ___bpf_apply(___bpf_kretarg, ___bpf_narg(args))(args)

/*
 * BPF_KRETPROBE - kretprobe with named return value.
 *
 * Usage:
 *   SEC("kretprobe/tcp_recvmsg")
 *   int BPF_KRETPROBE(my_kretprobe, int ret)
 *   {
 *       // ret is extracted from pt_regs return register
 *   }
 */
#define BPF_KRETPROBE(name, args...)                                    \
name(struct pt_regs *ctx);                                              \
static __always_inline typeof(name(0))                                  \
____##name(struct pt_regs *ctx, ##args);                                \
typeof(name(0)) name(struct pt_regs *ctx)                               \
{                                                                       \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")              \
    return ____##name(___bpf_kretargs(args));                           \
    _Pragma("GCC diagnostic pop")                                       \
}                                                                       \
static __always_inline typeof(name(0))                                  \
____##name(struct pt_regs *ctx, ##args)

#endif /* __BPF_TRACING_H__ */
