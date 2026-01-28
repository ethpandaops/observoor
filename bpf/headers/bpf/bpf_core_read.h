/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * BPF CO-RE (Compile Once - Run Everywhere) read helpers for observoor.
 */
#ifndef __BPF_CORE_READ_H__
#define __BPF_CORE_READ_H__

/*
 * BPF_CORE_READ - Read a field from a kernel structure using
 * bpf_probe_read for portability.
 *
 * Usage:
 *   __u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
 */
#define BPF_CORE_READ(src, a) ({                        \
    typeof((src)->a) __val;                             \
    bpf_probe_read(&__val, sizeof(__val),               \
                   &(src)->a);                          \
    __val;                                              \
})

#define BPF_CORE_READ_INTO(dst, src, a) ({              \
    bpf_probe_read((dst), sizeof(*(dst)),               \
                   &(src)->a);                          \
})

#define bpf_core_read(dst, sz, src) \
    bpf_probe_read(dst, sz, src)

#endif /* __BPF_CORE_READ_H__ */
