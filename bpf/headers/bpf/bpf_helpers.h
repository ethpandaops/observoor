/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Vendored BPF helpers for observoor.
 * Contains only the helpers and macros needed by this project.
 */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/* Map definition macros. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Section macro for placing programs, maps, and license. */
#define SEC(name) \
    _Pragma("GCC diagnostic push")                      \
    _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"") \
    __attribute__((section(name), used))                 \
    _Pragma("GCC diagnostic pop")

/* Map update flags. */
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

/* BPF map types (values from linux/bpf.h). */
enum {
    BPF_MAP_TYPE_HASH       = 1,
    BPF_MAP_TYPE_ARRAY      = 2,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH   = 9,
    BPF_MAP_TYPE_RINGBUF    = 27,
};

/* Compiler attributes. */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

/*
 * BPF helper function declarations.
 * Only helpers used by observoor are included.
 * Numbers are BPF helper IDs from include/uapi/linux/bpf.h.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static long (*bpf_probe_read)(void *dst, __u32 size,
                              const void *unsafe_ptr) = (void *) 4;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u32 (*bpf_get_prandom_u32)(void) = (void *) 7;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *) 8;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_probe_read_user)(void *dst, __u32 size,
                                   const void *unsafe_ptr) = (void *) 112;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size,
                                       const void *unsafe_ptr) = (void *) 114;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *) 113;

/* Ring buffer helpers. */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
                                    __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;

#endif /* __BPF_HELPERS__ */
