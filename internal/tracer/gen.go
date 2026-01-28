//go:build ignore

package tracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target amd64 -type syscall_event -type disk_io_event -type net_io_event -type sched_event -type page_fault_event -type fd_event observoor ../../bpf/observoor.c -- -I../../bpf/headers -I../../bpf/include
