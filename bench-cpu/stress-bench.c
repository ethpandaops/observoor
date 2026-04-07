/*
 * stress-bench: Deterministic syscall workload for observoor CPU overhead measurement.
 *
 * Generates a fixed number of syscalls across multiple threads to trigger all
 * major observoor probe groups: file I/O, network, scheduler, memory, futex.
 *
 * Usage: stress-bench [--wait-for-signal] [iterations]
 *   --wait-for-signal  Create /tmp/stress-bench-ready, block until SIGUSR1
 *   iterations         Number of iterations per thread (default: 50000)
 *
 * Process name in /proc/<pid>/comm will be "stress-bench" (12 chars, under 15 limit).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_THREADS 4
#define BUF_SIZE 4096
#define UDP_PORT 19999
#define READY_FILE "/tmp/stress-bench-ready"

static volatile int g_start = 0;
static int g_iterations = 50000;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static void sigusr1_handler(int sig) {
    (void)sig;
    g_start = 1;
}

/* Inline futex call — triggers syscall_futex probes. */
static void do_futex_wait_timeout(void) {
    int futex_word = 0;
    struct timespec ts = {0, 0};
    syscall(SYS_futex, &futex_word, FUTEX_WAIT, 0, &ts, NULL, 0);
}

static void *worker(void *arg) {
    int thread_id = *(int *)arg;
    char path[128];
    char buf[BUF_SIZE];
    int udp_fd;
    struct sockaddr_in addr;

    memset(buf, 'A' + (thread_id % 26), BUF_SIZE);
    snprintf(path, sizeof(path), "/tmp/stress-bench-%d-%d", getpid(), thread_id);

    /* Create a UDP socket for network I/O probes. */
    udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    for (int i = 0; i < g_iterations; i++) {
        /* File I/O: triggers fd_open, syscall_write, syscall_fsync, syscall_read, fd_close, disk_io. */
        int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, buf, BUF_SIZE);
            fsync(fd);
            lseek(fd, 0, SEEK_SET);
            read(fd, buf, BUF_SIZE);
            close(fd);
        }

        /* mmap/munmap: triggers syscall_mmap, page_fault. */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            /* Touch the page to trigger a page fault. */
            ((volatile char *)p)[0] = 1;
            munmap(p, 4096);
        }

        /* UDP sendto: triggers net_tx probes. */
        sendto(udp_fd, buf, 64, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));

        /* UDP recvfrom (non-blocking, will EAGAIN): triggers net_rx probe entry. */
        recvfrom(udp_fd, buf, 64, MSG_DONTWAIT, NULL, NULL);

        /* Futex: triggers syscall_futex probe. */
        do_futex_wait_timeout();

        /* Mutex: triggers futex + sched_switch under contention. */
        pthread_mutex_lock(&g_mutex);
        pthread_mutex_unlock(&g_mutex);
    }

    close(udp_fd);
    unlink(path);
    return NULL;
}

int main(int argc, char *argv[]) {
    int wait_for_signal = 0;
    int arg_idx = 1;

    /* Parse arguments. */
    if (argc > arg_idx && strcmp(argv[arg_idx], "--wait-for-signal") == 0) {
        wait_for_signal = 1;
        arg_idx++;
    }
    if (argc > arg_idx) {
        g_iterations = atoi(argv[arg_idx]);
        if (g_iterations <= 0) {
            fprintf(stderr, "usage: stress-bench [--wait-for-signal] [iterations]\n");
            return 1;
        }
    }

    /* If --wait-for-signal, create ready file and block until SIGUSR1. */
    if (wait_for_signal) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sigusr1_handler;
        sigaction(SIGUSR1, &sa, NULL);

        FILE *f = fopen(READY_FILE, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());
            fclose(f);
        }

        fprintf(stderr, "stress-bench: waiting for SIGUSR1 (PID %d)\n", getpid());
        while (!g_start) {
            pause();
        }
        fprintf(stderr, "stress-bench: starting workload (%d iterations x %d threads)\n",
                g_iterations, NUM_THREADS);
    }

    /* Create a UDP listener so sendto doesn't get ECONNREFUSED. */
    int listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(UDP_PORT);
    listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));

    /* Spawn worker threads. */
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, worker, &thread_ids[i]);
    }

    /* Wait for all threads. */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    close(listen_fd);
    unlink(READY_FILE);

    printf("DONE %d\n", g_iterations * NUM_THREADS);
    return 0;
}
