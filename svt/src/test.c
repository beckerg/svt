/*
 * Copyright (c) 2015,2016 Greg Becker.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include "system.h"
#include "cf.h"
#include "rtck.h"
#include "tb.h"
#include "test.h"
#include "main.h"

#ifndef ulong
typedef unsigned long ulong;
#endif

typedef void (*sigfunc_t)(int);

static volatile sig_atomic_t sigxxx_cnt;
static volatile sig_atomic_t sigint_cnt;
static volatile sig_atomic_t sigchld_cnt;

static char rng_state[256];

typedef enum {
    OP_NULL,
    OP_LOOP,
    OP_DONE,
    OP_PAD,
    OP_OPEN,
    OP_CLOSE,
    OP_VERIFY,
    OP_DEADLOCK,
    OP_WLOCK1,
    OP_WLOCK2,
    OP_WUNLOCK1,
    OP_WUNLOCK2,
    OP_GET1,
    OP_GET2,
    OP_PUT1,
    OP_PUT2,
} op_t;

/* Worker stats
 */
typedef struct {
    ulong           s_gets;     // Number of gets/reads done by this worker
    ulong           s_puts;     // Number of puts/writes done by this worker
    ulong           s_recs;     // Number of records swapped by this worker
} worker_stats_t;

/* Worker state
 */
typedef struct {
    __attribute__((aligned(PAGE_SIZE)))
    pid_t           w_pid;      // The worker's pid
    struct timeval  w_start;
    struct timeval  w_stop;

    worker_stats_t  w_astats;   // Active stats
    worker_stats_t  w_fstats;   // Frozen/stabilized stats
    worker_stats_t  w_ostats;   // Old/previous stats

    op_t            w_op;       // Current operation
    bool            w_exited;   // 'true' if worker exited
    int             w_status;   // wait3() status code
    struct rusage   w_rusage;
} worker_t;

static const char *op2txt[] = {
    "init", "loop", "done", "pad", "open", "close", "verify", "deadlk",
    "lock1", "lock2", "unlock1", "unlock2", "get1", "get2", "put1", "put2"
};

/* Note that we received a signal.
 */
RETSIGTYPE
sigxxx_isr(int sig)
{
    if (sig == SIGINT)
        ++sigint_cnt;
    else if (sig == SIGCHLD)
        ++sigchld_cnt;
    else
        ++sigxxx_cnt;
}

/* Reliable signal.
 */
int
signal_reliable(int signo, sigfunc_t func)
{
    struct sigaction nact;

    bzero(&nact, sizeof(nact));

    nact.sa_handler = func;
    sigemptyset(&nact.sa_mask);
    nact.sa_flags |= SA_RESTART;

    return sigaction(signo, &nact, NULL);
}

static void
test_worker(tb_ops_t *ops, worker_t *worker)
{
    worker_stats_t *stats;
    tb_rec_t *r1_base, *r2_base;
    time_t runtime_max;
    uint range_max;
    uint range_min;
    int i;

    range_max = cf.cf_range_max;
    range_min = cf.cf_range_min;

    r1_base = malloc(cf.tb_rec_sz * range_max);
    r2_base = malloc(cf.tb_rec_sz * range_max);
    if (!r1_base || !r2_base) {
        abort();
    }

    gettimeofday(&worker->w_start, NULL);
    worker->w_stop = worker->w_start;

    runtime_max = cf.cf_runtime_max;

    if (runtime_max > 0) {
        dprint(3, "pid %d testing %s for %ld seconds...\n",
               worker->w_pid, cf.tb_path, cf.cf_runtime_max);
        runtime_max += worker->w_start.tv_sec;
    }
    else {
        dprint(3, "pid %d testing %s until interrupted...\n",
               worker->w_pid, cf.tb_path);
    }

    stats = &worker->w_astats;

    while (1) {
        tb_fd_t *xfd1, *xfd2;
        uint32_t id1, id2;
        bool update;
        u_int range;

        /* Select two non-overlapping ranges within [0, (rec_max - range)].
         *
         * Note: If path is a dir then range_max will always be 1 so that
         * we don't have to manage opening large swaths of files.
         */
        range = (random() % (range_max - range_min + 1)) + range_min;

        id1 = random() % (cf.tb_rec_max - range);

        do {
            id2 = random() % (cf.tb_rec_max - range);
        } while (!(id2 > id1 + range || id1 > id2 + range));

        if (id1 > id2) {
            uint32_t tmp = id1;

            id1 = id2;
            id2 = tmp;
        }

        while (1) {
            worker->w_op = OP_WLOCK1;
            if (0 == rtck_wlock(id1, range)) {
                worker->w_op = OP_WLOCK2;
                if (0 == rtck_wlock(id2, range)) {
                    break;
                }

                dprint(2, "deadlock %5d  [%7u %7u %7u]\n", worker->w_pid, id1, id2, range);
                worker->w_op = OP_DEADLOCK;
                rtck_wunlock(id1, range);
                usleep(131);
            }
        }

        dprint(3, "swapping %5d  [%7u %7u %7u]\n", worker->w_pid, id1, id2, range);

        update = ((random() % 100) < cf.cf_swaps_pct);

        worker->w_op = OP_OPEN;
        xfd1 = ops->tb_open(cf.tb_path, O_RDWR, id1);
        xfd2 = ops->tb_open(cf.tb_path, O_RDWR, id2);

        worker->w_op = OP_GET1;
        ops->tb_get(r1_base, id1, range, xfd1);

        worker->w_op = OP_GET2;
        ops->tb_get(r2_base, id2, range, xfd2);

        stats->s_gets += 2;

        worker->w_op = OP_VERIFY;

        for (i = 0; i < range; ++i) {
            tb_rec_t *r1 = (tb_rec_t *)((char *)r1_base + (i * cf.tb_rec_sz));
            tb_rec_t *r2 = (tb_rec_t *)((char *)r2_base + (i * cf.tb_rec_sz));

            ops->tb_verify(r1);
            ops->tb_verify(r2);

            rtck_hash_verify(r1->tr_id, r1->tr_hash);
            rtck_hash_verify(r2->tr_id, r2->tr_hash);

            r1->tr_id = id2 + i;
            r2->tr_id = id1 + i;

            if (update) {
                ops->tb_update(r1);
                ops->tb_update(r2);

                rtck_hash_put(r1->tr_id, r1->tr_hash);
                rtck_hash_put(r2->tr_id, r2->tr_hash);
            }
        }

        if (update) {
            worker->w_op = OP_PUT1;
            ops->tb_put(r1_base, range, xfd2);

            worker->w_op = OP_PUT2;
            ops->tb_put(r2_base, range, xfd1);

            stats->s_puts += 2;
        }

        worker->w_op = OP_CLOSE;
        ops->tb_close(xfd2);
        ops->tb_close(xfd1);

        worker->w_op = OP_WUNLOCK1;
        rtck_wunlock(id2, range);

        worker->w_op = OP_WUNLOCK2;
        rtck_wunlock(id1, range);

        worker->w_op = OP_LOOP;

        stats->s_recs += range * 2;
        gettimeofday(&worker->w_stop, NULL);

        if (runtime_max > 0 || sigint_cnt > 0) {
            if (worker->w_stop.tv_sec >= runtime_max || sigint_cnt > 0) {
                break;
            }
        }
    }

    worker->w_op = OP_DONE;

    gettimeofday(&worker->w_stop, NULL);

    free(r1_base);
    free(r2_base);
}

static void
test_status(worker_t *worker, struct timeval *tv_tzero, struct timeval *tv_start)
{
    ulong tot_gets, tot_puts, tot_msecs;
    ulong itv_gets, itv_puts, itv_msecs;
    struct timeval tv_now, tv_diff;
    ulong msecs;
    int i;

    /* Stabilize the active stats.
     */
    for (i = 0; i < cf.cf_jobs_max; ++i) {
        worker[i].w_fstats.s_gets = worker[i].w_astats.s_gets;
        worker[i].w_fstats.s_puts = worker[i].w_astats.s_puts;
    }

    if (fheaders) {
        printf("\n%3s %6s %4s %3s %7s %7s %7s %10s %10s %10s %10s\n",
               "ID", "PID", "S", "C", "OP",
               "iGETS", "iPUTS", "tGETS", "tPUTS", "MSECS", "EPOCH");
    }

    tot_gets = tot_puts = 0;
    itv_gets = itv_puts = 0;

    gettimeofday(&tv_now, NULL);
    timersub(&tv_now, tv_start, &tv_diff);
    itv_msecs = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
    itv_msecs /= 1000;

    timersub(&tv_now, tv_tzero, &tv_diff);
    tot_msecs = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
    tot_msecs /= 1000;

    for (i = 0; i < cf.cf_jobs_max; ++i, ++worker) {
        worker_stats_t *stats, *ostats;
        const char *status;
        ulong gets, puts;
        uint code;

        /* Sum total ops for all workers.
         */
        stats = &worker->w_fstats;
        tot_gets += stats->s_gets;
        tot_puts += stats->s_puts;

        /* Compute interval ops for this worker.
         */
        ostats = &worker->w_ostats;
        gets = stats->s_gets - ostats->s_gets;
        puts = stats->s_puts - ostats->s_puts;

        /* Sum interval ops for all workers for this interval.
         */
        itv_gets += gets;
        itv_puts += puts;

        *ostats = *stats;

        if (verbosity < 1)
            continue;

        status = "run";
        code = 0;

        if (worker->w_exited) {
            if (WIFEXITED(worker->w_status)) {
                code = WEXITSTATUS(worker->w_status);
                status = "exit";
            } else if (WIFSIGNALED(worker->w_status)) {
                code = WTERMSIG(worker->w_status);
                status = "sig";

                if (WCOREDUMP(worker->w_status)) {
                    status = "core";
                }
            }
        }

        printf("%3d %6d %4s %3u %7s %7lu %7lu %10lu %10lu %10ld %10ld\n",
               i, worker->w_pid, status, code, op2txt[worker->w_op],
               gets, puts, stats->s_gets, stats->s_puts, itv_msecs,
               worker->w_stop.tv_sec);
    }

    printf("%3s %6d %4s %3u %7s %7lu %7lu %10lu %10lu %10ld %10ld\n",
           "-", getpid(), "-", 0, "total",
           itv_gets, itv_puts, tot_gets, tot_puts, tot_msecs,
           tv_now.tv_sec);
}

void
test(void)
{
    struct timeval tv_tzero, tv_next, tv_now, tv_interval;
    size_t worker_base_sz;
    worker_t *worker_base;
    struct stat sb;
    tb_ops_t *ops;
    tb_fd_t *xfd0;
    int nworkers;
    tb_rec_t *r;
    int oflags;
    ssize_t cc;
    pid_t pid;
    int fd;
    int rc;
    int i;

    struct timespec ts_interval = { 0, 0 };
    struct timespec *timeoutp;
    sigset_t sigmask_block;
    sigset_t sigmask_orig;
    struct pollfd fds[2];

    initstate(time(NULL), rng_state, sizeof(rng_state));

    cf_load();
    rtck_open();

    assert(cf.tb_rec_max > 0);

    rc = stat(cf.tb_path, &sb);
    if (rc) {
        eprint("%s: stat(%s): %s\n", __func__, cf.tb_path, strerror(errno));
        exit(EX_USAGE);
    }

    r = malloc(cf.tb_rec_sz);
    if (!r) {
        eprint("%s: malloc(%ld): out of memory\n", __func__, cf.tb_rec_sz);
        exit(EX_OSERR);
    }

    if (S_ISDIR(sb.st_mode)) {
        ops = tb_find("dir");
        cf.cf_range_max = 1;
        cf.cf_range_min = 1;
    }
    else if (S_ISREG(sb.st_mode)) {
        ops = tb_find("file");
    }
    else {
        ops = tb_find("dev");
    }

    /* Open the test bed.
     */
    xfd0 = ops->tb_open(cf.tb_path, O_RDWR | O_DIRECT, 0);

    worker_base_sz = sizeof(*worker_base) * cf.cf_jobs_max;

    int flags = MAP_ANON | MAP_SHARED;

    worker_base = mmap(NULL, worker_base_sz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (worker_base == MAP_FAILED) {
        eprint("%s: mmap(): %s\n", __func__, strerror(errno));
        exit(EX_OSERR);
    }

    if ((uintptr_t)worker_base & (PAGE_SIZE - 1)) {
        eprint("%s: mmap returned non-page aligned address: %p\n", worker_base);
    }
    if (sizeof(*worker_base) & (PAGE_SIZE - 1)) {
        eprint("%s: sizeof(worker_t) not page aligned: %zu\n", sizeof(*worker_base));
    }

    setpriority(PRIO_PROCESS, 0, -10);

    signal_reliable(SIGINT, sigxxx_isr);
    signal_reliable(SIGCHLD, sigxxx_isr);

    gettimeofday(&tv_tzero, NULL);
    tv_next = tv_tzero;

    nworkers = 0;

    for (i = 0; i < cf.cf_jobs_max; ++i) {
        worker_t *worker = worker_base + i;

        pid = fork();

        switch (pid) {
        case -1:
            eprint("%s: fork(): %s\n", __func__, strerror(errno));
            break;

        case 0:
            setpriority(PRIO_PROCESS, 0, -5);
            initstate(getpid(), rng_state, sizeof(rng_state));
            test_worker(ops, worker);
            _exit(0);

        default:
            worker->w_pid = pid;
            ++nworkers;
            break;
        }
    }

    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGCHLD);

    sigprocmask(SIG_BLOCK, &sigmask_block, &sigmask_orig);

    tv_interval.tv_sec = cf.cf_status_interval;
    tv_interval.tv_usec = 0;
    timeoutp = (cf.cf_status_interval > 0) ? &ts_interval : NULL;

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    while (nworkers > 0) {
        struct rusage rusage;
        int status;
        int nfds;
        int rc;

        /* First, gather status from all children who have something
         * to report, but don't block in wait3().
         */
        if (sigchld_cnt > 0) {
            pid = wait3(&status, WNOHANG, &rusage);

            if (pid > 0) {
                dprint(2, "reaped child %d, status 0x%x\n", pid, status);

                for (i = 0; i < cf.cf_jobs_max; ++i) {
                    worker_t *worker = worker_base + i;

                    if (worker->w_pid == pid) {
                        worker->w_status = status;
                        worker->w_rusage = rusage;

                        if (WIFEXITED(status) || WIFSIGNALED(status)) {
                            worker->w_exited = true;
                            --nworkers;
                        }
                        break;
                    }
                }
            } else if (pid == 0) {
                sigchld_cnt = 0; // All zombies reaped
            }
            else if (pid == -1) {
                if (errno == ECHILD) {
                    break; // All children have exited
                }

                eprint("%s: wait3(): %s\n", __func__, strerror(errno));
                sleep(1);
            }

            continue;
        }

        gettimeofday(&tv_now, NULL);

        if (timeoutp) {
            struct timeval tv_diff;

            while (timercmp(&tv_next, &tv_now, <)) {
                timeradd(&tv_next, &tv_interval, &tv_next);
            }
            timersub(&tv_next, &tv_now, &tv_diff);

            timeoutp->tv_sec = tv_diff.tv_sec;
            timeoutp->tv_nsec = tv_diff.tv_usec * 1000;
        }

        /* Wait in ppoll() until the timer expires or we catch a signal.
         */
        nfds = ppoll(fds, 1, timeoutp, &sigmask_orig);

        if (nfds == 0) {
            test_status(worker_base, &tv_tzero, &tv_now);
        }
        else if (nfds > 0) {
            if (fds[0].revents & POLLIN) {
                char buf[32];
                ssize_t cc;

                cc = read(fds[0].fd, buf, sizeof(buf));
                if (cc > 0) {
                    test_status(worker_base, &tv_tzero, &tv_now);
                }
                else if (cc == 0) {
                    kill(0, SIGINT);
                    fds[0].fd = -1;
                }
                else {
                    eprint("%s: read: %s\n", __func__, strerror(errno));
                    sleep(1);
                }
            }
        }
    }

    test_status(worker_base, &tv_tzero, &tv_now);

    sigprocmask(SIG_SETMASK, &sigmask_orig, NULL);

    munmap(worker_base, worker_base_sz);

    ops->tb_close(xfd0);
    rtck_close();
}
