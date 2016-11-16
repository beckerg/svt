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
#include "worker.h"

typedef void (*sigfunc_t)(int);

volatile sig_atomic_t sigxxx_cnt;
volatile sig_atomic_t sigint_cnt;
volatile sig_atomic_t sigchld_cnt;

static char rng_state[256];

const char *op2txt[] = {
    "null", "init", "loop", "done", "open", "close", "verify", "deadlk",
    "lock1", "lock2", "unlock1", "unlock2", "get1", "get2", "put1", "put2"
};

/* Note that we received a signal.
 */
static RETSIGTYPE
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
static int
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
worker_status(const char *mode, worker_t *worker, struct timeval *tv_tzero, struct timeval *tv_start)
{
    ulong tot_gets, tot_puts, tot_msecs;
    ulong itv_gets, itv_puts, itv_msecs;
    struct timeval tv_now, tv_diff;
    ulong msecs;
    bool once;
    int i;

    /* Stabilize the active stats.
     */
    for (i = 0; i < cf.cf_jobs_max; ++i) {
        worker[i].w_fstats.s_gets = worker[i].w_astats.s_gets;
        worker[i].w_fstats.s_puts = worker[i].w_astats.s_puts;
    }

    once = (verbosity > 0);
    if (!once && headers && tv_tzero && tv_start) {
        once = ((tv_start->tv_sec - tv_tzero->tv_sec) % 23) == 0;
    }

    if (once) {
        printf("\n%-5s %3s %6s %4s %3s %7s %7s %7s %10s %10s %10s %10s\n",
               "MODE", "TID", "PID", "S", "C", "OP",
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

        printf("%-5s %3d %6d %4s %3u %7s %7lu %7lu %10lu %10lu %10ld %10ld\n",
               mode, i, worker->w_pid, status, code, op2txt[worker->w_op],
               gets, puts, stats->s_gets, stats->s_puts, itv_msecs,
               worker->w_stop.tv_sec);
    }

    printf("%-5s %3s %6d %4s %3u %7s %7lu %7lu %10lu %10lu %10ld %10ld\n",
           mode, "all", getpid(), "-", 0, "total",
           itv_gets, itv_puts, tot_gets, tot_puts, tot_msecs,
           tv_now.tv_sec);
}

void
worker_run(const char *mode, worker_init_t *init, worker_fini_t *fini, worker_run_t *run, tb_ops_t *ops)
{
    struct timeval tv_tzero, tv_next, tv_now, tv_interval;
    size_t worker_base_sz;
    worker_t *worker_base;
    uint recs_per_job;
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

    worker_base_sz = sizeof(*worker_base) * cf.cf_jobs_max;

    int flags = MAP_ANON | MAP_SHARED;

    worker_base = mmap(NULL, worker_base_sz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (worker_base == MAP_FAILED) {
        eprint("%s: mmap(): %s\n", __func__, strerror(errno));
        exit(EX_OSERR);
    }

    if ((uintptr_t)worker_base & (getpagesize() - 1)) {
        eprint("%s: mmap returned non-page aligned address: %p\n", worker_base);
    }
    if (sizeof(*worker_base) & (getpagesize() - 1)) {
        eprint("%s: sizeof(worker_t) not page aligned: %zu\n", sizeof(*worker_base));
    }

    setpriority(PRIO_PROCESS, 0, -10);

    signal_reliable(SIGINT, sigxxx_isr);
    signal_reliable(SIGCHLD, sigxxx_isr);

    gettimeofday(&tv_tzero, NULL);
    tv_next = tv_tzero;

    sigxxx_cnt = 0;
    sigint_cnt = 0;
    sigchld_cnt = 0;

    nworkers = 0;

    /* Divy up the record space.
     */
    recs_per_job = (cf.tb_rec_max / cf.cf_jobs_max);
    if (recs_per_job * cf.cf_jobs_max < cf.tb_rec_max) {
        recs_per_job += 1;
    }

    for (i = 0; i < cf.cf_jobs_max; ++i) {
        worker_t *worker = worker_base + i;

        worker->w_id = i;
        worker->w_frec = i * recs_per_job;
        worker->w_lrec = worker->w_frec + recs_per_job;
        if (worker->w_lrec > cf.tb_rec_max) {
            worker->w_lrec = cf.tb_rec_max;
        }
    }

    if (init) {
        init(worker_base, ops);
    }

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
            run(worker, ops);
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
            worker_status(mode, worker_base, &tv_tzero, &tv_now);
        }
        else if (nfds > 0) {
            if (fds[0].revents & POLLIN) {
                char buf[32];
                ssize_t cc;

                cc = read(fds[0].fd, buf, sizeof(buf));
                if (cc > 0) {
                    worker_status(mode, worker_base, &tv_tzero, &tv_now);
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

    worker_status(mode, worker_base, &tv_tzero, &tv_now);

    sigprocmask(SIG_SETMASK, &sigmask_orig, NULL);

    if (fini) {
        fini(worker_base + i, ops);
    }

    setpriority(PRIO_PROCESS, 0, 0);
    munmap(worker_base, worker_base_sz);
}
