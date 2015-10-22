/*
 * Copyright (c) 2015 Greg Becker.  All rights reserved.
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <ctype.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#else
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif

#if HAVE_STRING_H
#if !STDC_HEADERS && HAVE_MEMORY_H
#include <memory.h>
#endif
#include <string.h>
#endif

#if HAVE_STRINGS_H
#include <strings.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#else
#if HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_ERRNO_H
#include <errno.h>
#endif

#include <assert.h>
#include <signal.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/select.h>
#include <math.h>

#include "cf.h"
#include "rtck.h"
#include "tb.h"
#include "test.h"
#include "main.h"

typedef void (*sigfunc_t)(int);

static volatile int sigcnt = 0;
static char rng_state[256];

typedef enum {
    OP_NULL,
    OP_WLOCK,
    OP_WUNLOCK,
    OP_DEADLOCK,
    OP_OPEN,
    OP_CLOSE,
    OP_GET,
    OP_PUT,
    OP_SWAP,
} op_t;

/* Worker state
 */
typedef struct {
    __attribute__((aligned(64)))
    pid_t           w_pid;      // The worker's pid
    struct timeval  w_start;
    struct timeval  w_stop;
    u_long          w_swaps;    // Number of swaps done by this worker
    u_long          w_recs;     // Number of records swapped by this worker

    op_t            w_op;       // Current operation
    int             w_exited;   // 'true' if worker exited
    int             w_status;   // wait3() status code
    struct rusage   w_rusage;
} worker_t;

static const char *op2txt[] = {
    "init", "lock", "unlock", "deadlk", "open", "close", "get", "put", "swap",
};

/* Note that we received a signal.
 */
RETSIGTYPE
signal_isr(int sig)
{
    ++sigcnt;
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

    if (SIGALRM == signo || SIGINT == signo) {
#ifdef SA_INTERRUPT
        nact.sa_flags |= SA_INTERRUPT;
#endif
    } else {
#ifdef SA_RESTART
        nact.sa_flags |= SA_RESTART;
#endif
    }

    return sigaction(signo, &nact, (struct sigaction *)0);
}

static void
test_worker(tb_ops_t *ops, u_int range_max, worker_t *worker)
{
    tb_rec_t *r1_base, *r2_base;
    time_t runtime_max;
    int i;

    r1_base = malloc(cf.tb_rec_sz * range_max);
    r2_base = malloc(cf.tb_rec_sz * range_max);
    if (!r1_base || !r2_base) {
        abort();
    }

    (void)gettimeofday(&worker->w_start, NULL);
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

    while (1) {
        tb_fd_t *xfd1, *xfd2;
        uint32_t id1, id2;
        u_int range;

        /* Select two non-overlapping ranges within [0, (rec_max - range)].
         *
         * Note: If path is a dir then range_max will always be 1 so that
         * we don't have to manage opening large swaths of files.
         */
        range = (random() % range_max) + 1;

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
            worker->w_op = OP_WLOCK;
            if (0 == rtck_wlock(id1, range)) {
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

        worker->w_op = OP_OPEN;
        xfd1 = ops->tb_open(cf.tb_path, O_RDWR, id1);
        xfd2 = ops->tb_open(cf.tb_path, O_RDWR, id2);

        worker->w_op = OP_GET;
        ops->tb_get(r1_base, id1, range, xfd1);
        ops->tb_get(r2_base, id2, range, xfd2);

        worker->w_op = OP_SWAP;

        for (i = 0; i < range; ++i) {
            tb_rec_t *r1 = (tb_rec_t *)((char *)r1_base + (i * cf.tb_rec_sz));
            tb_rec_t *r2 = (tb_rec_t *)((char *)r2_base + (i * cf.tb_rec_sz));

            ops->tb_verify(r1);
            ops->tb_verify(r2);

            rtck_verify(r1->tr_hash, r1->tr_id);
            rtck_verify(r2->tr_hash, r2->tr_id);

            r1->tr_id = id2 + i;
            r2->tr_id = id1 + i;

            ops->tb_update(r1);
            ops->tb_update(r2);

            rtck_put(r1->tr_hash, r1->tr_id);
            rtck_put(r2->tr_hash, r2->tr_id);
        }

        worker->w_op = OP_PUT;
        ops->tb_put(r1_base, range, xfd2);
        ops->tb_put(r2_base, range, xfd1);

        worker->w_op = OP_CLOSE;
        ops->tb_close(xfd2);
        ops->tb_close(xfd1);

        worker->w_op = OP_WUNLOCK;
        rtck_wunlock(id2, range);
        rtck_wunlock(id1, range);
        
        worker->w_swaps += 1;
        worker->w_recs += range;
        (void)gettimeofday(&worker->w_stop, NULL);

        if (runtime_max > 0 || sigcnt > 0) {
            if (worker->w_stop.tv_sec >= runtime_max || sigcnt > 0) {
                break;
            }
        }
    }

    (void)gettimeofday(&worker->w_stop, NULL);

    free(r1_base);
    free(r2_base);
}

static void
test_status(worker_t *worker_base)
{
    int i;

    printf("\n%2s %6s %6s %3s %10s %12s %5s %10s %10s %10s\n",
           "ID", "PID", "STATE", "RC", "SWAPS", "RECS", "SECS",
           "SWAPS/SEC", "RECS/SEC", "MB/s");

    for (i = 0; i < cf.cf_procs_max; ++i) {
        worker_t *worker = worker_base + i;
        time_t secs = worker->w_stop.tv_sec - worker->w_start.tv_sec;
        const char *state = "???";
        u_int code = 0;

        if (worker->w_exited) {
            if (WIFEXITED(worker->w_status)) {
                code = WEXITSTATUS(worker->w_status);
                state = "exited";
            }
            else if (WIFSTOPPED(worker->w_status)) {
                code = WSTOPSIG(worker->w_status);
                state = "stop";
            }
            else if (WIFSIGNALED(worker->w_status)) {
                code = WTERMSIG(worker->w_status);
                state = "signal";

                if (WCOREDUMP(worker->w_status)) {
                    state = "core";
                }
            }
        }
        else {
            state = op2txt[worker->w_op];
        }
        
        printf("%2d %6d %6s %3u %10lu %12lu %5ld %10.1lf %10.1lf %10.2lf\n",
               i, worker->w_pid, state, code, worker->w_swaps, worker->w_recs, secs,
               (double)worker->w_swaps / secs, (double)worker->w_recs / secs,
               ((double)(worker->w_recs * sizeof(tb_rec_t)) / secs) / (1024 * 1024));
    }
}

void
test(void)
{
    size_t worker_base_sz;
    worker_t *worker_base;
    u_int range_max;
    struct stat sb;
    tb_ops_t *ops;
    tb_fd_t *xfd0;
    tb_rec_t *r;
    int oflags;
    ssize_t cc;
    pid_t pid;
    int fd;
    int rc;
    int i;

#if HAVE_ALARM
    int sig;

    /* TODO: Is there a param for the max number of signals?
     */
    for (sig = 0; sig < SIGRTMIN; ++sig) {
        (void)signal_reliable(sig, signal_isr);
    }
#if defined(AIX4) || defined(AIX5) || defined(AIX6)
    (void)signal_reliable(SIGDANGER, sigHandler);
#endif
#else
#error TODO - this implementation does not support alarm
#endif /* HAVE_ALARM */

    (void)initstate(1, rng_state, sizeof(rng_state));

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

    range_max = 2048;
    if (range_max > cf.tb_rec_max) {
        range_max = cf.tb_rec_max;
    }

    if (S_ISDIR(sb.st_mode)) {
        ops = tb_find("dir");
        range_max = 1;
    }
    else if (S_ISREG(sb.st_mode)) {
        ops = tb_find("file");
    }
    else {
        ops = tb_find("dev");
    }

    /* Open the test bed.
     */
    xfd0 = ops->tb_open(cf.tb_path, O_RDWR, 0);

    worker_base_sz = sizeof(*worker_base) * cf.cf_procs_max;

    int flags = MAP_ANON | MAP_SHARED;

#ifdef MAP_ALIGNED
    flags |= MAP_ALIGNED(12);
#endif

    worker_base = mmap(NULL, worker_base_sz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (worker_base == MAP_FAILED) {
        eprint("%s: mmap(): %s\n", __func__, strerror(errno));
        exit(EX_OSERR);
    }

    bzero(worker_base, worker_base_sz);

    for (i = 0; i < cf.cf_procs_max; ++i) {
        worker_t *worker = worker_base + i;

        pid = fork();

        switch (pid) {
        case -1:
            eprint("%s: fork(): %s\n", __func__, strerror(errno));
            break;

        case 0:
            test_worker(ops, range_max, worker);
            _exit(0);

        default:
            worker->w_pid = pid;
            break;
        }
    }

    struct timespec timeout = { 0, 0 };
    struct timespec *timeoutp;
    sigset_t sigmask_none;
    sigset_t sigmask_all;
    fd_set rfds;
    int fdin;

    timeoutp = (cf.cf_status_interval > 0) ? &timeout : NULL;
    (void)sigemptyset(&sigmask_none);
    (void)sigfillset(&sigmask_all);
    FD_ZERO(&rfds);
    fdin = STDIN_FILENO;

    sigprocmask(SIG_BLOCK, &sigmask_all, NULL);

    while (1) {
        struct rusage rusage;
        int status;
        int nfds;
        int rc;

        /* First, gather status from all children who have something
         * to report, but don't block in wait3().
         */
        pid = wait3(&status, WNOHANG, &rusage);

        if (pid > 0) {
            dprint(3, "reaped child %d, status %x\n", pid, status);

            for (i = 0; i < cf.cf_procs_max; ++i) {
                worker_t *worker = worker_base + i;

                if (worker->w_pid == pid) {
                    worker->w_status = status;
                    worker->w_rusage = rusage;

                    if (WIFEXITED(status)) {
                        worker->w_exited = 1;
                    }
                    break;
                }
            }
            continue;
        }
        else if (pid == 0) {
            sigcnt = 0; // wait3() would have blocked...
        }
        else if (errno == ECHILD) {
            break; // No more children
        }
        else {
            eprint("%s: wait3(): %s\n", __func__, strerror(errno));
            sleep(1);
            continue;
        }

        if (fdin >= 0) {
            FD_SET(fdin, &rfds);
        }

        if (timeoutp) {
            timeoutp->tv_sec = cf.cf_status_interval;
            timeoutp->tv_nsec = 0;
        }

        /* Wait in pselect until the timer expires or we catch a signal.
         */
        nfds = pselect(1, &rfds, NULL, NULL, timeoutp, &sigmask_none);

        if (nfds == 0) {
            test_status(worker_base);
        }
        else if (nfds > 0) {
            if (fdin >= 0 && FD_ISSET(fdin, &rfds)) {
                char buf[32];
                ssize_t cc;

                cc = read(fdin, buf, sizeof(buf));
                if (cc > 0) {
                    test_status(worker_base);
                }
                else if (cc == 0) {
                    FD_CLR(fdin, &rfds);
                    fdin = -1;
                }
                else {
                    eprint("%s: read: %s\n", __func__, strerror(errno));
                    sleep(1);
                }
            }
        }
    }

    test_status(worker_base);
    
    (void)munmap(worker_base, worker_base_sz);

    ops->tb_close(xfd0);
    rtck_close();
}
