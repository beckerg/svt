/*
 * Copyright (c) 2015,2016,2019 Greg Becker.  All rights reserved.
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
 */

#ifndef SVT_WORKER_H
#define SVT_WORKER_H

#ifndef ulong
typedef unsigned long ulong;
#endif

typedef enum {
    OP_NULL,
    OP_INIT,
    OP_LOOP,
    OP_DONE,
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
    ulong           s_getbytes; // Number of bytes read by this worker
    ulong           s_putbytes; // Number of bytes written by this worker
    ulong           s_recs;     // Number of records swapped by this worker
} worker_stats_t;

/* Worker state
 */
typedef struct {
    __attribute__((__aligned__(4096)))
    uint            w_id;
    pid_t           w_pid;
    struct timeval  w_start;
    struct timeval  w_stop;
    uint            w_frec;    // First rec to process (inclusive)
    uint            w_lrec;    // Last rec to process (exclusive)

    worker_stats_t  w_astats;   // Active stats
    worker_stats_t  w_fstats;   // Frozen/stabilized stats
    worker_stats_t  w_ostats;   // Old/previous stats

    op_t            w_op;       // Current operation
    bool            w_exited;   // 'true' if worker exited
    int             w_status;   // wait3() status code
    struct rusage   w_rusage;
} worker_t;

typedef void worker_init_t(worker_t *, tb_ops_t *ops);
typedef void worker_fini_t(worker_t *, tb_ops_t *ops);
typedef void worker_run_t(worker_t *, tb_ops_t *ops);

extern volatile sig_atomic_t sigxxx_cnt;
extern volatile sig_atomic_t sigint_cnt;
extern volatile sig_atomic_t sigchld_cnt;

extern const char *op2txt[];

void
worker_run(const char *mode, worker_init_t *, worker_fini_t *, worker_run_t *, tb_ops_t *);

#endif /* SVT_WORKER_H */
