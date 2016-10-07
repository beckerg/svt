/*
 * Copyright (c) 2001-2006,2015,2016 Greg Becker.  All rights reserved.
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
#include "check.h"
#include "worker.h"
#include "main.h"

typedef struct {
    uint ninplace;
    uint cnts[];
} shared_t;

static shared_t *shared;

static void
check_run(worker_t *worker, tb_ops_t *ops)
{
    worker_stats_t *stats;
    tb_rec_t *r;
    int i;

    r = malloc(cf.tb_rec_sz);
    if (!r) {
        eprint("%s: malloc(%ld): out of memory\n", __func__, cf.tb_rec_sz);
        exit(EX_OSERR);
    }

    stats = &worker->w_astats;

    for (i = worker->w_frec; i < worker->w_lrec; ++i) {
        tb_fd_t *xfd;

        worker->w_op = OP_OPEN;
        xfd = ops->tb_open(cf.tb_path, O_RDONLY, i);

        worker->w_op = OP_GET1;
        ops->tb_get(r, i, 1, xfd);
        stats->s_gets += 1;

        worker->w_op = OP_VERIFY;
        ops->tb_verify(r);

        rtck_hash_verify(r->tr_id, r->tr_hash);

        if (i == r->tr_uniqid) {
            __sync_fetch_and_add(&shared->ninplace, 1);
        }
        __sync_fetch_and_add(&shared->cnts[r->tr_uniqid], 1);

        worker->w_op = OP_CLOSE;
        ops->tb_close(xfd);

        worker->w_op = OP_LOOP;

        if (sigint_cnt > 0) {
            break;
        }
    }

    free(r);
}


void
check(void)
{
    size_t sharedsz;
    int nduplicates;
    uint nmissing;
    tb_fd_t *xfd0;
    tb_ops_t *ops;
    int flags;
    int rc;
    int i;

    ops = tb_find(cf.tb_path);

    cf_load();
    rtck_open();

    xfd0 = ops->tb_open(cf.tb_path, O_RDONLY, 0);

    sharedsz = sizeof(*shared) + sizeof(shared->cnts[0]) * cf.tb_rec_max;
    flags = MAP_ANON | MAP_SHARED;

    shared = mmap(NULL, sharedsz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (shared == MAP_FAILED) {
        abort();
    }

    nduplicates = 0;
    nmissing = 0;

    dprint(1, "checking test bed integrity %s...\n", cf.tb_path);

    worker_run(NULL, NULL, check_run, ops);

    dprint(1, "checking uniqueness %s...\n", cf.tb_path);

    /* Check that each record appears exactly once.
     */
    for (i = 0; i < cf.tb_rec_max; ++i) {
        if (shared->cnts[i] != 1) {
            if (shared->cnts[i] < 1) {
                ++nmissing;
            }
            else if (shared->cnts[i] > 1) {
                ++nduplicates;
            }
            dprint(3, "record %d appeared %u times\n", i, shared->cnts[i]);
        }
    }

    dprint(1, "%u of %u records in place (%.2lf %%)\n",
           shared->ninplace, cf.tb_rec_max, (shared->ninplace * 100.0) / cf.tb_rec_max);

    if (nmissing > 0 || nduplicates > 0) {
        if (nmissing > 0) {
            eprint("%u records missing (data integrity error)\n", nmissing);
        }
        if (nduplicates > 0) {
            eprint("%u records duplicated (data integrity error)\n", nduplicates);
        }

        exit(EX_DATAERR);
    }

    munmap(shared->cnts, sharedsz);

    ops->tb_close(xfd0);

    rtck_close();
}
