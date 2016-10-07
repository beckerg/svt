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

static void
test_run(worker_t *worker, tb_ops_t *ops)
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

void
test(void)
{
    tb_ops_t *ops;
    tb_fd_t *xfd0;

    ops = tb_find(cf.tb_path);

    cf_load();
    rtck_open();

    xfd0 = ops->tb_open(cf.tb_path, O_RDWR | O_DIRECT, 0);

    worker_run(NULL, NULL, test_run, ops);

    ops->tb_close(xfd0);
    rtck_close();
}
