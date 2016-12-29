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
#include "murmur3.h"
#include "cf.h"
#include "rtck.h"
#include "tb.h"
#include "check.h"
#include "init.h"
#include "worker.h"
#include "main.h"

static void
init_run(worker_t *worker, tb_ops_t *ops)
{
    int oflags = O_CREAT | O_TRUNC | O_WRONLY;
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
        rtck_t rtck;
        tb_fd_t *xfd;

        worker->w_op = OP_OPEN;
        xfd = ops->tb_open(cf.tb_path, oflags, i);

        worker->w_op = OP_INIT;
        ops->tb_init(r, i);

        worker->w_op = OP_PUT1;
        ops->tb_put(r, 1, xfd);
        stats->s_puts += 1;

        worker->w_op = OP_PUT2;
        rtck_hash_set(r->tr_id, r->tr_hash);

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
init(void)
{
    tb_ops_t *ops;
    tb_fd_t *xfd0;
    int oflags;

    ops = tb_find(cf.tb_path);

    cf_save();
    cf_load();
    rtck_create();

    dprint(1, "initializing %s with %u %u-byte records...\n",
           cf.tb_path, cf.tb_rec_max, cf.tb_rec_sz);

    oflags = O_CREAT | O_TRUNC | O_WRONLY;
    xfd0 = ops->tb_open(cf.tb_path, oflags, 0);

    worker_run(__func__, NULL, NULL, init_run, ops);

    ops->tb_close(xfd0);

    rtck_close();
}
