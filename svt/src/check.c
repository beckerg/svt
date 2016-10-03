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
#include "main.h"

void
check(void)
{
    int nduplicates;
    tb_fd_t *xfd0;
    uint8_t *cnts;
    tb_ops_t *ops;
    int nmissing;
    int ninplace;
    tb_rec_t *r;
    int rc;
    int i;

    cf_load();
    rtck_open();

    r = malloc(cf.tb_rec_sz);
    if (!r) {
        eprint("%s: malloc(%ld): out of memory\n", __func__, cf.tb_rec_sz);
        exit(EX_OSERR);
    }

    ops = tb_find(cf.tb_path);

    xfd0 = ops->tb_open(cf.tb_path, O_RDONLY, 0);

    ninplace = 0;
    nmissing = 0;
    nduplicates = 0;
    cnts = calloc(cf.tb_rec_max, sizeof(*cnts));

    dprint(1, "checking test bed integrity %s...\n", cf.tb_path);

    for (i = 0; i < cf.tb_rec_max; ++i) {
        tb_fd_t *xfd;

        xfd = ops->tb_open(cf.tb_path, O_RDONLY, i);

        ops->tb_get(r, i, 1, xfd);
        ops->tb_verify(r);

        rtck_hash_verify(r->tr_id, r->tr_hash);

        if (cnts[r->tr_uniqid] < 128) {
            if (i == r->tr_uniqid) {
                ++ninplace;
            }
            ++cnts[r->tr_uniqid];
        }

        ops->tb_close(xfd);
    }

    dprint(1, "checking uniqueness %s...\n", cf.tb_path);

    /* Check that each record appears exactly once.
     */
    for (i = 0; i < cf.tb_rec_max; ++i) {
        if (cnts[i] != 1) {
            if (cnts[i] < 1) {
                ++nmissing;
            }
            else if (cnts[i] > 1) {
                ++nduplicates;
            }
            dprint(3, "record %d appeared %d times\n", i, cnts[i]);
        }
    }

    dprint(1, "%u of %u records in place (%.2lf %%)\n",
           ninplace, cf.tb_rec_max, (ninplace * 100.0) / cf.tb_rec_max);

    if (nmissing > 0 || nduplicates > 0) {
        if (nmissing > 0) {
            eprint("%d records missing (data integrity error)\n", nmissing);
        }
        if (nduplicates > 0) {
            eprint("%d records duplicated (data integrity error)\n", nduplicates);
        }

        exit(EX_DATAERR);
    }

    free(cnts);

    ops->tb_close(xfd0);

    rtck_close();
}
