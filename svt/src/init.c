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
#include "main.h"

void
init(void)
{
    int oflags = O_CREAT | O_TRUNC | O_WRONLY;
    struct stat sb;
    tb_ops_t *ops;
    tb_fd_t *xfd0;
    tb_rec_t *r;
    int rc;
    int i;

    rc = stat(cf.tb_path, &sb);
    if (rc) {
        if (errno != ENOENT) {
            eprint("%s: stat(%s): %s\n", __func__, cf.tb_path, strerror(errno));
            exit(EX_USAGE);
        }

        dprint(1, "creating test bed directory: %s\n", cf.tb_path);

        rc = mkdir(cf.tb_path, 0755);
        if (rc) {
            eprint("%s: mkdir(%s): %s\n", __func__, cf.tb_path, strerror(errno));
            exit(EX_OSERR);
        }

        rc = stat(cf.tb_path, &sb);
        if (rc) {
            eprint("%s: stat(%s): %s\n", __func__, cf.tb_path, strerror(errno));
            exit(EX_USAGE);
        }
    }

    cf.tb_rec_sz = sizeof(*r);

    ops = tb_find(cf.tb_path);

    r = malloc(cf.tb_rec_sz);
    if (!r) {
        eprint("%s: malloc(%ld): out of memory\n", __func__, cf.tb_rec_sz);
        exit(EX_OSERR);
    }

    cf_save();
    rtck_create();

    dprint(1, "initializing %s with %u records...\n",
           cf.tb_path, cf.tb_rec_max);

    xfd0 = ops->tb_open(cf.tb_path, oflags, 0);

    for (i = 0; i < cf.tb_rec_max; ++i) {
        rtck_t rtck;
        tb_fd_t *xfd;

        xfd = ops->tb_open(cf.tb_path, oflags, i);

        ops->tb_init(r, i);
        ops->tb_put(r, 1, xfd);

        rtck_hash_put(r->tr_id, r->tr_hash);

        ops->tb_close(xfd);
    }

    ops->tb_close(xfd0);

    rtck_close();
}
