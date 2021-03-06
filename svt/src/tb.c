/*
 * Copyright (c) 2001-2006,2015,2016,2019 Greg Becker.  All rights reserved.
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
#include "main.h"

#define TB_SUBDIR_MAX   (1024)

static tb_open_t        tb_open_generic;
static tb_close_t       tb_close_generic;
static tb_init_t        tb_init_generic;
static tb_update_t      tb_update_generic;
static tb_verify_t      tb_verify_generic;

static tb_open_t        tb_open_file;
static tb_close_t       tb_close_file;
static tb_get_t         tb_get_file;
static tb_put_t         tb_put_file;

static tb_open_t        tb_open_dir;
static tb_close_t       tb_close_dir;

static tb_ops_t tb_ops_dir = {
    .tb_open = tb_open_dir,
    .tb_close = tb_close_generic,
    .tb_init = tb_init_generic,
    .tb_get = tb_get_file,
    .tb_put = tb_put_file,
    .tb_update = tb_update_generic,
    .tb_verify = tb_verify_generic,
};

static tb_ops_t tb_ops_file = {
    .tb_open = tb_open_file,
    .tb_close = tb_close_file,
    .tb_init = tb_init_generic,
    .tb_get = tb_get_file,
    .tb_put = tb_put_file,
    .tb_update = tb_update_generic,
    .tb_verify = tb_verify_generic,
};

static tb_ops_t tb_ops_dev = {
    .tb_open = tb_open_file,
    .tb_close = tb_close_file,
    .tb_init = tb_init_generic,
    .tb_get = tb_get_file,
    .tb_put = tb_put_file,
    .tb_update = tb_update_generic,
    .tb_verify = tb_verify_generic,
};

static tb_fd_t *xfd_file;


/* Get a pointer to the path based operations object and initialize
 * the global configuration appropriately.
 *
 * Note:  Due to the side-effect of modifying the global config
 * this function is not thread-safe (and doesn't need to be...)
 */
tb_ops_t *
tb_find(const char *path)
{
    char errbuf[64];
    struct stat sb;
    int rc;

    assert(path);

    rc = stat(path, &sb);
    if (rc) {
        eprint("%s: stat(%s): %s\n", __func__, path, strerror(errno));
        exit(EX_USAGE);
    }

    if (S_ISDIR(sb.st_mode)) {
        char subdir[32];
        int fd;
        int i;

        fd = open(path, O_DIRECTORY);
        if (-1 == fd) {
            abort();
        }

        for (i = 0; i < TB_SUBDIR_MAX; ++i) {
            snprintf(subdir, sizeof(subdir), "%u", i);
            rc = mkdirat(fd, subdir, 0755);
            if (rc && errno != EEXIST) {
                abort();
            }
        }

        close(fd);

        cf.tb_rec_sz = sizeof(tb_rec_t);
        cf.cf_range_max = 1;
        cf.cf_range_min = 1;

        return &tb_ops_dir;
    }

    if (S_ISREG(sb.st_mode)) {
        cf.tb_rec_sz = sizeof(tb_rec_t);

        return &tb_ops_file;
    }

    if (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode)) {
        cf.tb_rec_sz = DEV_BSIZE;

        return &tb_ops_dev;
    }

    eprint("%s: no testbed ops for path %s (st_mode=%0u)\n",
           __func__, path, sb.st_mode);
    exit(EX_USAGE);

    /* NOTREACHED */
}


static tb_fd_t *
tb_open_generic(const char *path, int flags, uint32_t rec_id)
{
    char errbuf[64];
    tb_fd_t *xfd;
    bool odirect;

    xfd = calloc(1, sizeof(*xfd));
    if (!xfd) {
        eprint("%s: unable to alloc a testbed fd\n", __func__);
        exit(EX_OSERR);
    }

    odirect = (flags & O_DIRECT);

  again:
    xfd->tf_fd = open(path, flags, 0644);

    if (xfd->tf_fd == -1) {
        if (flags & O_DIRECT) {
            flags &= ~O_DIRECT;
            goto again;
        }

        eprint("%s: open(%s, 0x%x): %s\n", __func__, path, flags, strerror(errno));
        exit(EX_OSERR);
    }

    if (odirect && !(flags & O_DIRECT)) {
        dprint(1, "open(%s, 0x%x): O_DIRECT not supported\n", path, flags);
    }

    xfd->tf_opencnt = 1;

    return xfd;
}

static void
tb_close_generic(tb_fd_t *xfd)
{
    assert(xfd);

    if (xfd->tf_fd >= 0 && --xfd->tf_opencnt == 0) {
        close(xfd->tf_fd);
        xfd->tf_fd = -1;
        free(xfd);
    }
}

static void
tb_init_generic(tb_rec_t *r, uint32_t rec_id)
{
    struct timeval tv;

    (void)gettimeofday(&tv, NULL);

    r->tr_magic = 0x900dbeef900dcafe;
    r->tr_rec_max = cf.tb_rec_max;
    r->tr_rec_sz = cf.tb_rec_sz;
    r->tr_uniqid = rec_id;
    r->tr_sec = tv.tv_sec;
    r->tr_usec = tv.tv_usec;
    r->tr_id = rec_id;
    r->tr_hash[0] = 0;
    r->tr_hash[1] = 0;

    murmur3_128(r, sizeof(*r), r->tr_hash);

    dprint(3, "%7u %016lx.%016lx\n", rec_id, r->tr_hash[0], r->tr_hash[1]);
}

static void
tb_update_generic(tb_rec_t *r)
{
    r->tr_updates += 1;

    r->tr_hash[0] = 0;
    r->tr_hash[1] = 0;

    murmur3_128(r, sizeof(*r), r->tr_hash);
}

static void
tb_verify_generic(tb_rec_t *r)
{
    uint64_t hash_saved[2];
    rtck_t   rtck;

    dprint(4, "%08lx %7u %016lx.%016lx\n",
           r->tr_magic, r->tr_id, r->tr_hash[0], r->tr_hash[1]);

    hash_saved[0] = r->tr_hash[0];
    hash_saved[1] = r->tr_hash[1];

    r->tr_hash[0] = 0;
    r->tr_hash[1] = 0;

    murmur3_128(r, sizeof(*r), r->tr_hash);

    if (r->tr_hash[0] != hash_saved[0] ||
        r->tr_hash[1] != hash_saved[1]) {

        eprint("%s: record %u hash mismatch %lx vs %lx, %lx vs %lx\n",
               __func__, r->tr_id,
               r->tr_hash[0], hash_saved[0],
               r->tr_hash[1], hash_saved[1]);
        abort();
        exit(EX_DATAERR);
    }
}


/* Directory operations...
 */

/* Open a file within the test bed directory.
 *
 * If the test bed is a directory, then it contains a small and limited
 * number of subdirectories over which all the files in the test bed
 * are distributed (there is one file per record ID in the test bed).
 */
static tb_fd_t *
tb_open_dir(const char *path, int flags, uint32_t rec_id)
{
    char path_file[PATH_MAX];

    snprintf(path_file, sizeof(path_file), "%s/%u/fsx-%u",
             path, rec_id % TB_SUBDIR_MAX, rec_id);

    return tb_open_generic(path_file, flags, rec_id);
}


/* File/device operations...
 */

/* Open a file or device, or acquire a reference to an already open file.
 *
 * Note that in the interest of simplicity and efficiency only one file
 * can be open at a time (which is all that is currently required).
 *
 * To make this thread-safe and allow any number of file to be open
 * at the same time we'd have to employ a lookup mechanism.  Since this
 * program only ever needs to have one file open at a time such a
 * mechanism would be pure unnecessary overhead.
 */
static tb_fd_t *
tb_open_file(const char *path, int flags, uint32_t rec_id)
{
    if (xfd_file) {
        xfd_file->tf_opencnt += 1;
    }
    else {
        xfd_file = tb_open_generic(path, flags, rec_id);
    }

    return xfd_file;
}

static void
tb_close_file(tb_fd_t *xfd)
{
    assert(xfd);
    assert(xfd == xfd_file);

    if (xfd->tf_fd >= 0 && --xfd->tf_opencnt == 0) {
        xfd_file = NULL;
        close(xfd->tf_fd);
        free(xfd);
    }
}

static int
tb_get_file(tb_rec_t *r, uint32_t rec_id, int n, tb_fd_t *xfd)
{
    char errbuf[64];
    ssize_t cc;

    cc = pread(xfd->tf_fd, r, cf.tb_rec_sz * n, rec_id * cf.tb_rec_sz);

    if (cc != cf.tb_rec_sz * n) {
        const char *msg = "EOF";

        if (cc == -1) {
            strerror_r(errno, errbuf, sizeof(errbuf));
            msg = errbuf;
        }
        else if (cc > 0) {
            msg = "short read";
        }

        eprint("%s: pread(%d, %p, %u, %d) failed: cc=%ld %s\n",
               __func__, xfd->tf_fd, r, cf.tb_rec_sz * n, rec_id * cf.tb_rec_sz, cc, msg);
        abort();
    }

    return 0;
}

static int
tb_put_file(tb_rec_t *r, int n, tb_fd_t *xfd)
{
    char errbuf[64];
    ssize_t cc;

    cc = pwrite(xfd->tf_fd, r, cf.tb_rec_sz * n, r->tr_id * cf.tb_rec_sz);

    if (cc != cf.tb_rec_sz * n) {
        const char *msg = "EOF";

        if (cc == -1) {
            strerror_r(errno, errbuf, sizeof(errbuf));
            msg = errbuf;
        }
        else if (cc > 0) {
            msg = "short write";
        }

        eprint("%s: pwrite(%d, %p, %u, %d) failed: cc=%ld %s\n",
               __func__, xfd->tf_fd, r, cf.tb_rec_sz * n, r->tr_id * cf.tb_rec_sz, cc, msg);
        abort();
    }

    return 0;
}
