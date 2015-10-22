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
#include <time.h>
#include <sys/select.h>
#include <math.h>

#include "cf.h"
#include "rtck.h"
#include "main.h"

/* Run Time Check File...
 */

static char        *rtck_path;
static rtck_t      *rtck_base;
static int          rtck_fd = -1;

static void
rtck_init(void)
{
    size_t rtck_path_sz;
    struct stat sb;
    int rc;
    int i;

    rc = stat(cf.tb_path, &sb);
    if (rc) {
        abort();
    }

    rtck_path_sz = strlen(cf.tb_path) + 128;

    rtck_path = malloc(rtck_path_sz);
    if (!rtck_path) {
        abort();
    }

    (void)snprintf(rtck_path, rtck_path_sz, "%s/%s-%lu.rtck",
                   cf.cf_dir, progname, (u_long)sb.st_ino);
}

void
rtck_create(void)
{
    off_t len;

    rtck_init();

    len = cf.tb_rec_max * sizeof(*rtck_base);

    rtck_fd = open(rtck_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (-1 == rtck_fd) {
        eprint("%s: open(%s): %s\n", __func__, rtck_path, strerror(errno));
        exit(EX_OSERR);
    }

    if (-1 == ftruncate(rtck_fd, len)) {
        eprint("%s: ftruncate(%s, %lld): %s\n", __func__, rtck_path, len, strerror(errno));
        exit(EX_OSERR);
    }

    (void)close(rtck_fd);
    rtck_fd = -1;

    rtck_open();

    /* Zero the entire file (in an attempt to avoid fragmentation?)
     */
    bzero(rtck_base, len);
}

void
rtck_open(void)
{
    struct stat sb;
    int rc;

    if (rtck_fd >= 0) {
        return;
    }

    rtck_init();

    rtck_fd = open(rtck_path, O_RDWR);
    if (-1 == rtck_fd) {
        eprint("%s: open(%s): %s\n", __func__, rtck_path, strerror(errno));
        exit(EX_OSERR);
    }

    rc = fstat(rtck_fd, &sb);
    if (rc) {
        eprint("%s: fstat(%s): %s\n", __func__, rtck_path, strerror(errno));
        exit(EX_OSERR);
    }

    /* Check that the number of entries in the run time check file
     * matches the number of records in the test bed.
     */
    if (sb.st_size != (cf.tb_rec_max * sizeof(*rtck_base))) {
        exit(EX_DATAERR);
    }

    rtck_base = mmap((void *)0, cf.tb_rec_max * sizeof(*rtck_base),
                     PROT_READ | PROT_WRITE, MAP_SHARED, rtck_fd, 0);

    if (rtck_base == MAP_FAILED) {
        eprint("%s: mmap(%s): %s\n", __func__, rtck_path, strerror(errno));
        exit(EX_OSERR);
    }
}

void
rtck_close(void)
{
    if (rtck_fd >= 0) {
        (void)close(rtck_fd);
        rtck_base = NULL;
        rtck_fd = -1;
    }
}

void
rtck_get(uint64_t *hash, uint32_t rec_id)
{
    rtck_t *r;

    assert(rec_id < cf.tb_rec_max);
    assert(rtck_fd >= 0);

    r = rtck_base + rec_id;

    hash[0] = r->rtck_hash[0];
    hash[1] = r->rtck_hash[1];
}

void
rtck_put(const uint64_t *hash, uint32_t rec_id)
{
    rtck_t *r;

    assert(rec_id < cf.tb_rec_max);
    assert(rtck_fd >= 0);

    r = rtck_base + rec_id;

    r->rtck_hash[0] = hash[0];
    r->rtck_hash[1] = hash[1];
}

void
rtck_verify(const uint64_t *hash, uint32_t rec_id)
{
    rtck_t *r;

    assert(rec_id < cf.tb_rec_max);
    assert(rtck_fd >= 0);

    r = rtck_base + rec_id;

    assert(r->rtck_hash[0] == hash[0]);
    assert(r->rtck_hash[1] == hash[1]);
}

int
rtck_wlock(uint32_t rec_id, int range)
{
    struct flock lk;
    int rc;

    bzero(&lk, sizeof(lk));
    lk.l_start = rec_id * sizeof(rtck_t);
    lk.l_len = range * sizeof(rtck_t);
    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;

    rc = fcntl(rtck_fd, F_SETLKW, &lk);
    if (rc) {
        if (errno == EDEADLK) {
            return errno;
        }

        eprint("%s: fcntl(%d, F_SETLK): %s\n", __func__, rtck_fd, strerror(errno));
        exit(EX_OSERR);
    }

    return 0;
}

int
rtck_wunlock(uint32_t rec_id, int range)
{
    struct flock lk;
    int rc;

    bzero(&lk, sizeof(lk));
    lk.l_start = rec_id * sizeof(rtck_t);
    lk.l_len = range * sizeof(rtck_t);
    lk.l_type = F_UNLCK;
    lk.l_whence = SEEK_SET;

    rc = fcntl(rtck_fd, F_SETLK, &lk);
    if (rc) {
        eprint("%s: fcntl(%d, F_SETLK): %s\n", __func__, rtck_fd, strerror(errno));
        exit(EX_OSERR);
    }

    return 0;
}
