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

/*
 * Config File management module.
 */

#include "system.h"
#include "main.h"
#include "cf.h"

cf_t cf;

void
cf_save(void)
{
    size_t cf_path_sz = 4096;
    struct stat sb;
    char *cf_path;
    FILE *fp;
    int rc;

    if (!cf.cf_dir) {
        cf.cf_dir = "/var/tmp";
    }

    rc = stat(cf.tb_path, &sb);
    if (rc) {
        eprint("stat(%s): %s\n", cf.tb_path, strerror(errno));
        exit(EX_NOINPUT);
    }

    cf_path = malloc(cf_path_sz);
    if (!cf_path) {
        abort();
    }

    (void)snprintf(cf_path, cf_path_sz, "%s/%s-%lu.cf",
                   cf.cf_dir, progname, (u_long)sb.st_ino);

    rc = truncate(cf_path, 0);

    fp = fopen(cf_path, "w+");
    if (!fp) {
        eprint("fopen(%s): %s\n", cf_path, strerror(errno));
        exit(EX_OSERR);
    }

    dprint(1, "saving configuration in %s\n", cf_path);

    fprintf(fp, "# Generated on ...\n");
    fprintf(fp, "tb_rec_max %u\n", cf.tb_rec_max);
    fprintf(fp, "tb_rec_sz  %u\n", cf.tb_rec_sz);

    (void)fclose(fp);
}


void
cf_load(void)
{
    size_t cf_path_sz = 4096;
    char line[1024];
    struct stat sb;
    char *cf_path;
    int lineno;
    FILE *fp;
    int rc;

    if (!cf.cf_dir) {
        cf.cf_dir = "/var/tmp";
    }

    rc = stat(cf.tb_path, &sb);
    if (rc) {
        eprint("%s: stat(%s): %s\n", __func__, cf.tb_path, strerror(errno));
        exit(EX_NOINPUT);
    }

    cf_path = malloc(cf_path_sz);
    if (!cf_path) {
        abort();
    }

    (void)snprintf(cf_path, cf_path_sz, "%s/%s-%lu.cf",
                   cf.cf_dir, progname, (u_long)sb.st_ino);

    fp = fopen(cf_path, "r");
    if (!fp) {
        eprint("%s; fopen(%s): %s\n", __func__, cf_path, strerror(errno));
        exit(EX_OSERR);
    }

    dprint(2, "loading configuration from %s\n", cf_path);

    lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *val = line;
        char *name;

        ++lineno;

        /* Eat leading white space and comments.
         */
        while (*val == ' ' || *val == '\t') {
            ++val;
        }

        if (*val == '\000' || *val == '#') {
            continue;
        }

        name = strsep(&val, " \t=");

        /* TODO: Deal with strtol() errors...
         */
        if (0 == strcmp("tb_rec_max", name)) {
            cf.tb_rec_max = strtoul(val, NULL, 0);
        }
        else if (0 == strcmp("tb_rec_sz", name)) {
            cf.tb_rec_sz = strtoul(val, NULL, 0);
        }
        else if (0 == strcmp("cf_runtime_max", name)) {
            cf.cf_runtime_max = strtol(val, NULL, 0);
        }
        else {
            eprint("%s: ignoring invalid config variable name [%s] at line %d in %s\n",
                    __func__, name, lineno, cf_path);
        }
    }

    if (cf.cf_runtime_max < 0) {
        cf.cf_runtime_max = 0;
    }
    if (cf.cf_procs_max < 1) {
        cf.cf_procs_max = 1;
    }

    fprintf(fp, "tb_rec_max         %u\n", cf.tb_rec_max);
    fprintf(fp, "tb_rec_sz          %u\n", cf.tb_rec_sz);
    fprintf(fp, "cf_runtime_max     %ld\n", cf.cf_runtime_max);
    fprintf(fp, "cf_procs_max       %u\n", cf.cf_procs_max);
    fprintf(fp, "cf_status_interval %u\n", cf.cf_status_interval);

    assert(cf.tb_rec_max > 0);
    assert(cf.tb_rec_sz > 0);

    (void)fclose(fp);
}
