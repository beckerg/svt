/*
 * Copyright (c) 2001-2006,2011,2015,2016 Greg Becker.  All rights reserved.
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
#include "tb.h"
#include "test.h"
#include "check.h"
#include "init.h"
#include "clp.h"
#include "main.h"

#define NDEBUG

static char svnid[] = "$Id: main.c 52 2011-10-19 12:26:36Z greg $";

int verbosity = 0;
char *progname;

FILE *dprint_stream;
FILE *eprint_stream;


clp_posparam_t posparamv[] = {
    {
        .name = "testbed",
        .help = "path to the testbed",
        .convert = clp_convert_string, .result = &cf.tb_path,
    },

    { .name = NULL }
};

clp_option_t optionv[] = {
    CLP_OPTION_VERBOSE(&verbosity),
    CLP_OPTION_VERSION(svnid),
    CLP_OPTION_CONF(&cf.cf_dir),
    CLP_OPTION_HELP,

    {
        .optopt = 'i', .argname = "maxrecs",
        .help = "specify the size of the testbed (in records)",
        .convert = clp_convert_int, .result = &cf.tb_rec_max, .cvtarg = (void *)10,
    },

    {
        .optopt = 'p', .argname = "maxprocs",
        .help = "specify the maximum number of worker process",
        .convert = clp_convert_int, .result = &cf.cf_procs_max, .cvtarg = (void *)10,
    },

    {
        .optopt = 'm',
        .help = "use mmap",
        .convert = clp_convert_int, .result = &cf.cf_mmap, .cvtarg = (void *)10,
    },

    {
        .optopt = 's', .argname = "statsecs",
        .help = "print status every statsecs seconds",
        .convert = clp_convert_int, .result = &cf.cf_status_interval, .cvtarg = (void *)10,
    },

    {
        .optopt = 't', .argname = "maxsecs",
        .help = "run in test mode for maxsecs seconds",
        .convert = clp_convert_int, .result = &cf.cf_runtime_max, .cvtarg = (void *)10,
    },

    { .optopt = 0 }
};

bool
given(int c)
{
    clp_option_t *opt = clp_option_find(optionv, c);

    return (opt && opt->given);
}

int
main(int argc, char **argv)
{
    char errbuf[CLP_ERRBUFSZ];
    char state[256];
    int optind;
    int i, c;
    char *pc;
    int rc;

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    dprint_stream = stdout;
    eprint_stream = stderr;

    (void)initstate(time(NULL), state, sizeof(state));

    rc = clp_parsev(argc, argv, optionv, posparamv, errbuf, &optind);
    if (rc) {
        fprintf(stderr, "%s: %s\n", progname, errbuf);
        exit(rc);
    }

    if (given('h') || given('V'))
        return 0;

    if (!(given('c') || given('i') || given('t'))) {
        eprint("one of -c, -i, or -t must be given, use `-h' for help\n");
        exit(EX_USAGE);
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        eprint("mandatory arguments required, use `-h' for help\n");
        exit(EX_USAGE);
    } else if (argc > 1) {
        eprint("extraneous arguments detected, use `-h' for help\n");
        exit(EX_USAGE);
    }

#if !HAVE_MMAP
    if (given('m')) {
        eprint("mmap not available on this platform, use `-h' for help\n");
        exit(EX_USAGE);
    }
#endif

    /* TODO: Run these in the order given on the command line...
     */
    if (given('i'))
        init();

    if (given('t'))
        test();

    if (given('c'))
        check();

    return 0;
}


/* Debug print.  Usually called indirectly via the dprint() macro.
 */
void
dprint_impl(int lvl, const char *func, int line, const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    msg[0] = '\000';

    if (verbosity > 1) {
        (void)snprintf(msg, sizeof(msg), "%s:%-4d ", func, line);
    }

    va_start(ap, fmt);
    vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
    va_end(ap);

    fputs(msg, dprint_stream);
}


/* Error print.
 */
void
eprint(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    (void)snprintf(msg, sizeof(msg), "%s(%d): ", progname, getpid());

    va_start(ap, fmt);
    vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
    va_end(ap);

    fputs(msg, eprint_stream);
}
