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

static char version[] = SVT_VERSION;

char *progname;
int verbosity;

bool headers = true;
bool fcheck = false;
bool verify = true;
char *cf_dir;

FILE *dprint_stream;
FILE *eprint_stream;

CLP_VECTOR(rangev, u_int, 2, ",-:");

static void
rangev_after(struct clp_option_s *option)
{
    u_int *resultv = option->cvtdst;

    cf.cf_range_min = resultv[0];
    cf.cf_range_max = resultv[1];
}

clp_posparam_t posparamv[] = {
    { .name = "testbed",
      .help = "path to the testbed",
      .convert = clp_cvt_string, .cvtdst = &cf.tb_path, },

    CLP_PARAM_END
};

clp_option_t optionv[] = {
    CLP_OPTION_VERBOSE(verbosity),
    CLP_OPTION_VERSION(version),
    CLP_OPTION_HELP,

    { .optopt = 'C', .argname = "cfdir", .longopt = "conf",
      .help = "specify the config file directory",
      .convert = clp_cvt_string, .cvtdst = &cf_dir, },

    { .optopt = 'c', .longopt = "check",
      .help = "check the testbed for errors",
      .convert = clp_cvt_bool, .cvtdst = &fcheck, },

    { .optopt = 'H', .longopt = "no-headers",
      .help = "suppress column headers",
      .convert = clp_cvt_bool, .cvtdst = &headers, },

    { .optopt = 'i', .argname = "maxrecs", .longopt = "init",
      .help = "specify the size of the testbed (in records)",
      .convert = clp_cvt_int, .cvtdst = &cf.tb_rec_max, },

    { .optopt = 'j', .argname = "maxjobs", .longopt = "jobs",
      .help = "specify the maximum number of worker processes",
      .convert = clp_cvt_int, .cvtdst = &cf.cf_jobs_max, },

    { .optopt = 'R', .longopt = "verify",
      .help = "disable read verification",
      .convert = clp_cvt_bool, .cvtdst = &verify, },

    { .optopt = 'r', .argname = "range", .longopt = "range",
      .help = "specify the min[,max] number of records per swap",
      .convert = clp_cvt_int, .cvtdst = rangev.data,
      .cvtparms = &rangev, .after = rangev_after },

    { .optopt = 'S', .argname = "swpct", .longopt = "swpct",
      .help = "specify the percent of swap puts to gets",
      .convert = clp_cvt_int, .cvtdst = &cf.cf_swaps_pct, },

    { .optopt = 's', .argname = "statsecs", .longopt = "stats",
      .help = "print status every statsecs seconds",
      .convert = clp_cvt_int, .cvtdst = &cf.cf_status_interval, },

    { .optopt = 't', .argname = "testsecs", .longopt = "test",
      .help = "run in test mode for testsecs seconds",
      .convert = clp_cvt_int, .cvtdst = &cf.cf_runtime_max, },

    CLP_OPTION_END
};

bool
given(int c)
{
    clp_option_t *opt = clp_option_find(optionv, c);

    return (opt && opt->given > 0);
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
        eprint("one of -c, -i, or -t must be given, use -h for help\n");
        exit(EX_USAGE);
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        eprint("insufficient arguments for mandatory parameters, use -h for help\n");
        exit(EX_USAGE);
    } else if (argc > 1) {
        eprint("extraneous arguments detected, use -h for help\n");
        exit(EX_USAGE);
    }

#if !HAVE_MMAP
    if (given('m')) {
        eprint("mmap not available on this platform, use -h for help\n");
        exit(EX_USAGE);
    }
#endif

    cf.cf_dir = cf_dir;

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
