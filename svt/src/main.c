/*
 * Copyright (c) 2001-2006,2011,2015,2016,2019,2022 Greg Becker.  All rights reserved.
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

FILE *dprint_fp;
FILE *eprint_fp;

CLP_VECTOR(rangev, u_int, 2, ",-:");

static int
rangev_after(struct clp_option *option)
{
    u_int *resultv = option->cvtdst;

    cf.cf_range_min = resultv[0];
    cf.cf_range_max = resultv[1];

    return 0;
}

struct clp_posparam posparamv[] = {
    CLP_POSPARAM("testbed", string, cf.tb_path, NULL, NULL, "path to testbed"),
    CLP_POSPARAM_END
};

struct clp_option optionv[] = {
    CLP_OPTION_VERBOSITY(verbosity),
    CLP_OPTION_VERSION(version),
    CLP_OPTION_HELP,

    { .optopt = 'C', .argname = "cfdir", .longopt = "conf",
      .help = "specify the config file directory",
      .cvtfunc = clp_cvt_string, .cvtdst = &cf_dir, },

    { .optopt = 'c', .longopt = "check",
      .help = "check the testbed for errors",
      .cvtfunc = clp_cvt_bool, .cvtdst = &fcheck, },

    { .optopt = 'H', .longopt = "no-headers",
      .help = "suppress column headers",
      .cvtfunc = clp_cvt_bool, .cvtdst = &headers, },

    { .optopt = 'i', .argname = "maxrecs", .longopt = "init",
      .help = "specify the size of the testbed (in records)",
      .cvtfunc = clp_cvt_int, .cvtdst = &cf.tb_rec_max, },

    { .optopt = 'j', .argname = "maxjobs", .longopt = "jobs",
      .help = "specify the maximum number of worker processes",
      .cvtfunc = clp_cvt_int, .cvtdst = &cf.cf_jobs_max, },

    { .optopt = 'R', .longopt = "no-verify",
      .help = "disable read verification in test mode",
      .cvtfunc = clp_cvt_bool, .cvtdst = &verify, },

    { .optopt = 'r', .argname = "range", .longopt = "range",
      .help = "specify the min[,max] number of records per swap",
      .cvtfunc = clp_cvt_int, .cvtdst = rangev.data,
      .cvtparms = &rangev, .after = rangev_after },

    { .optopt = 's', .argname = "statsecs", .longopt = "stats",
      .help = "print status every statsecs seconds",
      .cvtfunc = clp_cvt_int, .cvtdst = &cf.cf_status_interval, },

    { .optopt = 't', .argname = "testsecs", .longopt = "test",
      .help = "run in test mode for testsecs seconds",
      .cvtfunc = clp_cvt_time_t, .cvtdst = &cf.cf_runtime_max, },

    { .optopt = 'w', .argname = "swpct", .longopt = "swpct",
      .help = "specify the percent of swap puts to gets",
      .cvtfunc = clp_cvt_int, .cvtdst = &cf.cf_swaps_pct, },

    CLP_OPTION_END
};

bool
given(int c)
{
    return !!clp_given(c, optionv, NULL);
}

int
main(int argc, char **argv)
{
    char state[256];
    int i, c;
    char *pc;
    int rc;

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    dprint_fp = stdout;
    eprint_fp = stderr;

    (void)initstate(time(NULL), state, sizeof(state));

    rc = clp_parsev(argc, argv, optionv, posparamv);
    if (rc) {
        exit(rc);
    }

    if (given('h') || given('V'))
        return 0;

    if (!(given('c') || given('i') || given('t'))) {
        eprint("one of -c, -i, or -t must be given, use -h for help\n");
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

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (verbosity > 1) {
        fprintf(dprint_fp, "%s:%-4d  %s", func, line, msg);
    } else {
        fprintf(dprint_fp, "%s", msg);
    }
}


/* Error print.
 */
void
eprint(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(eprint_fp, "%s(%d): %s", progname, getpid(), msg);
}
