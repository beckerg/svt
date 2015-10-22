/*
 * Copyright (c) 2001-2006,2011,2015 Greg Becker.  All rights reserved.
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
#include <sys/time.h>
#include <sys/select.h>
#include <time.h>
#include <math.h>

#include "cf.h"
#include "tb.h"
#include "test.h"
#include "check.h"
#include "init.h"
#include "main.h"

#define NDEBUG

static char svnid[] = "$Id: main.c 52 2011-10-19 12:26:36Z greg $";

/* Variables set by the option parser.
 * f{varname} - flag, true if option was given
 * arg{varname} - optarg argument
 */
int verbosity = 0;
int fHelp, fVersion;

FILE *dprint_stream;
FILE *eprint_stream;
char *progname;


static void
usage(void)
{
    printf("usage: %s [-cmv] [-C cfdir] [-i maxrecs] [-s statsecs] [-t maxsecs] testbed\n",
           progname);
    printf("usage: %s -h\n", progname);
    printf("usage: %s -V\n", progname);
    printf("-C cfdir     specify the config file directory\n");
    printf("-c           check the testbed for errors\n");
    printf("-h           print this help list\n");
    printf("-m           use mmap\n");
    printf("-p maxprocs  maximum number of worker processes to use\n");
    printf("-i maxrecs   specify the size of the testbed (in records)\n");
    printf("-s statsecs  print status every statsecs seconds\n");
    printf("-t maxsecs   run in test mode for maxsecs seconds\n");
    printf("-V           print version\n");
    printf("-v           be verbose\n");
    printf("testbed      path to test bed\n");

    /* Print more detailed help if -v was given.
     */
    if (verbosity > 0) {
    }
}


int
main(int argc, char **argv)
{
    int     posparam_min, posparam_max;
    char   *excludes[256];
    char    options[256];
    char    state[256];
    int     given[256];
    int     i, c;
    char   *pc;

    dprint_stream = stdout;
    eprint_stream = stderr;

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    (void)initstate(time(NULL), state, sizeof(state));

    (void)memset(given, 0, sizeof(given));
    (void)memset(excludes, 0, sizeof(excludes));

    /* The excludes table specifies which combinations of options are permitted to
     * be given on the same command line.  If the first character in the string is
     * a colon, then the option requires an argument.
     */
    excludes['C'] = ":hV";
    excludes['c'] = "hV";
    excludes['h'] = "cimtVv";
    excludes['i'] = ":hV";
    excludes['m'] = "hV";
    excludes['p'] = ":hV";
    excludes['s'] = ":hV";
    excludes['t'] = ":hV";
    excludes['V'] = "chimtv";
    excludes['v'] = "V";

    /* Generate the getopt options string from the excludes table.
     */
    pc = options;
    *pc++ = ':';
    for (i = 0; i < sizeof(excludes)/sizeof(excludes[0]); ++i) {
        if (excludes[i]) {
            *pc++ = i;
            if (':' == excludes[i][0]) {
                *pc++ = ':';
            }
        }
        assert(pc < &options[sizeof(options)]);
    }
    *pc = '\000';

    /* Set posparam_min to the number of expected positional parameters.
     * Set posparm_max to the the maximum number of positional parameters.
     */
    posparam_min = 1;
    posparam_max = 1;

    while (-1 != (c = getopt(argc, argv, options))) {
        for (pc = excludes[c]; pc && *pc; ++pc) {
            if (given[(int)*pc] > 0) {
                eprint("option -%c excludes -%c, use -h for help\n", *pc, c);
                exit(EX_USAGE);
            }
        }
        ++given[c];

        /* TODO: Deal with strtol() errors...
         */
        switch (c) {
        case 'C':
            cf.cf_dir = optarg;
            break;

        case 'h':
            fHelp = !0;
            break;

        case 'i':
            cf.tb_rec_max = strtol(optarg, NULL, 0);
            break;

        case 'm':
            cf.cf_mmap = !0;
            break;

        case 'p':
            cf.cf_procs_max = strtol(optarg, NULL, 0);
            break;

        case 's':
            cf.cf_status_interval = strtol(optarg, NULL, 0);
            break;

        case 't':
            cf.cf_runtime_max = strtol(optarg, NULL, 0);
            break;

        case 'V':
            fVersion = !0;
            break;

        case 'v':
            ++verbosity;
            break;

        case '?':
            eprint("invalid option -%c, use -h for help\n", (char)optopt);
            exit(EX_USAGE);

        case ':':
            eprint("option -%c requires a parameter, use -h for help\n",
                    (char)optopt);
            exit(EX_USAGE);

        default:

            /* We let boolean options slide by since their state can be examined
             * by checking (given[c]).  But if the option requires an argument
             * we print a diagnostic.
             */
            if (excludes[c][0] == ':') {

                /* If you get this error it means you have specified an option 'c'
                 * (with argument) via the excludes[] table, but you don't have a
                 * case to handle it.
                 */
                eprint("programmer error: option -%c requires argument processing\n", (char)c);
                abort();
            }
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if (fHelp) {
        usage();
        return 0;
    } else if (fVersion) {
        printf("%s\n", svnid);
        return 0;
    }

    if (!(given['c'] || given['i'] || given['t'])) {
        eprint("one of -c, -i, or -t must be given, use `-h' for help\n");
        exit(EX_USAGE);
    }

    if (argc < posparam_min) {
        eprint("mandatory arguments required, use `-h' for help\n");
        exit(EX_USAGE);
    } else if (argc > posparam_max) {
        eprint("extraneous arguments detected, use `-h' for help\n");
        exit(EX_USAGE);
    }

#if !HAVE_MMAP
    if (given['m']) {
        eprint("mmap not available on this platform, use `-h' for help\n");
        exit(EX_USAGE);
    }
#endif

    cf.tb_path = argv[0];

    /* TODO: Run these in the order given on the command line...
     */
    if (given['i']) {
        init();
    }
    if (given['t']) {
        test();
    }
    if (given['c']) {
        check();
    }

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
