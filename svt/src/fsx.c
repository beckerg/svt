/*
 * Copyright (c) 2001-2006,2013 Greg Becker.  All rights reserved.
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
 * $Id: dits.c 202 2013-07-05 20:27:35Z greg $
 */

/* dits - Data Integrity Test Suite
 *
 * dits is a tool for validating disk drivers, file systems, and
 * lock managers.  More than an exerciser, dits is able to verify
 * that no detectable data integrity errors have occurred.
 *
 * The tool does its work in three mutually exclusive phases:
 *
 * (1) Init - Write a unique ID to each sector in the test bed.
 *
 * (2) Test - Continuously select arbitrary non-overlapping ranges of
 * sectors and swap them.  File range locking is used to ensure mutual
 * exclusion amongst concurrently executing processes working in the
 * same test bed.
 *
 * (3) Check - Verify that each and every unique ID written in
 * the init phase are intact and neither missing nor duplicated.
 */

static const char svnid[] = "$Id: dits.c 202 2013-07-05 20:27:35Z greg $";
static const char svnrevision[] = "$Revision: 202 $";

/* TODO: Wire this up with autoconf?
 */
#ifndef O_DIRECT
#define _GNU_SOURCE
#endif

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

#if HAVE_AIO_H
#include <aio.h>

/* configure on linux can't seem to tell us that aio_* are defined....
 */
#define HAVE_AIO    1
#endif /* HAVE_AIO_H */

/* TODO: How does one get autoconf to generate HAVE_AIO???
 */
#ifndef HAVE_AIO
#if defined(HAVE_AIO_READ) && defined(HAVE_AIO_WRITE) &&    \
    defined(HAVE_AIO_ERROR) && defined(HAVE_AIO_RETURN) &&  \
    defined(HAVE_AIO_SUSPEND)
#define HAVE_AIO    1
#endif
#endif /* HAVE_AIO_H */

#define NDEBUG

#include "fsx.h"


#if HAVE_AIO
static xaio_t *xaiohead = 0;
#endif /* HAVE_AIO */


/* Variables set by the option parser.
 *
 * f{varname} - flag, true if option was given
 * arg{varname} - optarg argument
 */
int fAIO, fCheck, fConcurrency, fDump, fHelp, fInit, fOSeek;
int fRepair, fTest, fVersion;

#if HAVE_SETPGID
int fSetPGID;
#endif /* HAVE_SETPGID */

int fExec = 1;
int fHdrs = 1;
int fRtck = 1;
char *argSession;

int verbosity = 0;

char *excludes[256];
char given[256];

int64_t maxswapsectors = MAXSWAPSECTORS;
int64_t minswapsectors = MINSWAPSECTORS;
long maxiterations = 0;
u_long maxblksps = 0;           /* Max blocks per second */
off_t oseek = 0;            /* Device seek offset from zero */
int naioreqs = 2;
int nprocs = 4;
char *progname;
time_t gctime = 0;
time_t testtimemax = 0;
char *gtmpdir = "/var/tmp";
int fSigAlarm;
int fSig;

/* Error injection probabilies.
 */
long eipBefore, eipDuring, eipAfter, eipRTCK;

char state[256];            /* For initstate() */


void init(char *partition, int64_t sectors);
void check(char *partition);
void teststart(char *partition);
void test(info_t *infobase, rtck_t *rtckbase, int fdInfo, int fdLock,
          int fdPart, int64_t nsectors);
void dump(char *partition, off_t start, off_t stop);
void chkrgn(FILE *fp, sector_t *sb, off_t offset, size_t len,
            rtck_t *rtckbase, defect_t *d, crc32_t *signature);
void saverollback(sector_t *x, sector_t *y, int64_t nrgns);
void dumprgn(FILE *fp, sector_t *sb, off_t offset, int64_t nrgns,
             rtck_t *rtck, int fHeaders);
void updatergn(sector_t *sb, off_t src, off_t dst, size_t len,
               pid_t pid, time_t time, rtck_t *rtckbase);
int repair(int fdPart, defect_t *d, rtck_t *rtckbase);
int cleanlocks(info_t *victim, int fdInfo, int fdPart, int64_t nsectors,
               rtck_t *rtckbase);
RETSIGTYPE sigHandler(int sig);
RETSIGTYPE sigAlarm(int sig);
void getrgn(int fd, sector_t *sb, off_t offset, size_t len, aiocbptr_t aio);
void putrgn(int fd, sector_t *sb, off_t offset, size_t len, aiocbptr_t aio);
unsigned long svnrev2num(const char *revision);
int getpsize(int fd, off_t *psize);
void getustime(long *utime, long *stime);

int reliable_signal(int signo, sigfunc_t func);

int o_direct = 0;

void
usage()
{
#if HAVE_MMAP
    char *opt_r = "r";
#else
    char *opt_r = "";
#endif /* HAVE_MMAP */

#if HAVE_SETPGID
    char *opt_g = "g";
#else
    char *opt_g = "";
#endif

#if HAVE_AIO
    char *opt_a = " [-a naioreqs]";
#else
    char *opt_a = "";
#endif /* HAVE_AIO */


    printf("usage: %s -i [-Hv] [-o skip] [-S max] partition nblocks\n",
           progname);

    printf("usage: %s -t [-%sHn%svX]%s"
           " [-b bps] [-C nprocs] [-E type:prob] [-I iter] [-o skip]"
           " [-S max] [-s min] [-T ttmax] partition\n",
           progname, opt_g, opt_r, opt_a);

    printf("usage: %s -c [-HRv]%s [-o skip] [-S max] partition\n",
           progname, opt_a);

    printf("usage: %s -d [-Hv] [-o skip] [-S max] "
           "partition [start [stop]]\n", progname);
    printf("usage: %s -h\n", progname);
    printf("usage: %s -V\n", progname);

#if HAVE_AIO
    printf("-a nreqs      use AIO, limit to nreqs outstanding requests\n");
#endif /* HAVE_AIO */

    printf("-b bps        limit throughput to bps blocks/sec\n");
    printf("-C nprocs     set concurrency (default: %d)\n", nprocs);
    printf("-c            check the test bed\n");
    printf("-d            dump the given range of device blocks\n");
    printf("-E type:prob  inject errors of the given type and probability\n");

#if HAVE_SETPGID
    printf("-g            put the master and workers into their own "
           "process group\n");
#endif /* HAVE_SETPGID */

    printf("-H            suppress column headers\n");
    printf("-h            show this help list\n");
    printf("-I iter       max iterations\n");
    printf("-i            initialize test bed\n");
    printf("-N name       specify the session name\n");
    printf("-n            don't perform write operations\n");
    printf("-o skip       skip first skip number of blocks in partition\n");
    printf("-R            attempt to repair a corrupted test bed\n");

#if HAVE_MMAP
    printf("-r            disable run time sanity checking\n");
#endif /* HAVE_MMAP */

    printf("-S max        maximum device blocks to swap (default: %" PRId64 ")\n",
           maxswapsectors);
    printf("-s min        minimum device blocks to swap (default: %" PRId64 ")\n",
           minswapsectors);
    printf("-T ttmax      specify the test mode maximum running time\n");
    printf("-t            run the swap test\n");
    printf("-V            print version\n");
    printf("-v            increase verbosity\n");

#ifdef O_DIRECT
    printf("-X            enable directIO\n");
#endif

    printf("partition  a disk partition, volume, file, etc, ...\n");
    printf("nblocks    number of blocks in test bed\n");
    printf("prob       a probability in the interval [0.0-1.0]\n");
    printf("start      starting block number\n");
    printf("stop       ending block number\n");
    printf("type       one of {rtck,before,during,after}\n");
    printf("ttmax      maximum test mode run time in seconds\n");

    printf("\n(Using a block size of %d bytes)\n", DEV_BSIZE);
}


int
chkexcludes(int c)
{
    char *msg = (char *)0;
    char *pc;
    int i;

    /* First, check to see if any option already given excludes this option.
     */
    for (i = 0; i < 256; ++i) {
        if (given[i]) {
            for (pc = excludes[i]; pc && *pc; ++pc) {
                if (*pc == (char)c) {
                    msg = "excludes";
                    goto done;
                }
            }
        }
    }

    /* Next, check to see if this option excludes any already given.
     */
    for (pc = excludes[c]; pc && *pc; ++pc) {
        if (given[(int)*pc]) {
            msg = "is excluded by";
            i = *pc;
            goto done;
        }
    }

 done:
    if (msg) {
        eprint("%s: option `-%c' %s `-%c', use `-h' for help\n",
               progname, (char)i, msg, (char)c);
        return i;
    }

    return 0;
}


int
decodeErrInject(char *type)
{
    char *pc = optarg;
    double prob;

    while (*pc && (*pc != ':')) {
        ++pc;
    }

    if (*pc == ':') {
        *pc++ = '\000';

        errno = 0;
        prob = strtod(pc, (char **)0);
        if (errno) {
            return errno;
        }
    } else {
        prob = .01; /* One percent */
    }

    if (prob < 0.0 || prob > 1.0) {
        return EINVAL;
    }

    while (*type && isspace((int)*type)) {
        ++type;
    }

    if (0 == strcmp(type, "before")) {
        eipBefore = prob * 1000;
    } else if (0 == strcmp(type, "during")) {
        eipDuring = prob * 1000;
    } else if (0 == strcmp(type, "after")) {
        eipAfter = prob * 1000;
    } else if (0 == strcmp(type, "rtck")) {
        eipRTCK = prob * 1000;
    } else {
        return EINVAL;
    }

    dprint(1, "decodeErrInject: type=%s prob=%.2lf%%\n",
           type, prob * 100);
    dprint(1, "decodeErrInject: total probability that any error "
           "injection event will occur is %.2lf%%\n",
           (1.0 - ((1.0 - eipRTCK/1000.0) * (1.0 - eipBefore/1000.0) *
                   (1.0 - eipDuring/1000.0) * (1.0 - eipAfter/1000.0))) *
           100);
    return 0;
}


int
main(int argc, char **argv)
{
    int nargsexpected;
    int nargsoptional;
    char *envopts;
    int rc;
    int c;

    dprint(3, "sizeof(sector_t) == %lu\n", sizeof(sector_t));
    assert(sizeof(sector_t) == DEV_BSIZE);

#if HAVE_AIO
    assert(sizeof(xaio_t) < sizeof(sector_t));
#endif /* HAVE_AIO */

    progname = strrchr(argv[0], (int)'/');
    progname = (progname ? progname+1 : argv[0]);

    (void)initstate((u_long)time((time_t *)0), state, sizeof(state));
    crc32_init();

    /* TODO: Get options from the environment.
     */
    envopts = getenv("FSX");
    if (envopts) {
        eprint("FSX=%s ignored\n", envopts);
    }

    /* Initialize the option exlusion tables.
     */
    excludes['c'] = "bCEgIhinsTtVX";
    excludes['d'] = "abCcEgIhinoRsTtVX";
    excludes['h'] = "abCcEgdIinoRrsTtVvX";
    excludes['i'] = "abCcdEgIhRsTtVX";
    excludes['R'] = "abCdEghIirsTtVX";
    excludes['t'] = "cdhiRV";
    excludes['V'] = "abCcdEgIhinoRrsSTtvX";

#ifdef O_DIRECT
    excludes['X'] = "cDdhiRV";
#endif

    nargsexpected = 0;
    nargsoptional = 0;

    while (-1 != (c = getopt(argc, argv, ":a:b:C:cdE:HhI:iN:no:RrS:s:T:tVvX"))) {
        if (chkexcludes(c)) {
            exit(EX_USAGE);
        }
        given[c] = c;

        switch (c) {
        case 'a':
#if HAVE_AIO
            fAIO = !0;
            naioreqs = atoi(optarg);
            if ((naioreqs < 2) || (naioreqs > MAXAIOREQS)) {
                eprint("nreqs must be in the interval [2,%d]\n", MAXAIOREQS);
                exit(EX_USAGE);
            }
            if (naioreqs & 0x0001) {
                eprint("nreqs must be a multiple of 2\n");
                exit(EX_USAGE);
            }

            /* TODO: For now we set nprocs to 1 because mulitple
             * procs using aio don't play well together.
             */
            if (fConcurrency && (nprocs > 1)) {
                dprint(0, "Use of AIO not compatible with more than one process.  Using -C1\n");
            }
            nprocs = 1;
#else
            eprint("Not built with -DHAVE_AIO.\n");
            exit(EX_USAGE);
#endif /* HAVE_AIO */
            break;

        case 'b':
            maxblksps = strtoul(optarg, (char **)0, 0);
            break;

        case 'C':
            fConcurrency = !0;
            nprocs = atoi(optarg);
            if (nprocs < 1) {
                eprint("nprocs must be > 0\n");
                exit(EX_USAGE);
            }

            if (fAIO && (nprocs > 1)) {
                dprint(0, "Use of aio not compatible with more than one process.  Using -C1\n");
                nprocs = 1;
            }
            break;

        case 'c':
            fCheck = !0;
            nargsexpected = 1;
            break;

        case 'd':
            fDump = !0;
            nargsexpected = 1;
            nargsoptional = 2;
            break;

        case 'E':
            rc = decodeErrInject(optarg);
            if (rc) {
                eprint("invalid error type or probability\n");
                exit(EX_USAGE);
            }
            break;

        case 'H':
            fHdrs = 0;
            break;

        case 'h':
            fHelp = !0;
            break;

        case 'I':
            maxiterations = strtol(optarg, (char **)0, 0);
            if (maxiterations < 1) {
                eprint("max iterations must be > 0\n");
                exit(EX_USAGE);
            }
            break;

        case 'i':
            fInit = !0;
            nargsexpected = 1;
            nargsoptional = 1;
            break;

        case 'N':
            argSession = optarg;
            break;

        case 'n':
            fExec = 0;
            break;

        case 'o':
            fOSeek = !0;
            oseek = strtoll(optarg, (char **)0, 0);
            if (oseek < 0) {
                eprint("oseek must be >= 0\n");
                exit(EX_USAGE);
            }
            break;

#if HAVE_SETPGID
        case 'g':
            fSetPGID = !0;
            break;
#endif /* HAVE_SETPGID */

        case 'R':
            fRepair = !0;
            break;

        case 'r':
            fRtck = 0;
            break;

        case 'S':
            maxswapsectors = strtoll(optarg, (char **)0, 0);
            if (maxswapsectors < 0) {
                eprint("max swap device blocks must be > 0\n");
                exit(EX_USAGE);
            } else if (maxswapsectors < minswapsectors) {
                eprint("max swap device blocks (%lld) must be >= %lld\n",
                       maxswapsectors, minswapsectors);
                exit(EX_USAGE);
            }
            break;

        case 's':
            minswapsectors = strtoll(optarg, (char **)0, 0);
            if (minswapsectors < 1) {
                eprint("min swap blocks must be > 0\n");
                exit(EX_USAGE);
            } else if (minswapsectors > maxswapsectors) {
                eprint("min swap blocks must be <= %lld\n",
                       maxswapsectors);
                exit(EX_USAGE);
            }
            break;

        case 'T':
            testtimemax = strtol(optarg, (char **)0, 0);
            if (testtimemax < 1) {
                eprint("max run time must be > 0 seconds\n");
                exit(EX_USAGE);
            }
            break;

        case 't':
            fTest = !0;
            nargsexpected = 1;
            break;

        case 'V':
            fVersion = !0;
            break;

        case 'v':
            ++verbosity;
            break;

#ifdef O_DIRECT
        case 'X':
            o_direct = O_DIRECT;
            break;
#endif

        case '?':
            eprint("invalid option `-%c'\n", optopt);
            exit(EX_USAGE);

        default:
            eprint("option `-%c' requires a parameter\n", optopt);
            exit(EX_USAGE);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < nargsexpected) {
        eprint("mandatory arguments required, use `-h' for help\n");
        exit(EX_USAGE);
    } else if (argc > nargsexpected + nargsoptional) {
        eprint("extraneous arguments detected, use `-h' for help\n");
        exit(EX_USAGE);
    }

    if (fInit) {
        int64_t nsectors = 0;

        if (argc > 1) {
            nsectors = strtoll(argv[1], (char **)0, 0);
            if (nsectors < 0) {
                eprint("nblocks < 0... surely you jest?\n");
                exit(EX_USAGE);
            }
        }

        init(argv[0], nsectors);
    } else if (fTest) {
        teststart(argv[0]);
    } else if (fCheck) {
        check(argv[0]);
    } else if (fDump) {
        off_t start = 0;
        off_t stop = 0;

        if (argc > 1) {
            start = strtoll(argv[1], (char **)0, 0);
            if (start < 0) {
                eprint("start must be >= 0\n");
                exit(EX_USAGE);
            }

            stop = start + 1;
        }

        if (argc > 2) {
            stop = strtoll(argv[2], (char **)0, 0);
            if ((stop > 0) && (start > stop)) {
                eprint("stop must be 0 or >= start\n");
                exit(EX_USAGE);
            }
        }

        dump(argv[0], start, stop);
    } else if (fHelp) {
        usage();
    } else if (fVersion) {
        printf("%s.%lu\n", VERSION, svnrev2num(svnrevision));
    } else {
        eprint("one of [-cdhitV] required, use `-h' for help\n");
        exit(EX_USAGE);
    }

    return 0;
}


/* Write a unique record to each sector of the given partition.
 */
void
init(char *partition, int64_t nsectors)
{
    char *partbasename;
    char infopath[128];
    char lockpath[128];
    char rtckpath[128];
    uint32_t revision;
    uint64_t sbflags;
    rtck_t *rtckbase;
    char *src, *dst;
    sector_t *sb;
    size_t sbsz;
    time_t now;
    int fdPart;
    int fdRTCK;
    int i, j;
    int rc;

    now = time((time_t *)0);

    fdPart = open(partition, O_RDWR);
    if (-1 == fdPart) {
        eprint("open(%s): %s\n", partition, strerror(errno));
        exit(EX_OSERR);
    }

    partbasename = strrchr(partition, (int)'/');
    if (!partbasename) {
        partbasename = partition;
    } else {
        ++partbasename;
    }

    /* Use the partition base name for the session name if the
     * session name wasn't specified.
     */
    if (!argSession) {
        argSession = partbasename;
    }

    /* If nsectors is zero then we try to determine and use the full
     * size of the partition.
     */
    if (nsectors == 0) {
        struct stat sb;
        int64_t psize;
        int rc;

        rc = fstat(fdPart, &sb);
        if (rc) {
            eprint("init: fstat(%s): %s\n",
                   partition, strerror(errno));
            exit(EX_OSERR);
        }

        if (S_ISBLK(sb.st_mode)) {
            eprint("Warning: Using block device yields inaccurate "
                   "results in determining partition size\n");
            eprint("Please specify the test bed size.\n");
            exit(EX_USAGE);
        } else if (S_ISCHR(sb.st_mode)) {
            rc = getpsize(fdPart, &psize);
        } else {
            psize = sb.st_size;
        }

        nsectors = psize / DEV_BSIZE;
        if (nsectors <= 0) {
            eprint("Partition/volume/file must be at least "
                   "one %d-byte block\n", DEV_BSIZE);
            exit(EX_USAGE);
        }
    }

    if (-1 == lseek(fdPart, oseek * sizeof(*sb), SEEK_SET)) {
        eprint("init: lseek(%s, %lld): %s\n",
               partition, oseek * sizeof(*sb), strerror(errno));
        exit(EX_OSERR);
    }

    dprint(2, "DEVICE:  \t%s\n", partition);
    dprint(2, "NBLOCKS: \t%lld\n", nsectors);
    dprint(2, "OSEEK:   \t%lld\n", oseek);
    dprint(2, "SESSION: \t%s\n", argSession);

    /* Create the shared run time check table.
     */
    fdRTCK = -1;
    rtckbase = (rtck_t *)0;
    sbflags = 0;

    /* Try to create the run time check file.
     */
    while (fRtck && (fdRTCK == -1)) {
        sbflags |= DITS_FRTCK;

        (void)snprintf(rtckpath, sizeof(rtckpath), "%s/%s-rtck-%s",
                       gtmpdir, progname, argSession);

        dprint(2, "Creating primary rtck file: %s\n", rtckpath);

        fdRTCK = open(rtckpath, O_CREAT|O_TRUNC|O_RDWR, 0600);
        if (-1 == fdRTCK) {
            dprint(2, "open(%s): %s\n",
                   rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        if (-1 == ftruncate(fdRTCK, nsectors * sizeof(*rtckbase))) {
            eprint("ftruncate(%s, %lld): %s\n",
                   rtckpath, nsectors * sizeof(*rtckbase),
                   strerror(errno));
            exit(EX_OSERR);
        }

        rtckbase = (rtck_t *)
            mmap((void *)0, nsectors * sizeof(*rtckbase),
                 PROT_READ|PROT_WRITE, MAP_SHARED, fdRTCK, 0);
        if (rtckbase == MAP_FAILED) {
            eprint("mmap(%s): %s\n", rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        /* Fill the whole file with zero writes so as
         * to prevent fragmentation.
         */
        bzero(rtckbase, nsectors * sizeof(*rtckbase));
    }

    sbsz = maxswapsectors * sizeof(*sb);
    sb = malloc(sbsz);
    if (!sb) {
        eprint("malloc(%d) failed\n", sbsz);
        exit(EX_OSERR);
    }
    bzero(sb, sbsz);

    revision = svnrev2num(svnrevision);

    /* We buffer a "region" of changes and write them out
     * in one call to write().
     */
    for (i = 0; i < nsectors; i += maxswapsectors) {
        size_t min;

        min = DITS_MIN(nsectors - i, maxswapsectors);

        for (j = 0; j < min; ++j) {
            record_t *r = &sb[j].rec[0];

            sb[j].magic = DITS_MAGIC;
            sb[j].revision = revision;
            sb[j].flags = sbflags;

            /* Initialize the invariant fields.
             */
            r[0].id = i + j;
            r[0].nsectors = nsectors;
            r[0].ctime = now;

            r[1] = r[0];
            r[1].id = -1;

            (void)strncpy(sb[j].session, argSession,
                          sizeof(sb[j].session));
            sb[j].session[sizeof(sb[j].session)-1] = '\0';
        }

        bcopy(state, sb->payload, sizeof(sb->payload));

        dprint(3, "Initializing blocks [%8lld - %-8lld]\n",
               i + oseek, i + oseek + min - 1);

        updatergn(sb, i, i, min, -1, now, rtckbase);
        putrgn(fdPart, sb, i, min, (aiocbptr_t)0);
    }

    if (-1 != fdRTCK) {
        rc = fsync(fdRTCK);
        if (rc) {
            eprint("init: fsync(%s): %s\n",
                   rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        (void)close(fdRTCK);
    }
    free(sb);
    (void)close(fdPart);

    /* Remove the info and lock files if they for some reason exist.
     */
    (void)snprintf(infopath, sizeof(infopath),
                   "%s/%s-info-%s", gtmpdir, progname, argSession);
    (void)unlink(infopath);

    (void)snprintf(lockpath, sizeof(lockpath),
                   "%s/%s-locks-%s", gtmpdir, progname, argSession);
    (void)unlink(lockpath);
}


/* Allocate a defect table.  This can be quite large for a large test bed.
 */
defect_t *
defect_alloc(int64_t nsectors)
{
    defect_t *d;

    d = malloc(sizeof(*d));
    if (!d) {
        eprint("defect_alloc: malloc(%lu) failed\n", sizeof(*d));
        return (defect_t *)0;
    }
    bzero((char *)d, sizeof(*d));

    d->x = malloc(sizeof(*d->x) * nsectors);
    if (!d->x) {
        eprint("defect_alloc: malloc(%lu) failed\n",
               sizeof(*d->x) * nsectors);
        free(d);
        return (defect_t *)0;
    }
    memset(d->x, -1, sizeof(*d->x) * nsectors);

    d->y = malloc(sizeof(*d->y) * nsectors);
    if (!d->y) {
        eprint("defect_alloc: malloc(%lu) failed\n",
               sizeof(*d->y) * nsectors);
        free(d->x);
        return (defect_t *)0;
    }
    memset(d->y, -1, sizeof(*d->y) * nsectors);

    d->id = malloc(sizeof(*d->id) * nsectors);
    if (!d->id) {
        eprint("defect_alloc: malloc(%lu) failed\n",
               sizeof(*d->id) * nsectors);
        free(d->y);
        free(d->x);
        return (defect_t *)0;
    }
    memset(d->id, -1, sizeof(*d->id) * nsectors);

    d->crc = malloc(sizeof(*d->crc) * nsectors);
    if (!d->crc) {
        eprint("defect_alloc: malloc(%lu) failed\n",
               sizeof(*d->crc) * nsectors);
        free(d->id);
        free(d->y);
        free(d->x);
        return (defect_t *)0;
    }
    memset(d->crc, -1, sizeof(*d->crc) * nsectors);

    d->msg = malloc(sizeof(*d->msg) * nsectors);
    if (!d->msg) {
        eprint("defect_alloc: malloc(%lu) failed\n",
               sizeof(*d->msg) * nsectors);
        free(d->crc);
        free(d->id);
        free(d->y);
        free(d->x);
        return (defect_t *)0;
    }
    memset(d->msg, 0, sizeof(*d->msg) * nsectors);

    d->nsectors = nsectors;
    d->ndefects = 0;

    return d;
}


void
defect_free(defect_t *d)
{
    int i;

    if (d) {
        for (i = 0; i < d->nsectors; ++i) {
            if (d->msg[i]) {
                free(d->msg[i]);
            }
        }

        free(d->msg);
        free(d->crc);
        free(d->id);
        free(d->y);
        free(d->x);
        free(d);
    }
}


/* Check that all the data written by init() is intact and that there
 * are no missing nor duplicated records.
 */
void
check(char *partition)
{
    char *partbasename;
    char infopath[128];
    char lockpath[128];
    char rtckpath[128];
    crc32_t signature;
    struct stat stat;
    rtck_t *rtckbase;
    int64_t nsectors;
    char *src, *dst;
    char hdr[128];
    sector_t *sb;
    defect_t *d;
    size_t sbsz;
    int64_t rgn;
    int fdRTCK;
    int fdPart;
    int nerrs;
    int64_t i;
    int rc;

    fdRTCK = -1;
    rtckbase = (rtck_t *)0;

    fdPart = open(partition, (fRepair ? O_RDWR : O_RDONLY));
    if (-1 == fdPart) {
        eprint("check(%s): open: %s\n", partition, strerror(errno));
        exit(EX_OSERR);
    }

    /* Get the base name of the partition.
     */
    partbasename = strrchr(partition, '/');
    if (!partbasename) {
        partbasename = partition;
    } else {
        ++partbasename;
    }

    sbsz = maxswapsectors * sizeof(*sb);
    sb = malloc(sbsz);
    if (!sb) {
        eprint("check(%s): malloc(%lu) failed\n",
               partition, sbsz);
        exit(EX_OSERR);
    }

    /* Get the first record which tells how many records are
     * in the test bed.
     */
    getrgn(fdPart, sb, 0, (int64_t)1, (aiocbptr_t)0);
    chkrgn(stderr, sb, 0, (int64_t)1,
           (rtck_t *)0, (defect_t *)0, (crc32_t *)0);
    nsectors = sb->rec[0].nsectors;
    gctime = sb->rec[0].ctime;

    dprint(2, "DEVICE:  \t%s\n", partition);
    dprint(2, "NBLOCKS: \t%lld\n", nsectors);
    dprint(2, "OSEEK:   \t%lld\n", oseek);
    dprint(2, "SESSION: \t%s\n", sb->session);
    dprint(2, "CTIME:   \t%s", ctime((time_t *)&gctime));

    /* Use the partition base name for the session name if the
     * session name wasn't specified.
     */
    if (!argSession) {
        static char session[128];

        (void)strncpy(session, sb->session, sizeof(session));
        session[sizeof(session) - 1] = '\000';
        argSession = session;
    }

#if HAVE_MMAP
    /* Try to open the run time check file, but proceed regardless
     * of whether one is found.
     */
    while (fRtck && (fdRTCK == -1) && (sb->flags & DITS_FRTCK)) {
        (void)snprintf(rtckpath, sizeof(rtckpath), "%s/%s-rtck-%s",
                       gtmpdir, progname, argSession);

        fdRTCK = open(rtckpath, O_RDWR);
        if (-1 == fdRTCK) {
            eprint("The run time check file %s could not be "
                   "opened.\n", rtckpath);
            eprint("open(%s): %s\n", rtckpath, strerror(errno));
            break;
        }

        rtckbase = (rtck_t *)
            mmap((void *)0, nsectors * sizeof(*rtckbase),
                 PROT_READ|PROT_WRITE, MAP_SHARED, fdRTCK, 0);
        if (rtckbase == MAP_FAILED) {
            eprint("mmap(%s): %s\n",
                   rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        /* Check that the number of entries in the mapped run time
         * cross check file agrees with the size of the test bed that
         * we just determined from the first sector in the test bed.
         */
        rc = fstat(fdRTCK, &stat);
        if (rc) {
            eprint("fstat(%s): %s\n", rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        if (stat.st_size != (nsectors * sizeof(*rtckbase))) {
            eprint("The number of blocks (%lld) as read from "
                   "the first block in the test bed "
                   "doesn't agree with the number of entries "
                   "in the run time cross check file (%lld)\n",
                   (long long)nsectors,
                   (long long)stat.st_size / sizeof(*rtckbase));
            exit(EX_DATAERR);
        }

        /* TODO: Attempt to lock the file and deal with issues
         * arising from some other process using the file.
         */

        dprint(2, "Using rtck file: %s\n", rtckpath);
    }
#else
#error "TODO - this implementation does not support mmap"
#endif /* HAVE_MMAP */

    d = defect_alloc(nsectors + oseek);
    if (!d) {
        exit(EX_OSERR);
    }

    /* Iteratively read in chunks of the test bed so that chkrgn can
     * check the region and populate the defect table for each chunk.
     */
    signature = 0;

    dprint(2, "Reading %lld blocks...\n", nsectors);

    if (fAIO) {
#if HAVE_AIO
        xaio_t **axaio;
        xaio_t *xrd;
        size_t min;
        ssize_t cc;
        int gbrc;
        int ichk;
        int ird;

        ird = ichk = 0;

        axaio = malloc(naioreqs * sizeof(*axaio));
        assert(axaio);
        bzero(axaio, naioreqs * sizeof(*axaio));

        for (rgn = 0; rgn < nsectors; rgn += maxswapsectors) {
            min = DITS_MIN(nsectors - rgn, maxswapsectors);

            gbrc = getxaiobuf(min, -1, &xrd, (xaio_t **)0);
            assert(!gbrc);

            getrgn(fdPart, xrd->sb, rgn, xrd->nrgns, &xrd->aio);

            assert(!axaio[ird % naioreqs]);
            axaio[ird++ % naioreqs] = xrd;

            if ((ird % naioreqs) == (ichk % naioreqs)) {
                struct aiocb *araio[2];
                int64_t rgnchk;
                xaio_t *xchk;

                xchk = axaio[ichk % naioreqs];
                assert(xchk);
                araio[0] = &xchk->aio;

                rc = AIO_ERROR(&xchk->aio);
                if (rc) {
                    if (rc != EINPROGRESS) {
                        perror("aio_error");
                        exit(1);
                    }

                    rc = AIO_SUSPEND(araio, 1);
                    if (rc) {
                        perror("aio_suspend");
                        exit(1);
                    }
                }

                cc = aio_return(&xchk->aio);
                if (cc != xchk->aio.aio_nbytes) {
                    eprint("check: aio_return: cc (%lu) "
                           "!= aio_nbytes (%lu)\n",
                           cc, xchk->aio.aio_nbytes);
                    exit(EX_OSERR);
                }

                rgnchk = xchk->aio.aio_offset /
                    sizeof(*xchk->sb);
                dprint(3, "Checking blocks "
                       "[%8lld - %-8lld]  Signature: ",
                       rgnchk + oseek,
                       rgnchk + oseek + xchk->nrgns,
                       signature);

                chkrgn(stderr, xchk->sb, rgnchk,
                       xchk->nrgns, rtckbase, d, &signature);
        
                dprint(3, "%lX\n", signature);

                freexaiobuf(xchk, (xaio_t *)0);
                axaio[ichk++ % naioreqs] = (xaio_t *)0;
            }
        }

        while (ichk < ird) {
            struct aiocb *araio[1];
            xaio_t *xchk;
            int64_t rgnchk;

            xchk = axaio[ichk % naioreqs];
            assert(xchk);
            araio[0] = &xchk->aio;

            rc = AIO_ERROR(&xchk->aio);
            if (rc) {
                if (rc != EINPROGRESS) {
                    perror("aio_error");
                    exit(1);
                }

                rc = AIO_SUSPEND(araio, 1);
                if (rc) {
                    perror("aio_suspend");
                    exit(1);
                }
            }

            cc = aio_return(&xchk->aio);
            if (cc != xchk->aio.aio_nbytes) {
                eprint("check: aio_return: cc (%lu) "
                       "!= aio_nbytes (%lu)\n",
                       cc, xchk->aio.aio_nbytes);
                exit(EX_OSERR);
            }

            rgnchk = xchk->aio.aio_offset / sizeof(*xchk->sb);
            dprint(3, "Checking blocks [%8lld - %-8lld]  "
                   "Signature: ",
                   rgnchk + oseek,
                   rgnchk + oseek + xchk->nrgns,
                   signature);

            chkrgn(stderr, xchk->sb, rgnchk,
                   xchk->nrgns, rtckbase, d, &signature);
        
            dprint(3, "%lX\n", signature);

            freexaiobuf(xchk, (xaio_t *)0);
            axaio[ichk % naioreqs] = (xaio_t *)0;
            ++ichk;
        }

        free(axaio);
#endif /* HAVE_AIO */
    } else {
        for (rgn = 0; rgn < nsectors; rgn += maxswapsectors) {
            size_t min;

            min = DITS_MIN(nsectors - rgn, maxswapsectors);

            dprint(3, "Checking blocks [%8lld - %-8lld]  "
                   "Signature: ",
                   rgn + oseek, rgn + min + oseek, signature);

            getrgn(fdPart, sb, rgn, min, (aiocbptr_t)0);
            chkrgn(stderr, sb, rgn, min,
                   rtckbase, d, &signature);
            dprint(3, "%lX\n", signature);
        }

        dprint(3, "\n");
    }


    if (fRepair) {
        rc = repair(fdPart, d, rtckbase);
    }

    /* Check that each record id maps to one and only one sector.
     */
    nerrs = 0;
    hdr[0] = '\000';
    if (fHdrs) {
        (void)snprintf(hdr, sizeof(hdr),
					   "%8s %8s %8s %8s  %8s %3s %s\n",
					   "LBA", "ID", "TO", "DUPTO", "CRC", "", "DETAILS");
    }

    for (i = 0; i < nsectors; ++i) {
        if (d->x[i] == -1) {
            char rtckmsg[1024] = "\000";

            /* If the rtck file exists, try to find the LBA
             * where the missing record should have been.
             */
            if (rtckbase) {
                int64_t j;

                snprintf(rtckmsg, sizeof(rtckmsg),
                         ", ID %" PRId64 "not found in rtck file",
                         d->id[i] + oseek);
                for (j = 0; j < nsectors; ++j) {
                    if (rtckbase[j].id == d->id[i]) {
                        snprintf(rtckmsg, sizeof(rtckmsg),
                                 ", should have been at LBA %" PRId64, j + oseek);
                        break;
                    }
                }
            }

            dprint(0, "%s%8lu %8lld %8lld %8lld  %08lx  M  %s%s\n",
                   hdr, (u_long)i, d->id[i],
                   d->x[i], d->y[i], d->crc[i],
                   d->msg[i] ? d->msg[i] : "Record missing",
                   rtckmsg);
            ++nerrs;
            hdr[0] = '\000';
        } else if (d->y[i] != -1) {
            dprint(0, "%s%8lu %8lld %8lld %8lld  %08lx  D  %s\n",
                   hdr, (u_long)i, d->id[i],
                   d->x[i], d->y[i], d->crc[i],
                   d->msg[i] ? d->msg[i] :
                   "Duplicate record at device block ???");
            ++nerrs;
            hdr[0] = '\000';
        } else if ((verbosity > 3) || d->msg[i]) {
            dprint(0, "%s%8lu %8lld %8lld %8lld  %08lx     %s\n",
                   hdr, (u_long)i, d->id[i],
                   d->x[i], d->y[i], d->crc[i],
                   d->msg[i] ? d->msg[i] : "");
            hdr[0] = '\000';
        }
    }

    if (nerrs) {
        dprint(0, "Data integrity errors: %d\n", nerrs);
        exit(EX_DATAERR);
    }

    if (fHdrs) {
        dprint(1, "DEVICE        NBLOCKS  INPLACE             "
               "SIGNATURE\n");
    }

    dprint(1, "%-12s %8lld %8lld (%07.3f%%)  %lX\n",
           partbasename, d->nsectors, d->inplace,
           (d->inplace * 100.0)/d->nsectors, signature);

    /* Remove the info file if it exists.
     */
    (void)snprintf(infopath, sizeof(infopath),
                   "%s/%s-info-%s", gtmpdir, progname, argSession);
    if (-1 != unlink(infopath)) {
        dprint(2, "Info file %s removed.\n", infopath);
    }

    (void)snprintf(lockpath, sizeof(lockpath),
                   "%s/%s-locks-%s", gtmpdir, progname, argSession);
    if (-1 != unlink(lockpath)) {
        dprint(2, "Lock file %s removed.\n", lockpath);
    }

    if (-1 != fdRTCK) {
        (void)close(fdRTCK);
    }
    defect_free(d);
    free(sb);
    (void)close(fdPart);
}


/* Scan the defect list for duplicate records (i.e., records with the same
 * ID field) and roll them back.  Rollback is accomplished by copying the
 * rollback record (i.e., sector.rec[1]) to the primary record (sector.rec[0]).
 *
 * d->x[id] contains the LBA of the first sector that contains a record with
 * an ID field that matches 'id'.
 * d->y[id] contains the LBA of the second sector (if any) that matches 'id'.
 * I.e., the sector address of the first occurrence of a record ID is in
 * d->x[id], and the second occurrence, if any, is in d->y[id].
 */
int
repair(int fdPart, defect_t *d, rtck_t *rtckbase)
{
    int64_t nrtckcorrections;
    int64_t nrollbacks;
    sector_t x, y;
    int64_t id;
    int rc = 0;

    dprint(2, "Examining %lld defects from %lld blocks...\n",
           d->ndefects, d->nsectors);

    nrollbacks = 0;
    nrtckcorrections = 0;

    /* The defect table is indexed by record ID.  Scan the table
     * for each possible ID in the test bed to see if it needs
     * to be rolled back (i.e., both x[id] and y[id] are not -1).
     */
    for (id = 0; id < d->nsectors; ++id) {
        if (d->msg[id]) {
            dprint(2, "repair: LBA %lld: %s\n",
                   d->x[id] + oseek, d->msg[id]);
        }

        if (d->x[id] == -1) {
            continue;
        }

        if (d->y[id] == -1) {
            if (!rtckbase) {
                continue;
            }

            /* Not a duplicate, but check to ensure the rtck
             * file and on-disk record are in agreement.  If
             * not, force the rtck file into compliance.
             */
            if ((rtckbase[d->x[id]].id == d->id[id]) &&
                (rtckbase[d->x[id]].crc == d->crc[id])) {
                continue;
            }

            getrgn(fdPart, &x, d->x[id], (int64_t)1, (aiocbptr_t)0);

            if ((rtckbase[d->x[id]].id != x.rec[0].id) ||
                (rtckbase[d->x[id]].crc != x.crc)) {
                dprint(2, "repair: rtck rollback "
                       "LBA %lld: ID(%lld <- %lld)  "
                       "CRC(0x%lx <- 0x%lx)\n",
                       d->x[id] + oseek,
                       rtckbase[d->x[id]].id, x.rec[0].id,
                       rtckbase[d->x[id]].crc, x.crc);

                /* The rtck file is indexed by LBA, not ID.
                 */
                rtckbase[d->x[id]].id = x.rec[0].id;
                rtckbase[d->x[id]].crc = x.crc;
                ++nrtckcorrections;
            }
            continue;
        }

        dprint(2, "repair: duplicate IDs found at LBAs "
               "%lld and %lld\n",
               d->x[id] + oseek, d->y[id] + oseek);

        getrgn(fdPart, &x, d->x[id], (int64_t)1, (aiocbptr_t)0);
        dumprgn(stdout, &x, d->x[id], (int64_t)1, (rtck_t *)0, 1);

        getrgn(fdPart, &y, d->y[id], (int64_t)1, (aiocbptr_t)0);
        dumprgn(stdout, &y, d->y[id], (int64_t)1, (rtck_t *)0, 0);

        /* If the ID's don't match, then these sectors were not
         * involved in the same interrupted swap transaction.  The
         * implications are that this record has occurred more than
         * twice, meaning there are serious problems somewhere.
         */
        if (x.rec[0].id != y.rec[0].id) {
            eprint("repair: ID mismatch: LBA/ID: "
                   "%lld/%lld %lld/%lld\n",
                   d->x[id] + oseek, x.rec[0].id,
                   d->y[id] + oseek, y.rec[0].id);
            rc = EINVAL;
            continue;
        }

        /* Roll back the problem sector.  Given any record, the
         * source field is the LBA of the record's previous
         * position in the testbed.  One of the duplicate records
         * should have a source address of the other, and that
         * is the record we want to roll back.  Rollback is
         * accomplished by copying the saved record state (e.g.,
         * x.rec[1] to the primary record state (x.rec[0]).
         */
        if (x.rec[0].src == d->y[id]) {
            dprint(2, "repair: rolling back x record for "
                   "LBA %lld\n", d->x[id] + oseek);

            x.rec[0] = x.rec[1];
            ++x.rec[0].nrollbacks;

            bzero(&x.rec[1], sizeof(x.rec[1]));
            x.rec[1].id = -1;

            x.kscratch = 0;
            x.crc = 0;
            x.crc = crc32((u_char *)&x, sizeof(x), CRC32_PRELOAD);

            putrgn(fdPart, &x, d->x[id], 1, (aiocbptr_t)0);
            assert(d->x[x.rec[0].id] == -1);
        } else if (y.rec[0].src == d->x[id]) {
            dprint(2, "repair: rolling back y record for "
                   "LBA %lld\n", d->y[id] + oseek);

            y.rec[0] = y.rec[1];
            ++y.rec[0].nrollbacks;

            bzero(&y.rec[1], sizeof(y.rec[1]));
            y.rec[1].id = -1;

            y.kscratch = 0;
            y.crc = 0;
            y.crc = crc32((u_char *)&y, sizeof(y), CRC32_PRELOAD);

            putrgn(fdPart, &y, d->y[id], 1, (aiocbptr_t)0);
            assert(d->x[y.rec[0].id] == -1);
        } else {
            eprint("repair: houston, we have a problem...\n");
            assert(0);
        }

        /* Now, updated the run time check file to reflect what's
         * on disk.  The rtck file is indexed by LBA, not ID.
         */
        if (rtckbase) {
            if ((rtckbase[d->x[id]].id != x.rec[0].id) ||
                (rtckbase[d->x[id]].crc != x.crc)) {
                dprint(2, "repair: rolling back rtck for "
                       "LBA %lld: "
                       "ID(%lld <- %lld) "
                       "CRC(0x%lx <- 0x%lx)\n",
                       d->x[id] + oseek,
                       rtckbase[d->x[id]].id, x.rec[0].id,
                       rtckbase[d->x[id]].crc, x.crc);

                rtckbase[d->x[id]].id = x.rec[0].id;
                rtckbase[d->x[id]].crc = x.crc;
                ++nrtckcorrections;
            }

            if ((rtckbase[d->y[id]].id != y.rec[0].id) ||
                (rtckbase[d->y[id]].crc != y.crc)) {
                dprint(2, "repair: rolling back rtck for "
                       "LBA %lld: "
                       "ID(%lld <- %lld) "
                       "CRC(0x%lx <- 0x%lx)\n",
                       d->y[id] + oseek,
                       rtckbase[d->y[id]].id, y.rec[0].id,
                       rtckbase[d->y[id]].crc, y.crc);

                rtckbase[d->y[id]].id = y.rec[0].id;
                rtckbase[d->y[id]].crc = y.crc;
                ++nrtckcorrections;
            }
        }

        d->y[id] = -1;
        ++nrollbacks;

        dprint(2, "\n");
    }

    dprint(1, "repair: %lld defects, %lld of %lld blocks rolled back, "
           "%lld rtck file corrections\n",
           d->ndefects, nrollbacks, d->nsectors, nrtckcorrections);

    return rc;
}


/* Print detailed information about the records in the specified range.
 */
void
dump(char *partition, off_t start, off_t stop)
{
    char *partbasename;
    char infopath[128];
    char rtckpath[128];
    int64_t nsectors;
    rtck_t *rtckbase;
    char *src, *dst;
    sector_t *sb;
    size_t sbsz;
    int64_t rgn;
    int fdRTCK;
    int fdPart;
    int64_t i;
    int hdr;

    assert(start >= 0);

    fdPart = open(partition, O_RDONLY);
    if (-1 == fdPart) {
        eprint("dump: open(%s): %s\n", partition, strerror(errno));
        exit(EX_OSERR);
    }

    sbsz = maxswapsectors * sizeof(*sb);
    sb = malloc(sbsz);
    if (!sb) {
        eprint("dump: malloc(%lu) failed\n", sbsz);
        exit(EX_OSERR);
    }

    /* Get the first record which tells how many records are
     * in the test bed.
     */
    getrgn(fdPart, sb, 0, (int64_t)1, (aiocbptr_t)0);
    chkrgn(stdout, sb, 0, (int64_t)1,
           (rtck_t *)0, (defect_t *)0, (crc32_t *)0);
    nsectors = sb->rec[0].nsectors;
    gctime = sb->rec[0].ctime;

    dprint(2, "DEVICE:  \t%s\n", partition);
    dprint(2, "NBLOCKS: \t%lld\n", nsectors);
    dprint(2, "OSEEK:   \t%lld\n", oseek);
    dprint(2, "SESSION: \t%s\n", sb->session);

    if (start < oseek) {
        eprint("start (%lld) lies outside the test bed LBA range "
               "[%lld, %lld]\n",
               start, oseek, nsectors + oseek);
        exit(EX_USAGE);
    } else if (start >= nsectors + oseek) {
        eprint("start (%lld) lies outside the test bed LBA range "
               "[%lld, %lld]\n",
               start, oseek, nsectors + oseek);
        exit(EX_USAGE);
    }

    if (stop == 0) {
        stop = nsectors;
    } else if (stop < start) {
        dprint(1, "limiting stop to %lld\n", nsectors);
        stop = nsectors;
    }

    /* Get the base name of the partition.
     */
    partbasename = strrchr(partition, '/');
    if (!partbasename) {
        partbasename = partition;
    } else {
        ++partbasename;
    }

    /* Use the session name from the testbed if the session
     * name wasn't specified.
     */
    if (!argSession) {
        static char session[128];

        (void)strncpy(session, sb->session, sizeof(session));
        session[sizeof(session) - 1] = '\000';
        argSession = session;
    }

#if HAVE_MMAP
    fdRTCK = -1;
    rtckbase = (rtck_t *)0;

    /* Try to open the run time check table.
     */
    while (fRtck && (fdRTCK == -1) && (sb->flags & DITS_FRTCK)) {
        (void)snprintf(rtckpath, sizeof(rtckpath), "%s/%s-rtck-%s",
                       gtmpdir, progname, argSession);
        fdRTCK = open(rtckpath, O_RDWR);
        if (-1 == fdRTCK) {
            eprint("The run time check file %s could not be "
                   "opened.\n", rtckpath);
            eprint("open(%s): %s\n", rtckpath, strerror(errno));
            break;
        }

        rtckbase = (rtck_t *)
            mmap((void *)0, nsectors * sizeof(*rtckbase),
                 PROT_READ|PROT_WRITE, MAP_SHARED, fdRTCK, 0);
        if (rtckbase == MAP_FAILED) {
            eprint("mmap(%s): %s\n", rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        dprint(2, "using rtck file: %s\n", rtckpath);
    }
#else
#error TODO - this implementation does not support mmap
#endif /* HAVE_MMAP */

    /* Iteratively read in chunks of the test bed so that chkrgn
     * can populate the defect table for each chunk.
     */
    hdr = 0;
    for (rgn = start; rgn < stop; rgn += maxswapsectors) {
        size_t min;

        min = DITS_MIN(stop - rgn, maxswapsectors);

        dprint(3, "reading blocks [%8lld-%-8lld]\n",
               rgn + oseek, rgn + oseek + min);

        getrgn(fdPart, sb, rgn, min, (aiocbptr_t)0);
        dumprgn(stdout, sb, rgn, min, rtckbase, (hdr++ % 7) == 0);
    }

    if (-1 != fdRTCK) {
        (void)close(fdRTCK);
    }
    free(sb);
    (void)close(fdPart);
}


void
dumprgn(FILE *fp, sector_t *sb, off_t offset, int64_t nrgns,
        rtck_t *rtckbase, int fHeaders)
{
    char msg[256];
    int i, j;

    if (fHeaders) {
        snprintf(msg, sizeof(msg),
                 "%8s %3s %8s %6s %8s %8s %8s %8s %6s %8s %4s",
                 "LBA", "TYP", "ID", "PID", "CTIME", "MTIME", "SRC",
                 "DST", "LEN", "CRC",  "NRBKS");
        fprintf(fp, "%s\n", msg);
    }

    for (i = 0; i < nrgns; ++i, ++sb) {
        snprintf(msg, sizeof(msg),
                 "%8" PRId64 "PRI %8" PRId64 "%6" PRId64 "%8" PRIx64 "%8" PRIx64
                 " %8" PRId64 "%8" PRId64 "%6d %08x %5d",
                 offset + i + oseek,
                 sb->rec[0].id, sb->rec[0].pid,
                 sb->rec[0].ctime, sb->rec[0].mtime,
                 sb->rec[0].src, sb->rec[0].dst,
                 sb->rec[0].len, sb->crc,
                 sb->rec[0].nrollbacks);

        fprintf(fp, "%s\n", msg);

        if (verbosity > 1) {
            snprintf(msg, sizeof(msg),
                     "%8" PRId64 "RBK %8" PRId64 " %6" PRId64 " %8" PRIx64 " %8" PRIx64
                     " %8" PRId64 "%8" PRId64 "%6d %08x %5d",
                     offset + i + oseek,
                     sb->rec[1].id, sb->rec[1].pid,
                     sb->rec[1].ctime, sb->rec[1].mtime,
                     sb->rec[1].src, sb->rec[1].dst,
                     sb->rec[1].len, sb->crc,
                     sb->rec[1].nrollbacks);

            fprintf(fp, "%s\n", msg);
        }
    }
}


/* Start some number of child processes to do the actual work of
 * region swapping.
 */
void
teststart(char *partition)
{
    char *partbasename;
    char lockpath[128];
    char infopath[128];
    char rtckpath[128];
    char *psrc, *pdst;
    int64_t nsectors;
    info_t *infobase;
    rtck_t *rtckbase;
    struct stat stat;
    info_t *victim;
    char *devname;
    sector_t sb;
    int fdRTCK;
    int fdInfo;
    int fdLock;
    int fdPart;
    pid_t pid;
    int64_t i;
    int fRun;
    int rc;

    /* Open the data partition (i.e., the testbed).
     */
    fdPart = open(partition, O_RDWR | o_direct);
    if (-1 == fdPart) {
        eprint("open(%s): %s\n", partition, strerror(errno));
        exit(EX_OSERR);
    }

    /* Get the base name of the partition.
     */
    partbasename = strrchr(partition, '/');
    if (!partbasename) {
        partbasename = partition;
    } else {
        ++partbasename;
    }

    /* Get the first record so as to find out the total number
     * of records involved in the test.
     */
    getrgn(fdPart, &sb, 0, (int64_t)1, (aiocbptr_t)0);
    chkrgn(stderr, &sb, 0, (int64_t)1,
           (rtck_t *)0, (defect_t *)0, (crc32_t *)0);
    nsectors = sb.rec[0].nsectors;
    gctime = sb.rec[0].ctime;

    dprint(2, "DEVICE:  \t%s\n", partition);
    dprint(2, "NBLOCKS: \t%lld\n", nsectors);
    dprint(2, "OSEEK:   \t%lld\n", oseek);
    dprint(2, "SESSION: \t%s\n", sb.session);
    dprint(2, "CTIME:   \t%s", ctime((time_t *)&gctime));

    /* Use the session name from the testbed if the session
     * name wasn't specified.
     */
    if (!argSession) {
        static char session[128];

        (void)strncpy(session, sb.session, sizeof(session));
        session[sizeof(session) - 1] = '\000';
        argSession = session;
    }

#if HAVE_MMAP
    /* Open the run time check table.
     */
    fdRTCK = -1;
    rtckbase = (rtck_t *)0;

    /* Try to open the run time check file, but proceed regardless
     * of whether one is found.
     */
    while (fRtck && (fdRTCK == -1) && (sb.flags & DITS_FRTCK)) {
        (void)snprintf(rtckpath, sizeof(rtckpath), "%s/%s-rtck-%s",
                       gtmpdir, progname, argSession);

        fdRTCK = open(rtckpath, O_RDWR);
        if (-1 == fdRTCK) {
            eprint("The primary run time check file %s could "
                   "not be opened.\n", rtckpath);
            eprint("open(%s): %s\n", rtckpath, strerror(errno));
            break;
        }

        rtckbase = (rtck_t *)
            mmap((void *)0, nsectors * sizeof(*rtckbase),
                 PROT_READ|PROT_WRITE, MAP_SHARED, fdRTCK, 0);
        if (rtckbase == MAP_FAILED) {
            eprint("mmap(%s): %s\n", rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        rc = fstat(fdRTCK, &stat);
        if (rc) {
            eprint("fstat(%s): %s\n", rtckpath, strerror(errno));
            exit(EX_OSERR);
        }

        dprint(2, "Using primary rtck file: %s\n", rtckpath);

        /* Check that the number of entries in the mapped run time
         * cross check file agrees with the size of the test bed that
         * we just determined from the first sector in the test bed.
         */
        if (stat.st_size != (nsectors * sizeof(*rtckbase))) {
            eprint("The number of blocks (%lld) as read from "
                   "the first block in the test bed "
                   "doesn't agree with the number of entries "
                   "in the run time cross check file (%lld)\n",
                   (long long)nsectors,
                   (long long)stat.st_size / sizeof(*rtckbase));
            exit(EX_DATAERR);
        }
    }
#else
#error TODO - this implementation does not support mmap
#endif /* HAVE_MMAP */

    /* Create the lock file.  We use a lock file rather than the
     * partition because file locking doesn't work on device special
     * files.  Each byte in the lock file represents one sector in
     * the partition file.
     */
    (void)snprintf(lockpath, sizeof(lockpath), "%s/%s-locks-%s",
                   gtmpdir, progname, argSession);
    fdLock = open(lockpath, O_CREAT|O_EXCL|O_RDWR, 0600);
    if (-1 == fdLock) {
        eprint("Test bed is dirty.  Run `%s -cRv' to repair.\n",
               lockpath, progname);
        eprint("open(%s): %s\n", lockpath, strerror(errno));
        exit(EX_OSERR);
    }

    if (-1 == ftruncate(fdLock, nsectors)) {
        eprint("ftruncate(%s): %s\n", lockpath, strerror(errno));
        exit(EX_OSERR);
    }

    rc = fsync(fdLock);
    if (-1 == rc) {
        eprint("fsync(%s): %s\n", lockpath, strerror(errno));
        exit(EX_OSERR);
    }
    (void)close(fdLock);

    dprint(2, "Using lock file: %s\n", lockpath);


    /* The info file name is constructed from the base name of the
     * given partition. Existence of this file means that the program
     * terminated abnormally and the test bed should be checked.
     */
    (void)snprintf(infopath, sizeof(infopath),
                   "%s/%s-info-%s", gtmpdir, progname, argSession);

    /* The parent removes the lock info file on normal termination.
     * If the file exists, it means that something bad happened
     * during the test phase, e.g., the machine crashed or the
     * parent process died.  In any event, the file needs to be
     * examined and all in progress transactions rolled back.
     */
    if (0 == access(infopath, R_OK|W_OK)) {
        eprint("access(%s): %s\n", infopath, strerror(errno));
        eprint("Test bed is dirty.  Run `%s -cRv %s' to repair.\n",
               progname, partition);
        exit(EX_DATAERR);
    }

    /* Create the shared info file, which is a table of range locks
     * currently held by each child processes.
     */
    fdInfo = open(infopath, O_CREAT|O_EXCL|O_RDWR, 0600);
    if (-1 == fdInfo) {
        eprint("open(%s): %s", infopath, strerror(errno));
        exit(EX_OSERR);
    }

    if (-1 == ftruncate(fdInfo, (nprocs + 1) * sizeof(*infobase))) {
        eprint("ftruncate(%s): %s\n", infopath, strerror(errno));
        exit(EX_OSERR);
    }

    dprint(2, "Using info file: %s\n", infopath);

#if HAVE_MMAP
    infobase = (info_t *)mmap((void *)0, (nprocs + 1) * sizeof(*infobase),
                              PROT_READ|PROT_WRITE, MAP_SHARED, fdInfo, 0);
    if (infobase == MAP_FAILED) {
        eprint("mmap(%s): %s", infopath, strerror(errno));
        exit(EX_OSERR);
    }
    bzero((char *)infobase, (nprocs + 1) * sizeof(*infobase));
    infobase[nprocs].pid = -1;  /* End of table sentinel */
    victim = infobase;

#else
#error TODO - this implementation does not support mmap
#endif /* HAVE_MMAP */


#if HAVE_ALARM
    (void)reliable_signal(SIGHUP, sigHandler);
    (void)reliable_signal(SIGINT, sigHandler);
    (void)reliable_signal(SIGPIPE, sigHandler);
    (void)reliable_signal(SIGXCPU, sigHandler);
    (void)reliable_signal(SIGXFSZ, sigHandler);
    (void)reliable_signal(SIGVTALRM, sigHandler);
    (void)reliable_signal(SIGPROF, sigHandler);
    (void)reliable_signal(SIGUSR1, sigHandler);
    (void)reliable_signal(SIGUSR2, sigHandler);
    (void)reliable_signal(SIGTERM, sigHandler);
#if defined(AIX4) || defined(AIX5) || defined(AIX6)
    (void)reliable_signal(SIGDANGER, sigHandler);
#endif
#else
#error TODO - this implementation does not support alarm
#endif /* HAVE_ALARM */

#if HAVE_SETPGID
    if (fSetPGID) {
        rc = setpgid(0, getpid());
        if (rc) {
            eprint("teststart: setpgid: %s\n", strerror(errno));
        }
    }
#endif /* HAVE_SETPGID */

    fRun = !0;

 spawn:
    while (fRun && (0 == victim->pid)) {
        pid = fork();
        switch (pid) {
        case -1:
            eprint("fork: %s\n", strerror(errno));
            sleep(3);
            continue;

        case 0:
            victim->pid = getpid();

            /* Each child needs his own private file offsets.
             */
            (void)close(fdPart);
            fdPart = open(partition, O_RDWR);
            if (-1 == fdPart) {
                eprint("open(%s): %s\n",
                       partition, strerror(errno));
                _exit(EX_OSERR);
            }

            fdLock = open(lockpath, O_RDWR);
            if (-1 == fdLock) {
                eprint("open(%s): %s\n",
                       lockpath, strerror(errno));
                _exit(EX_OSERR);
            }

            if (fAIO) {
#if HAVE_AIO
                testaio(infobase, rtckbase, fdInfo, fdLock,
                        fdPart, nsectors);
#endif /* HAVE_AIO */
                _exit(0);
            }

            test(infobase, rtckbase, fdInfo, fdLock, fdPart,
                 nsectors);
            _exit(0);

        default:
            dprint(3, "teststart: child %d started...\n", pid);
            ++victim;
            break;
        }
    }

    if (maxiterations > 0) {
        dprint(1, "%-6s %7s %7s %8s %9s %10s %10s\n",
               "PID", "USRTIME", "SYSTIME", "NSWAPS",
               "SWAPS/SEC", "NBLKSWR", "BLKSWR/SEC");
    }

    while (1) {
        unsigned int status;

        if (fSig) {
            fSig = fRun = 0;

            for (victim = infobase; victim->pid != -1; ++victim) {
                if (victim->pid > 0) {
                    dprint(2, "teststart: killing pid %d\n",
                           victim->pid);
                    rc = kill(victim->pid, SIGTERM);
                    if (rc) {
                        eprint("teststart: "
                               "kill(%d, SIGTERM): %s\n",
                               victim->pid, strerror(errno));
                    }
                }
            }
        }

        pid = wait((int *)&status);
        if (-1 == pid) {
            if (EINTR == errno) {
                dprint(3, "teststart: wait interrupted\n",
                       pid);
                dprint(1, "\n%-6s %7s %7s %8s %9s %10s %10s\n",
                       "PID", "USRTIME", "SYSTIME", "NSWAPS",
                       "SWAPS/SEC", "NBLKSWR", "BLKSWR/SEC");
                continue;
            } else if (ECHILD == errno) {
                break;
            }
            eprint("teststart: wait: %s\n", strerror(errno));
            exit(EX_OSERR);
        }

        /* Find this child's entry in the info table.
         */
        for (victim = infobase; victim->pid != pid; ++victim) {
            /* Do nothing */
        }
        assert(victim->pid == pid);

        if (WIFSTOPPED(status)) {
            dprint(0, "teststart: child %d stopped(%d)\n",
                   pid, WSTOPSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status)) {
            dprint(0, "teststart: child %d exited(%d)\n",
                   pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            dprint(0, "teststart: child %d signaled(%d)\n",
                   pid, WTERMSIG(status));
        }

        /* It may be necessary to roll back any changes if
         * the child terminated abnomally.
         */
        if ((WIFEXITED(status) && WEXITSTATUS(status)) ||
            WIFSIGNALED(status)) {
            cleanlocks(victim, fdInfo, fdPart, nsectors, rtckbase);
            victim->pid = 0;
            goto spawn;
        }

        victim->pid = -2;
    }

    if (-1 != fdRTCK) {
        rc = fsync(fdRTCK);
        if (rc) {
            eprint("teststart: fscync(%s): %s\n",
                   rtckpath, strerror(errno));
        }
    }

    dprint(2, "Removing info file: %s\n", infopath);
    (void)unlink(infopath);

    dprint(2, "Removing lock file: %s\n", lockpath);
    (void)unlink(lockpath);
}


/* Lock the info file and scan all the lock ranges for conflicts.  Conflicts
 * arise due to locks stranded by children who suffered traumatic deaths
 * (e.g., kill -9).  The parent process will eventually clean up the info
 * table and rollback any half baked swaps.
 */
int
itlock(int fdInfo, info_t *infobase, pid_t pid,
       struct flock *sw, struct flock *dw, int idx)
{
    struct flock lk;
    info_t *me;
    int rc;
    int i;

    assert(sw->l_len == dw->l_len);
    assert(sw->l_len > 0);
    assert(idx >= 0);
    assert(idx <= naioreqs);

    /* Lock the entire info file (i.e., the shared memory file).
     */
    lk.l_start = 0;
    lk.l_len = 0;
    lk.l_pid = 0;
    lk.l_whence = SEEK_SET;
    lk.l_type = F_WRLCK;
    if (-1 == fcntl(fdInfo, F_SETLKW, &lk)) {
        eprint("chklocks(%d): fcntl(%d, F_SETLK): %s\n",
               pid, fdInfo, strerror(errno));
        exit(EX_OSERR);
    }

    /* Check for conflicts.  Conflicts arise due to child processes
     * that exited (abnormally) without releasing their locked ranges.
     */
    rc = EBUSY;
    for (me = 0; infobase->pid != -1; ++infobase) {
        if (infobase->pid == pid) {
            me = infobase;
            continue;
        } else if (0 == infobase->nlocks) {
            continue;
        }

        for (i = 0; i < naioreqs + 1; ++i) {
            struct flock *sh, *dh;      /* src held, dst held */

            sh = &infobase->src[i];
            dh = &infobase->dst[i];

            if (0 == sh->l_len) {
                continue;
            }

            if (!((sw->l_start + sw->l_len <= sh->l_start) ||
                  (sw->l_start >= sh->l_start + sh->l_len))) {
                goto release;
            }
            if (!((sw->l_start + sw->l_len <= dh->l_start) ||
                  (sw->l_start >= dh->l_start + dh->l_len))) {
                goto release;
            }
            if (!((dw->l_start + dw->l_len <= sh->l_start) ||
                  (dw->l_start >= sh->l_start + sh->l_len))) {
                goto release;
            }
            if (!((dw->l_start + dw->l_len <= dh->l_start) ||
                  (dw->l_start >= dh->l_start + dh->l_len))) {
                goto release;
            }
        }
    }

    /* Update the lock ranges and set "locked" to one, thereby
     * reserving these ranges even if the fcntl locks are lost
     * due to the child exiting.
     */
    assert(me);
    assert(0 == me->src[idx].l_len);
    assert(0 == me->dst[idx].l_len);

    me->src[idx] = *sw;
    me->dst[idx] = *dw;
    ++me->nlocks;
    rc = 0;

    dprint(4, "itlock(%d): idx=%d locking range [%lld %lld %lu]\n",
           me->pid, idx,
           (long long)me->src[idx].l_start + oseek,
           (long long)me->dst[idx].l_start + oseek,
           (unsigned long)me->src[idx].l_len);

 release:
    lk.l_type = F_UNLCK;
    if (-1 == fcntl(fdInfo, F_SETLKW, &lk)) {
        eprint("chklocks(%d): fcntl(F_UNLCK): %s\n",
               pid, strerror(errno));
        exit(EX_OSERR);
    }

    return rc;
}


void
itunlock(int fdInfo, info_t *me, int idx)
{
    struct flock lk;

    assert(me);
    assert(idx >= 0);
    assert(idx <= naioreqs);

    lk.l_start = 0;
    lk.l_len = 0;
    lk.l_pid = 0;
    lk.l_whence = SEEK_SET;

    /* Release info table record lock.
     */
    lk.l_type = F_WRLCK;
    if (-1 == fcntl(fdInfo, F_SETLKW, &lk)) {
        eprint("test(%d): fcntl(info, F_WRLCK): %s\n",
               getpid(), strerror(errno));
        exit(EX_OSERR);
    }

    dprint(4, "itunlock(%d): idx=%d unlocking range [%lld %lld %lu]\n",
           me->pid, idx,
           (long long)me->src[idx].l_start + oseek,
           (long long)me->dst[idx].l_start + oseek,
           (unsigned long)me->src[idx].l_len);

    assert(me->nlocks > 0);
    assert(me->src[idx].l_len > 0);
    assert(me->dst[idx].l_len > 0);

    --me->nlocks;
    me->src[idx].l_start = 0;
    me->src[idx].l_len = 0;
    me->dst[idx].l_start = 0;
    me->dst[idx].l_len = 0;

    lk.l_type = F_UNLCK;
    if (-1 == fcntl(fdInfo, F_SETLKW, &lk)) {
        eprint("test(%d): fcntl(info, F_UNLCK): %s\n",
               getpid(), strerror(errno));
        exit(EX_OSERR);
    }
}


/* cleanlocks is called to clean up stale locks left by a process
 * that exited abnormally.  If the process died while holding locks,
 * then me->locked will be `true' and we have to examine the disk
 * regions covered by the child's range locks (src and dst), and
 * roll back records involved in an interrupted swap (if any).
 */
int
cleanlocks(info_t *me, int fdInfo, int fdPart, int64_t nsectors,
           rtck_t *rtckbase)
{
    sector_t *sb;
    defect_t *d;
    int nlocks;
    int rc;
    int i;

    if (0 == me->nlocks) {
        dprint(2, "cleanlocks: no locks held by child %d\n", me->pid);
        return 0;
    }

    /* At this point we know the child had some range locks,
     * so we need to see if there are any records that need
     * to be rolled back.
     */
    dprint(1, "cleanlocks: child %d has %d range locks...\n",
           me->pid, me->nlocks);

    sb = malloc(maxswapsectors * sizeof(*sb));
    if (!sb) {
        eprint("cleanlocks: out of memory\n");
        return 0;
    }

    d = defect_alloc(nsectors);
    if (!d) {
        eprint("cleanlocks: out of memory\n");
        free(sb);
        return 0;
    }

    nlocks = me->nlocks;
    for (i = 0; (i < naioreqs + 1) && (nlocks > 0); ++i) {
        if ((me->src[i].l_len == 0) || (me->dst[i].l_len == 0)) {
            continue;
        }

        dprint(2, "cleanlocks: pid=%d idx=%d [%lld %lld %lu]\n",
               me->pid, i,
               (long long)me->src[i].l_start + oseek,
               (long long)me->dst[i].l_start + oseek,
               (unsigned long)me->src[i].l_len);

        /* Get the regions involved in the swap.
         */
        getrgn(fdPart, sb, me->src[i].l_start, me->src[i].l_len,
               (aiocbptr_t)0);
        chkrgn(stderr, sb, me->src[i].l_start, me->src[i].l_len,
               (rtck_t *)0, d, (crc32_t *)0);

        getrgn(fdPart, sb, me->dst[i].l_start, me->dst[i].l_len,
               (aiocbptr_t)0);
        chkrgn(stderr, sb, me->dst[i].l_start, me->dst[i].l_len,
               (rtck_t *)0, d, (crc32_t *)0);

        --nlocks;
    }

    if (nlocks > 0) {
        eprint("cleanlocks: child %d has %d unreconciled locks\n",
               me->pid, nlocks);
    }

    rc = repair(fdPart, d, rtckbase);

    dprint(1, "cleanlocks: child %d cleaned\n\n", me->pid);

    me->pid = 0;
    me->nlocks = 0;
    bzero(me->src, sizeof(me->src));
    bzero(me->dst, sizeof(me->dst));

    free(sb);
    defect_free(d);

    return 0;
}


/* Continuously select two arbitrary contiguous regions and swap them.
 */
void
test(info_t *infobase, rtck_t *rtckbase, int fdInfo, int fdLock,
     int fdPart, int64_t nsectors)
{
    time_t starttime, now;
    struct flock src, dst;
    sector_t *sb1, *sb2;
    int64_t nblkswr;
    int64_t tmp64;
    long nswaps;
    long utime;
    long stime;
    size_t len;
    info_t *me;
    pid_t pid;

    /* Add pid to the seed so that the child processes
     * don't all generate the same sequence.
     */
    pid = getpid();

    /* Limit maxswapsectors so that the workers have
     * a fighting chance to run without complete deadlock.
     */
    tmp64 = nsectors / ((nprocs * 2) + 1);
    if (maxswapsectors > tmp64) {
        maxswapsectors = tmp64;
        dprint(1, "test(%d): limiting maxswapdevblks "
               "to %lld\n", pid, tmp64);

        if (maxswapsectors < 1) {
            eprint("test(%d): the test bed needs to contain "
                   "at least %d blocks given %d worker "
                   "processes\n", pid, (nprocs * 2) + 1, nprocs);
            sleep(3);
            exit(EX_USAGE);
        }

        if (minswapsectors > maxswapsectors) {
            tmp64 /= 2;
            dprint(1, "test(%d): limiting minswapdevblks "
                   "to %lld\n", pid, tmp64);
            minswapsectors = tmp64;
        }
    }

    dprint(3, "test(%d) nblocks=%lld oseek=%lld\n",
           pid, nsectors, oseek);
    dprint(3, "test(%d): minswapdevblks=%lld maxswapdevblks=%lld\n",
           pid, minswapsectors, maxswapsectors);

    /* Allocate two buffers into which to hold the data to be swapped.
     */
    sb1 = malloc(maxswapsectors * sizeof(*sb1));
    sb2 = malloc(maxswapsectors * sizeof(*sb2));
    if (!(sb1 && sb2)) {
        eprint("test(%d): insufficient memory for %lld swapdevblk "
               "buffers\n", pid, maxswapsectors);
        exit(EX_OSERR);
    }
    bzero(sb1, sizeof(*sb1) * maxswapsectors);
    bzero(sb2, sizeof(*sb2) * maxswapsectors);

    if ((void(*)(int))-1 == signal(SIGALRM, sigAlarm)) {
        eprint("test(%d): signal: %s\n", pid, strerror(errno));
        exit(EX_OSERR);
    }

    /* Find my entry in the info table.
     */
    for (me = infobase; me->pid != pid; ++me) {
        /* Do nothing */
    }
    assert(me->pid == pid);

    nswaps = 0;
    nblkswr = 0;
    starttime = time((time_t *)0);

    while (!fSig) {
        len = (random() % (maxswapsectors - minswapsectors + 1)) +
            minswapsectors;

        /* Get write locks.
         */
        src.l_start = random() % (nsectors - len + 1);
        src.l_len = len;
        src.l_pid = 0;
        src.l_type = F_WRLCK;
        src.l_whence = SEEK_SET;

        /* Set a watchdog so as to break deadlocks.
         */
        fSigAlarm = 0;
        alarm(30);

        /* Try for an exclusive lock over the src region,
         * blocking if necessary (F_SETLKW vs F_SETLK).
         */
        if (-1 == fcntl(fdLock, F_SETLKW, &src)) {
            alarm(0);
            if (EINTR == errno && fSig) {
                continue;
            } else if (EINTR == errno && fSigAlarm) {
                dprint(2, "test(%d): fcntl: deadlock?\n", pid);
                continue;
            }
            eprint("test(%d) fcntl(srclock, F_WRLCK): %s\n",
                   pid, strerror(errno));
            exit(EX_OSERR);
        }
        alarm(0);

        /* Try for an exclusive lock over the dst region,
         * but do not block (F_SETLK).
         */
        while (1) {
            dst.l_start = random() % (nsectors - len + 1);
            dst.l_len = len;
            dst.l_pid = 0;
            dst.l_type = F_WRLCK;
            dst.l_whence = SEEK_SET;

            /* If the dst region overlaps the src region
             * then reselect the dst region.
             */
            if (!((dst.l_start > src.l_start + len) ||
                  (dst.l_start + len < src.l_start))) {
                continue;
            }

            if (-1 == fcntl(fdLock, F_SETLK, &dst)) {
                if (EAGAIN == errno) {
                    dprint(4, "test(%d): [%lld %lld %lu] "
                           "busy\n",
                           pid,
                           (long long)src.l_start + oseek,
                           (long long)dst.l_start + oseek,
                           len);
                        
                    continue;
                } else if (EINTR == errno) {
                    continue;
#if defined(AIX4) || defined(AIX5) || defined(AIX6) || defined(HPUX1111) || defined(HPUX1123)
                } else if (EACCES == errno) {
                    continue;
#endif
                }

                eprint("test(%d): fcntl(dstlock, F_WRLCK): "
                       "%s start=%lld len=%lu\n",
                       pid, strerror(errno),
                       (long long)dst.l_start + oseek, len);
                exit(EX_OSERR);
            }
            break;
        }

        if (src.l_start < 0 || dst.l_start < 0) {
            eprint("test(%d): huh?", pid);
            exit(69);
        }

        /* Acquire info table lock.
         */
        if (0 != itlock(fdInfo, infobase, pid, &src, &dst, 0)) {
            dprint(1, "test(%d): stranded lock detected: "
                   "[%lld %lld %lu]\n",
                   pid, (long long)src.l_start + oseek,
                   (long long)dst.l_start + oseek, len);
            goto release;
        }

        dprint(3, "test(%d): swapping [%lld %lld %lu]\n",
               pid, (long long)src.l_start + oseek,
               (long long)dst.l_start + oseek, len);

        /* Read and check the data from the selected regions.
         */
        getrgn(fdPart, sb1, src.l_start, len, (aiocbptr_t)0);
        chkrgn(stderr, sb1, src.l_start, len,
               rtckbase, (defect_t *)0, (crc32_t *)0);

        getrgn(fdPart, sb2, dst.l_start, len, (aiocbptr_t)0);
        chkrgn(stderr, sb2, dst.l_start, len,
               rtckbase, (defect_t *)0, (crc32_t *)0);

        /* Save the rollback records.
         */
        saverollback(sb1, sb2, len);

        /* Update all records.
         */
        now = time((time_t *)0);
        updatergn(sb1, src.l_start, dst.l_start, len,
                  pid, now, rtckbase);

        /* Exit if "run time check file" error injection is enabled.
         */
        if ((eipRTCK > 0) && (eipRTCK > (random() % 1000))) {
            eprint("test(%d): eipRTCK=%ld\n", pid, eipRTCK);
            exit(EX_SOFTWARE);
        }

        updatergn(sb2, dst.l_start, src.l_start, len,
                  pid, now, rtckbase);

        /* Exit if "before swap" error injection is enabled.
         */
        if ((eipBefore > 0) && (eipBefore > (random() % 1000))) {
            eprint("test(%d): eipBefore=%ld\n", pid, eipBefore);
            exit(EX_SOFTWARE);
        }

        /* Swap and write the regions.  Always write the range
         * with the lowere disk block address first to make
         * rollback easier.
         */
        if (src.l_start < dst.l_start) {
            putrgn(fdPart, sb2, src.l_start, len, (aiocbptr_t)0);

            if ((eipDuring > 0) && (eipDuring>(random() % 1000))) {
                eprint("test(%d): eipDuring=%ld\n",
                       pid, eipDuring);
                exit(EX_SOFTWARE);
            }

            putrgn(fdPart, sb1, dst.l_start, len, (aiocbptr_t)0);
        } else {
            putrgn(fdPart, sb1, dst.l_start, len, (aiocbptr_t)0);

            if ((eipDuring > 0) && (eipDuring>(random() % 1000))) {
                eprint("test(%d): eipDuring=%ld\n",
                       pid, eipDuring);
                exit(EX_SOFTWARE);
            }

            putrgn(fdPart, sb2, src.l_start, len, (aiocbptr_t)0);
        }

        /* Exit if "after swap" error injection is enabled.
         */
        if ((eipAfter > 0) && (eipAfter > (random() % 1000))) {
            eprint("test(%d): eipAfter=%ld\n", pid, eipAfter);
            exit(EX_SOFTWARE);
        }

        /* Release info table record lock.
         */
        itunlock(fdInfo, me, 0);

        /* Release file range locks.
         */
    release:
        dst.l_type = F_UNLCK;
        if (-1 == fcntl(fdLock, F_SETLKW, &dst)) {
            eprint("test(%d): fcntl(dstlock, F_UNLCK): %s\n",
                   pid, strerror(errno));
            exit(EX_OSERR);
        }

        src.l_type = F_UNLCK;
        if (-1 == fcntl(fdLock, F_SETLKW, &src)) {
            eprint("test(%d): fcntl(srclock, F_UNLCK): %s\n",
                   pid, strerror(errno));
            exit(EX_OSERR);
        }

        ++nswaps;
        if ((maxiterations > 0) && (nswaps >= maxiterations)) {
            break;
        } else if ((testtimemax > 0) &&
                   (now >= testtimemax + starttime)) {
            break;
        }

        /* Add the number of blocks just written to the running
         * total (nblkswr).  If the number of blocks written per
         * second thus far (nblkswrps) exceeds the maximum desired
         * number of blocks written per second (maxblksps), then
         * sleep long enough to try and keep the rates as
         * close as possible.
         */
        nblkswr += len * 2;

        if ((maxblksps > 0) && (now > starttime)) {
            static int64_t nblkswr_saved = 0;
            static u_long delay = 0;

            if (nblkswr_saved < nblkswr) {
                int64_t nblkswrps;
                u_long adjust;

                nblkswrps = nblkswr / (now - starttime);
                nblkswr_saved = nblkswr;
                adjust = nblkswrps * 100000 / maxblksps;

                dprint(3, "(%d): nblkswrps=%lld nblkswr=%lld "
                       "delay=%lu\n", pid,
                       nblkswrps, nblkswr, delay);

                if (nblkswrps > maxblksps) {
                    delay += adjust;
                    usleep(delay);
                } else if (delay > adjust) {
                    delay -= adjust;
                }
            }
        }
    }

    getustime(&utime, &stime);

    now = time((time_t *)0);
    dprint(1, "%-6d %7ld %7ld %8ld %9.1f %10lld %10.1f\n",
           pid, stime, utime, nswaps, (float)nswaps / (now - starttime),
           nblkswr, (float)nblkswr / (now - starttime));

    free(sb1);
    free(sb2);
}


#if HAVE_AIO
void
testaio(info_t *infobase, rtck_t *rtckbase, int fdInfo, int fdLock,
        int fdPart, int64_t nsectors)
{
    time_t starttime, now;
    struct aiocb **arwaio;
    int maxtries = 8;
    int64_t nblkswr;
    xaio_t **axaio;
    int64_t tmp64;
    int64_t nrgns;
    long nswaps;
    long utime;
    long stime;
    info_t *me;
    int rwidx;
    pid_t pid;
    int nrw;

    pid = getpid();

    starttime = time((time_t *)0);
    srandom(starttime + pid);
    nswaps = 0;

    /* Limit maxswapsectors so that the workers have
     * a fighting chance to run without complete deadlock.
     */
    tmp64 = nsectors / ((naioreqs * 2) + 1);
    if (maxswapsectors > tmp64) {
        maxswapsectors = tmp64;
        dprint(1, "testaio(%d): limiting maxswapdevblks "
               "to %lld\n", pid, tmp64);

        if (maxswapsectors < 1) {
            eprint("testaio(%d): the test bed needs to contain "
                   "at least %d blocks given %d AIO requests\n",
                   pid, (naioreqs * 2) + 1, naioreqs);
            sleep(3);
            exit(EX_USAGE);
        }

        if (minswapsectors > maxswapsectors) {
            tmp64 /= 2;
            dprint(1, "testaio(%d): limiting minswapdevblks "
                   "to %lld\n", pid, tmp64);
            minswapsectors = tmp64;
        }
    }

    dprint(3, "testaio(%d) nblocks=%lld oseek=%lld\n",
           pid, nsectors, oseek);
    dprint(3, "testaio(%d): minswapdevblks=%lld maxswapdevblks=%lld\n",
           pid, minswapsectors, maxswapsectors);

    /* Allocate the aiocb pointer array.  This array holds
     * pointers to aiocbs that are in flight.
     */
    arwaio = malloc(naioreqs * sizeof(*arwaio));
    if (!arwaio) {
        eprint("testaio(%d): insufficient memory for %d "
               "aio requests\n", pid, naioreqs);
        exit(EX_OSERR);
    }
    bzero(arwaio, naioreqs * sizeof(*arwaio));

    /* Allocate the xaio pointer array.  This array hold
     * pointers to xaios for which there is an active
     * swap in progress.
     */
    axaio = malloc(naioreqs * sizeof(*axaio));
    if (!axaio) {
        eprint("testaio(%d): insufficient memory for %d "
               "aio requests\n", pid, naioreqs);
        exit(EX_OSERR);
    }
    bzero(axaio, naioreqs * sizeof(*axaio));

    if ((void(*)(int))-1 == signal(SIGALRM, sigAlarm)) {
        eprint("testaio(%d): signal: %s\n", pid, strerror(errno));
        exit(EX_OSERR);
    }

    if (testtimemax > 0) {
        fSigAlarm = 0;
        alarm((unsigned int)testtimemax);
    }

    /* Find my entry in the info table.
     */
    for (me = infobase; me->pid != pid; ++me) {
        /* Do nothing */
    }
    assert(me->pid == pid);

    nrw = 0;
    rwidx = 0;
    nblkswr = 0;

    while (1) {
        xaio_t *x1, *x2;
        int tries;
        int gbrc;
        int rc;
        int i;

        nrgns = (random() % (maxswapsectors - minswapsectors + 1)) +
            minswapsectors;

        /* Create two xaio control buffers, one for
         * each region that we are going to swap.
         */
        assert(nrgns <= maxswapsectors);
        gbrc = getxaiobuf(nrgns, fdLock, &x1, &x2);
        if (gbrc) {
            goto reaprw;
        }

        x1->read = 1;
        x2->read = 1;

        /* Try for an exclusive lock over the first region,
         * but do not block (F_SETLK).
         */
        x1->idx = getidx(naioreqs, axaio, &rwidx);
        x1->lkidx = x2->lkidx = x1->idx;

        for (tries = 0; tries < maxtries; ++tries) {
            x1->lk.l_start = random() % (nsectors - nrgns + 1);
            x1->lk.l_len = nrgns;
            x1->lk.l_pid = 0;
            x1->lk.l_type = F_WRLCK;
            x1->lk.l_whence = SEEK_SET;

            /* Check that this lock range doesn't overlap
             * any other request that is in progress.
             *
             * TODO: This code spins if naioreqs is too
             * large for the testbed.
             */
            if (chkoverlap(naioreqs, axaio, x1)) {
                dprint(3, "testaio(%d): overlapping "
                       "lock rgns start=%lld\n",
                       pid, (long long)x1->lk.l_start + oseek);
                continue;
            }

            /* Get an exclusive range lock to prevent
             * concurrent access to this region by any
             * other process working in this test bed.
             */
            if (-1 == fcntl(fdLock, F_SETLK, &x1->lk)) {
                dprint(4, "testaio(%d): fcntl(F_SETLK): %s\n",
                       pid, strerror(errno));
                sleep(1);

                if (EAGAIN == errno) {
                    continue;
                } else if (EINTR == errno) {
                    continue;
#if defined(AIX4) || defined(AIX5) || defined(AIX6) || defined(HPUX1111) || defined(HPUX1123)
                } else if (EACCES == errno) {
                    continue;
#endif
                }

                eprint("testaio(%d): fcntl(F_SETLK): %s\n",
                       pid, strerror(errno));
                exit(EX_OSERR);
            }
            break;
        }

        if (tries < maxtries) {
            axaio[x1->idx] = x1;
            arwaio[x1->idx] = &x1->aio;
        } else {
            dprint(3, "testaio(%d): couldn't lock first "
                   "region\n", pid);

            x1->read = 0;
            x2->read = 0;
            freexaiobuf(x1, x2);
            goto reaprw;
        }

        /* Try for an exclusive lock over the second region,
         * but do not block (F_SETLK).
         */
        x2->idx = getidx(naioreqs, axaio, &rwidx);
        for (tries = 0; tries < maxtries; ++tries) {
            x2->lk.l_start = random() % (nsectors - nrgns + 1);
            x2->lk.l_len = nrgns;
            x2->lk.l_pid = 0;
            x2->lk.l_type = F_WRLCK;
            x2->lk.l_whence = SEEK_SET;

            /* Check that this lock range doesn't overlap
             * any other request that is in progress.
             *
             * TODO: This code spins if naioreqs is too
             * large for the testbed.
             */
            if (chkoverlap(naioreqs, axaio, x2)) {
                dprint(3, "testaio(%d): overlapping "
                       "lock rgns start=%lld\n",
                       pid, (long long)x2->lk.l_start + oseek);
                continue;
            }

            /* Get an exclusive range lock to prevent
             * concurrent access to this region by any
             * other process working in this test bed.
             */
            if (-1 == fcntl(fdLock, F_SETLK, &x2->lk)) {
                dprint(4, "testaio(%d): F_SETLK: %s\n",
                       pid, strerror(errno));
                sleep(1);

                if (EAGAIN == errno) {
                    continue;
                } else if (EINTR == errno) {
                    continue;
#if defined(AIX4) || defined(AIX5) || defined(AIX6) || defined(HPUX1111) || defined(HPUX1123)
                } else if (EACCES == errno) {
                    continue;
#endif
                }

                eprint("testaio(%d): fcntl(F_WRLCK): "
                       "%s start=%lld nrgns=%lld\n",
                       pid, strerror(errno),
                       (long long)x1->lk.l_start + oseek,
                       nrgns);
                exit(EX_OSERR);
            }
            break;
        }

        /* Acquire info table lock.
         */
        if (0 != itlock(fdInfo, infobase, pid,
                        &x1->lk, &x2->lk, x1->lkidx)) {
            dprint(1, "testaio(%d): stranded lock detected: "
                   "[%lld %lld %lu]\n",
                   pid, (long long)x1->lk.l_start + oseek,
                   (long long)x2->lk.l_start + oseek, nrgns);
            assert(0);  /* This should never happen! */
        }

        if (tries < maxtries) {
            axaio[x2->idx] = x2;
            arwaio[x2->idx] = &x2->aio;

            dprint(3, "testaio(%d): aio read [%lld %lld %lu]\n",
                   pid, (long long)x1->lk.l_start + oseek,
                   (long long)x2->lk.l_start + oseek, x1->nrgns);

            /* Read the data from the selected regions.
             */
            getrgn(fdPart, x1->sb, x1->lk.l_start,
                   x1->nrgns, &x1->aio);
            getrgn(fdPart, x2->sb, x2->lk.l_start,
                   x2->nrgns, &x2->aio);

            nrw += 2;
        } else {
            /* Release info table record lock.
             */
            itunlock(fdInfo, me, x1->lkidx);

            x1->lk.l_type = F_UNLCK;
            if (-1 == fcntl(fdLock, F_SETLKW, &x1->lk)) {
                eprint("testaio(%d): fcntl(F_UNLCK): "
                       "%s\n", pid, strerror(errno));
                exit(EX_OSERR);
            }

            dprint(3, "testaio(%d): couldn't lock second "
                   "region\n", pid);

            x1->read = 0;
            x2->read = 0;
            axaio[x1->idx] = 0;
            arwaio[x1->idx] = 0;
            freexaiobuf(x1, x2);
            goto reaprw;
        }


    reaprw:
        /* Here we scan the array of requests to reap
         * read requests that have completed.
         */
        for (i = 0; i < naioreqs; ++i) {
            ssize_t cc;

            x1 = axaio[i];

            if (!x1 || !x1->read || !arwaio[i]) {
                continue;
            }
            assert(!x1->done);

            rc = AIO_ERROR(&x1->aio);
            if (rc) {
                if (rc != EINPROGRESS) {
                    eprint("testaio(%d): aio_error: %s\n",
                           pid, strerror(rc));
                    exit(EX_OSERR);
                }
                continue;
            }

            cc = aio_return(&x1->aio);
            if (cc != x1->aio.aio_nbytes) {
                eprint("testaio(%d): aio_return: cc (%lu) "
                       "!= aio_nbytes (%lu)\n",
                       pid, cc, x1->aio.aio_nbytes);
                exit(EX_OSERR);
            }

            x1->done = 1;
            x1->read = 0;
            x2 = x1->sibling;
            arwaio[i] = 0;

            dprint(3, "testaio(%d): read done [%lld %lld %lu] "
                   "cc=%ld\n",
                   pid, (long long)x1->lk.l_start + oseek,
                   (long long)x2->lk.l_start + oseek,
                   x1->nrgns, cc);
                
            chkrgn(stderr, x1->sb, x1->lk.l_start, x1->nrgns,
                   rtckbase, (defect_t *)0, (crc32_t *)0);


            /* If the sibling is done, then both reads have
             * completed.  We can now initiate the write/swap
             * phase of the transaction.
             */
            if (x2->done) {
                x1->done = x2->done = 0;

                /* Save the rollback records.
                 */
                saverollback(x1->sb, x2->sb, x1->nrgns);

                arwaio[x1->idx] = &x1->aio;
                arwaio[x2->idx] = &x2->aio;

                dprint(3, "testaio(%d): aio write "
                       "[%lld %lld %lu]\n",
                       pid, (long long)x1->lk.l_start + oseek,
                       (long long)x2->lk.l_start + oseek,
                       x1->nrgns);

                now = time((time_t *)0);
                updatergn(x1->sb, x1->lk.l_start,
                          x2->lk.l_start, x1->nrgns,
                          pid, now, rtckbase);

                /* Exit if "run time check file" error
                 * injection is enabled.
                 */
                if ((eipRTCK > 0) &&
                    (eipRTCK > (random() % 1000))) {
                    eprint("testaio(%d): eipRTCK=%ld\n",
                           pid, eipRTCK);
                    exit(EX_SOFTWARE);
                }

                updatergn(x2->sb, x2->lk.l_start,
                          x1->lk.l_start, x2->nrgns,
                          pid, now, rtckbase);

                /* Exit if "before swap" error
                 * injection is enabled.
                 */
                if ((eipBefore > 0) &&
                    (eipBefore > (random() % 1000))) {
                    eprint("testaio(%d): eipBefore=%ld\n",
                           pid, eipBefore);
                    exit(EX_SOFTWARE);
                }

                putrgn(fdPart, x1->sb, x2->lk.l_start,
                       x1->nrgns, &x1->aio);

                /* Exit if "during swap" error
                 * injection is enabled.
                 */
                if ((eipDuring > 0) &&
                    (eipDuring > (random() % 1000))) {
                    eprint("testaio(%d): eipDuring=%ld\n",
                           pid, eipDuring);
                    exit(EX_SOFTWARE);
                }

                putrgn(fdPart, x2->sb, x1->lk.l_start,
                       x2->nrgns, &x2->aio);

                nblkswr += x1->nrgns + x2->nrgns;
            }
        }


        /* Here we scan the array of requests to reap
         * write requests that have completed.
         */
        for (i = 0; i < naioreqs; ++i) {
            ssize_t cc;

            x1 = axaio[i];

            if (!x1 || x1->read || !arwaio[i]) {
                continue;
            }
            assert(!x1->done);

            rc = AIO_ERROR(&x1->aio);
            if (rc) {
                if (rc != EINPROGRESS) {
                    eprint("testaio(%d): aio_error: %s\n",
                           pid, strerror(rc));
                    exit(EX_OSERR);
                }
                continue;
            }

            cc = aio_return(&x1->aio);
            if (cc != x1->aio.aio_nbytes) {
                eprint("testaio(%d): aio_return: cc (%lu) "
                       "!= aio_nbytes (%lu)\n",
                       pid, cc, x1->aio.aio_nbytes);
                exit(EX_OSERR);
            }

            x1->done = 1;
            x2 = x1->sibling;
            arwaio[i] = 0;

            dprint(3, "testaio(%d): write done [%lld %lld %lu] "
                   "cc=%lu\n",
                   pid, (long long)x1->lk.l_start + oseek,
                   (long long)x2->lk.l_start + oseek,
                   x1->nrgns, cc);

            /* If the sibling is done, then both writes
             * have completed and the swap is complete.
             */
            if (x2->done) {
                /* Release info table record lock.
                 */
                itunlock(fdInfo, me, x1->lkidx);

                /* Release range locks.
                 */
                x1->lk.l_type = F_UNLCK;
                if (-1 == fcntl(fdLock, F_SETLKW, &x1->lk)) {
                    eprint("testaio(%d): fcntl(F_UNLCK): "
                           "%s\n", pid, strerror(errno));
                    exit(EX_OSERR);
                }

                x2->lk.l_type = F_UNLCK;
                if (-1 == fcntl(fdLock, F_SETLKW, &x2->lk)) {
                    eprint("testaio(%d): fcntl(F_UNLCK): "
                           "%s\n", pid, strerror(errno));
                    exit(EX_OSERR);
                }

                axaio[x1->idx] = 0;
                axaio[x2->idx] = 0;
                freexaiobuf(x1, x2);

                /* Exit if "after swap" error
                 * injection is enabled.
                 */
                if ((eipAfter > 0) &&
                    (eipAfter > (random() % 1000))) {
                    eprint("testaio(%d): eipAfter=%ld\n",
                           pid, eipAfter);
                    exit(EX_SOFTWARE);
                }

                nrw -= 2;
                ++nswaps;
                if ((maxiterations > 0) &&
                    (--maxiterations == 0)) {
                    ++fSig;
                }
            }
        }

        /* If we caught a signal to terminate, then we must
         * wait for all the in flight I/O to finish.
         */
        if (fSig | fSigAlarm) {
            static int gavemsg = 0;

            if (!nrw) {
                break;
            } else if (!gavemsg) {
                dprint(3, "testaio(%d): flushing %d "
                       "buffers...\n", pid, nrw);
                gavemsg = 1;
            }
        }

        /* Here we must stay in the reaper loop until space
         * frees up in the aio request tracking table (axio[]).
         */
        if ((naioreqs - nrw < 2) || gbrc || (fSig | fSigAlarm)) {
            dprint(3, "testaio(%d): nrw=%d gbrc=%d fsig=%d\n",
                   pid, nrw, gbrc, fSig);
            if (nrw > 0) {
                rc = AIO_SUSPEND(arwaio, naioreqs);
                if (rc == -1) {
                    dprint(4, "testaio(%d): aio_suspend: "
                           "%s nrw=%d\n",
                           pid, strerror(errno), nrw);
                    sleep(1);
                }
            }
            goto reaprw;
        }

        /* Add the number of blocks just written to the running
         * total (nblkswr).  If the number of blocks written per
         * second thus far (nblkswrps) exceeds the maximum desired
         * number of blocks written per second (maxblksps), then
         * sleep long enough to try and keep the rates as
         * close as possible.
         */
        if ((maxblksps > 0) && (now > starttime)) {
            static int64_t nblkswr_saved = 0;
            static u_long delay = 0;

            if (nblkswr_saved < nblkswr) {
                int64_t nblkswrps;
                u_long adjust;

                nblkswrps = nblkswr / (now - starttime);
                nblkswr_saved = nblkswr;
                adjust = nblkswrps * 100000 / maxblksps;

                dprint(3, "(%d): nblkswrps=%ld nblkswr=%lld "
                       "delay=%lu\n", pid,
                       nblkswrps, nblkswr, delay);

                if (nblkswrps > maxblksps) {
                    delay += adjust;
                    usleep(delay);
                } else if (delay > adjust) {
                    delay -= adjust;
                }
            }
        }
    }

    free(arwaio);
    free(axaio);

    getustime(&utime, &stime);

    now = time((time_t *)0);
    dprint(1, "%-6d %7ld %7ld %8ld %9.1f %10lld %10.1f\n",
           pid, utime, stime, nswaps, (float)nswaps / (now - starttime),
           nblkswr, (float)nblkswr / (now - starttime));
}
#endif /* HAVE_AIO */


/* Update region prepares each record in the given range
 * to be written to disk.
 */
void
updatergn(sector_t *sb, off_t src, off_t dst, size_t len,
          pid_t pid, time_t curtime, rtck_t *rtckbase)
{
    long randupd;
    int i;

    randupd = random();

    for (i = 0; i < len; ++i, ++sb) {
        record_t *r = &sb->rec[0];

        r->pid = pid;
        r->mtime = curtime;
        r->src = src + i;
        r->dst = dst + i;
        r->len = len;
        ++r->nswaps;

        /* Randomly updated number for increasing the probability
         * that the record is different from its predecessor.
         */
        sb->randupd = randupd;

        sb->kscratch = 0;
        sb->crc = 0;
        sb->crc = crc32((u_char *)sb, sizeof(*sb), CRC32_PRELOAD);

        if (rtckbase && fExec) {
            rtckbase[dst + i].id = r->id;
            rtckbase[dst + i].crc = sb->crc;
        }
    }
}


/* For each record in the given range, check region calculates
 * the crc and compares it to the stored crc in effort to
 * validate that the record has not been corrupted.
 */
void
chkrgn(FILE *fp, sector_t *sb, off_t offset, size_t len,
       rtck_t *rtckbase, defect_t *d, crc32_t *signature)
{
    int i;

    /* Check the integrity of the data read.
     */
    for (i = 0; i < len; ++i, ++sb) {
        record_t *r = &sb->rec[0];
        char msg[1024] = "\000";
        crc32_t crc;

        /* The kernel scratch area is used for in-kernel
         * validation (sequence number validation, etc, ...
         * We must set it to zero before computing the crc.
         */
        sb->kscratch = 0;

        if (d) {
            d->id[offset + i] = r->id;
            d->crc[offset + i] = sb->crc;
        }

        /* If the testbed is corrupted, then we want to kill off all
         * the test processes rather than let the parent try to fix
         * things.  The base defect list pointer `d' is usually null
         * during test mode and valid during check mode.  We use
         * that to decide whether we should abort or continue.
         */
        crc = sb->crc;
        sb->crc = 0;
        sb->crc = crc32((u_char *)sb, sizeof(*sb), CRC32_PRELOAD);
        if (crc != sb->crc) {
            (void)snprintf(msg, sizeof(msg),
                           "Corrupted sector (Calculated "
                           "CRC=%X on-disk=%X)",
                           sb->crc, crc);
            if (d) {
                d->msg[offset + i] = strdup(msg);
                ++d->ndefects;
                continue;
            }

            fprintf(fp, "LBA %" PRId64 ": %s\n", offset + i + oseek, msg);
            dumprgn(fp, sb, 0, 1, rtckbase, 1);
            (void)killpg(0, SIGTERM);
            exit(EX_DATAERR);
        }

        if (rtckbase) {
            if (rtckbase[offset + i].crc != sb->crc) {
                snprintf(msg, sizeof(msg),
                         "RTCK CRC mismatch: "
                         "RTCK.crc=%x sector.crc=%x "
                         "RTCK.id=%" PRId64 " sector.id=%" PRId64,
                         rtckbase[offset + i].crc, sb->crc,
                         rtckbase[offset + i].id + oseek,
                         r->id + oseek);
            } else if (rtckbase[offset + i].id != r->id) {
                snprintf(msg, sizeof(msg),
                         "RTCK ID mismatch "
                         "RTCK.id=%" PRId64 " sector.id=%" PRId64,
                         rtckbase[offset + i].id + oseek,
                         r->id + oseek);
            }

            if (msg[0]) {
                if (d) {
                    d->msg[offset + i] = strdup(msg);
                    ++d->ndefects;
                    continue;
                }

                fprintf(fp, "LBA %" PRId64 ": %s\n",
                        offset + i + oseek, msg);
                dumprgn(fp, sb, 0, 1, rtckbase, 1);
                (void)killpg(0, SIGTERM);
                exit(EX_DATAERR);
            }
        }

        if ((gctime > 0) && (gctime != r->ctime)) {
            snprintf(msg, sizeof(msg),
                     "CTIME mismatch (Expected %lu"
                     " vs on-disk %lu)",
                     gctime, r->ctime);
            if (d) {
                d->msg[offset + i] = strdup(msg);
                ++d->ndefects;
                continue;
            }

            fprintf(fp, "LBA %" PRId64 ": %s\n",
                    offset + i + oseek, msg);
            fprintf(fp, "%s\n", msg);
            dumprgn(fp, sb, 0, 1, rtckbase, 1);
            (void)killpg(0, SIGTERM);
            exit(EX_DATAERR);
        }

        /* The record's dst field should match the sector
         * from which the record was read.
         */
        if (r->dst != offset + i) {
            snprintf(msg, sizeof(msg),
                     "Dst blk mismatch (Expected %" PRId64
                     " vs on-disk %" PRId64 "\n",
                     offset + i + oseek, r->dst);
            if (!d) {
                fprintf(fp, "LBA %" PRId64 ": %s\n",
                        offset + i + oseek, msg);
                dumprgn(fp, sb, 0, 1, rtckbase, 1);
                (void)killpg(0, SIGTERM);
                exit(EX_DATAERR);
            }

            d->msg[offset + i] = strdup(msg);
            ++d->ndefects;
        }

        if (d) {
            if ((r->id < 0) || (r->id > d->nsectors)) {
                fprintf(fp, "chkrgn: invalid record ID %" PRId64
                        " at LBA %" PRId64 "\n",
                        r->id, offset + i + oseek);
                fprintf(fp, "chkrgn: nsectors=%" PRId64 "\n",
                        d->nsectors);
                exit(EX_DATAERR);
            }

            if (r->id == (offset + i)) {
                ++d->inplace;
            }

            /* Save in d->x[r->id] the sector at which the record
             * r->id was found.  If d->x[r->id] is not (-1), then
             * this is a duplicate, and so we store the duplicate
             * info in d->y[r->id] in hopes that we can repair
             * the problem.
             */
            if (d->x[r->id] == -1) {
                d->x[r->id] = offset + i;
            } else if (d->y[r->id] == -1) {
                d->y[r->id] = offset + i;

                if (!d->msg[r->id]) {
                    (void)snprintf(msg, sizeof(msg),
                                   "Duplicate record for "
                                   " ID %" PRId64 " found at "
                                   "LBA %" PRId64,
                                   r->id,
                                   offset + i + oseek);
                    d->msg[r->id] = strdup(msg);
                }
                ++d->ndefects;
            } else {
                char *pc;

                pc = d->msg[r->id];
                pc += strlen(pc);

                if (pc < &msg[sizeof(msg)]) {
                    (void)snprintf(msg, sizeof(msg),
                                   ", %s DUP(%" PRId64 ")",
                                   pc, offset + i + oseek);
                    free(d->msg[r->id]);
                    d->msg[r->id] = strdup(msg);
                }

                ++d->ndefects;
            }
        }

        if (signature) {
            *signature = crc32((u_char *)&crc, sizeof(crc),
                               *signature);
        }
    }
}


/* Called prior to a swap write.  Saves the previous contents of rec[0]
 * into rec[1] so that rec[0] can be rolled back in the case of
 * catastrophic error (e.g., system crash, kill -9, etc, ...)
 */
void
saverollback(sector_t *x, sector_t *y, int64_t nrgns)
{
    while (nrgns-- > 0) {
        x[nrgns].rec[1] = y[nrgns].rec[0];
        y[nrgns].rec[1] = x[nrgns].rec[0];
    }
}


/* Note that we received a signal.
 */
RETSIGTYPE
sigHandler(int sig)
{
    char msg[] = "signal registered, please be patient...\n";

    if ((++fSig > 1) && (SIGINT == sig)) {
#if 0
        (void)write(1, msg, strlen(msg));
#endif
    }
}


/* Note that the watchdog timer expired.
 */
RETSIGTYPE
sigAlarm(int sig)
{
    ++fSigAlarm;
}


/* Debug print.
 */
void
dprint(int lvl, char *fmt, ...)
{
    if (verbosity >= lvl) {
        char msg[1024];
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        fputs(msg, stdout);
        fflush(stdout);
    }
}


/* Error print.
 */
void
eprint(char *fmt, ...)
{
    char msg[1024];
    va_list ap;

    sprintf(msg, "%s: ", progname);

    va_start(ap, fmt);
    vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
    va_end(ap);

    fputs(msg, stderr);
}


#if HAVE_AIO
int
getxaiobuf(int nrgns, int fd, xaio_t **x1, xaio_t **x2)
{
    assert(sizeof(xaio_t) <= sizeof(sector_t));

    if (xaiohead) {
        *x1 = xaiohead;
        xaiohead = (*x1)->next;
        if ((*x1)->next) {
            (*x1)->next = (xaio_t *)0;
        }
        assert((*x1)->magic == 0xdeadbeef);
    } else {
        (*x1) = malloc((maxswapsectors + 1) * sizeof(sector_t));
        if (!(*x1)) {
            eprint("getxaiobuf: malloc(%lu) failed...\n",
                   (nrgns + 1) * sizeof(sector_t));
            return ENOMEM;
        }
    }

    bzero(*x1, sizeof(**x1));
    (*x1)->sb = (sector_t *)((char *)(*x1) + sizeof(sector_t));
    (*x1)->nrgns = nrgns;
    (*x1)->magic = 0x01234567;

    if (!x2) {
        return 0;
    }

    if (xaiohead) {
        *x2 = xaiohead;
        xaiohead = (*x2)->next;
        if ((*x2)->next) {
            (*x2)->next = (xaio_t *)0;
        }
        assert((*x2)->magic == 0xdeadbeef);
    } else {
        *x2 = malloc((maxswapsectors + 1) * sizeof(sector_t));
        if (!(*x2)) {
            eprint("getxaiobuf: malloc(%lu) failed...\n",
                   (nrgns + 1) * sizeof(sector_t));
            (*x1)->magic = 0xdeadbeef;
            (*x1)->next = xaiohead;
            xaiohead = (*x1);
            return ENOMEM;
        }
    }

    bzero(*x2, sizeof(**x2));
    (*x2)->sb = (sector_t *)((char *)(*x2) + sizeof(sector_t));
    (*x2)->nrgns = nrgns;
    (*x2)->magic = 0x01234567;

    (*x1)->sibling = *x2;
    (*x2)->sibling = *x1;

    return 0;
}


void
freexaiobuf(xaio_t *xaio1, xaio_t *xaio2)
{
    assert(xaio1->magic == 0x01234567);
    xaio1->magic = 0xdeadbeef;
    xaio1->next = xaiohead;
    xaiohead = xaio1;

    if (xaio2) {
        assert(xaio2->magic == 0x01234567);
        xaio2->magic = 0xdeadbeef;
        xaio2->next = xaiohead;
        xaiohead = xaio2;
    }
}


int
getidx(int n, xaio_t **ap, int *pidx)
{
    int idx = *pidx;
    int i;

    for (i = 0; i < n; ++i) {
        if (!ap[idx]) {
            return (*pidx = idx);
        }
        idx = (idx + 1) % n;
    }

    eprint("getidx: array is full!\n");

    for (i = 0; i < n; ++i) {
        fprintf(stderr, "%d: %p\n", i, ap[i]);
    }

    sleep(3);

    exit(EX_DATAERR);
}


int
chkoverlap(int n, xaio_t **ap, xaio_t *tgt)
{
    int i;

    for (i = 0; i < n; ++i) {
        xaio_t *x = ap[i];

        if (x) {
            if (x->lk.l_start + x->lk.l_len <
                tgt->lk.l_start) {
                continue;
            }

            if (tgt->lk.l_start + tgt->lk.l_len <
                x->lk.l_start) {
                continue;
            }

            return 1;
        }
    }

    return 0;
}
#endif /* HAVE_AIO */



#if 0
/* The following C code (by Rob Warnock <rpw3@sgi.com>) does CRC-32 in
 * BigEndian/BigEndian byte/bit order.  That is, the data is sent most
 * significant byte first, and each of the bits within a byte is sent most
 * significant bit first, as in FDDI. You will need to twiddle with it to do
 * Ethernet CRC, i.e., BigEndian/LittleEndian byte/bit order. [Left as an
 * exercise for the reader.]

 * The CRCs this code generates agree with the vendor-supplied Verilog models
 * of several of the popular FDDI "MAC" chips.
 */

/* Build auxiliary table for parallel byte-at-a-time CRC-32.
 */
#define CRC32_POLY 0x04c11db7     /* AUTODIN II, Ethernet, & FDDI */

static crc32_t crc32_table[256];

void
crc32_init(void)
{
    crc32_t c;
    int i, j;

    for (i = 0; i < 256; ++i) {
        for (c = i << 24, j = 8; j > 0; --j) {
            c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
        }
        crc32_table[i] = c;
    }
}


crc32_t
crc32(u_char *buf, int len, crc32_t crc)
{
    u_char *p;

    for (p = buf; len > 0; ++p, --len) {
        crc = (crc << 8) ^ crc32_table[(crc >> 24) ^ *p];
    }

    return ~crc;        /* transmit complement, per CRC-32 spec */
}

#else

/* This code is copyright © 1993 Richard Black. All rights are reserved. You
 * may use this code only if it includes a statement to that effect.
 *
 * This algorithm takes the observation used to produce algorithm three one
 * stage further. Whereas it still performs the division eight bits at a time
 * for cache performance reasons, it is designed in such a way that the data
 * can be fed into the remainder in thirty two bit units (which are more
 * efficient units on most computers). This necessitates re-ordering the bits
 * of the polynomial in a non-monotonic fashion depending on the endian of the
 * computer on which the algorithm is running. The polynomials in the lookup
 * table likewise have the same non-linear transform applied to them as they
 * are generated.
 *
 * Of course this now only works for word aligned data and assumes that the
 * data is an exact number of words. I do not regard these as significant
 * limitations. This code is approximately twice as fast as algorithm three.
 * It should also be noticed that since the data is not broken up into bytes,
 * this code has an even larger benefit when used as an integral part of a
 * data copy routine. The result is also in the local form and should be
 * written directly as a word to the data and not as a sequence of bytes.

 * The tinkerer will observe that the C can be made slightly more beautiful
 * by rearranging the insertion of the data to the start of the loop, using
 * a pre-condition of , and stopping early. However, apart from the issue at
 * the receiver, such code will be considerably slower, because the data is
 * required synchronously. In the code as I have written it, the compilergif
 * will perform the load on p early in the loop body, and so the load delay
 * will have passed by the time the data is required.

 * This loop compiles to 16 instructions on the Arm, 29 on the Mips, 30 on
 * the Alpha, and 19 on the HP-PA. The Arm's instruction count is so low
 * because of the ability to perform shifts for free on all operations, but
 * it looses out on its blocking loads to about the same number of cycle as
 * the Mips. The Alpha gains over the Mips with its s4addq instruction, but
 *  looses this win because 32bit loads sign extend and require zeroed. The
 * HP-PA assembler is too weird to comment further.

 * On all architectures, assuming the 1K lookup table is in the cache, the
 * algorithm proceeds at an average of about 1 bit per clock cycle. This
 * represents 25 Mbit/sec on the FPC3 or Maxine, and 150 Mbit/sec on the
 * Sandpiper.

 * This implementation is particularly suitable for hardware at a point where
 * the data path is thirty two bits wide. The generating register can be
 * implemented as a 32 bit register with an 8 bit barrel roll operation.
 * Between each data word being exclusive-ored in, four rolls with exclusive
 * or of the quotient can be performed. (or two of sixteen). This makes the
 * xor circuitry much simpler and reduces the percentage of cycles which must
 * involve the actual data. 
 */

#define CRC32_POLY 0x04c11db7     /* AUTODIN II, Ethernet, & FDDI */

static crc32_t crctab[256];

void
crc32_init(void)
{
    int i,j;

    unsigned int crc;

    for (i = 0; i < 256; i++) {
        crc = i << 24;
        for (j = 0; j < 8; j++) {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ CRC32_POLY;
            else
                crc = crc << 1;
        }
        crctab[i] = crc;
    }
}


crc32_t
crc32(unsigned char *data, int len, crc32_t crc)
{
    unsigned int *p = (unsigned int *)data;
    unsigned int *e = (unsigned int *)(data + len);
    unsigned int result;
    
    if (len < 4) {
        abort();
    }

    result = crc;
    result ^= ~*p++;
    
    while (p < e) {
        result = crctab[result >> 24] ^ result << 8;
        result = crctab[result >> 24] ^ result << 8;
        result = crctab[result >> 24] ^ result << 8;
        result = crctab[result >> 24] ^ result << 8;
        result ^= *p++;
    }
    
    return ~result;
}
#endif


/* Read "len" number of sectors into "sb" starting from "offset".
 */
void
getrgn(int fd, sector_t *sb, off_t offset, size_t len, aiocbptr_t aio)
{
    ssize_t cc;

    offset += oseek;

    /* Read the data over the locked regions.
     */
#if HAVE_AIO
    if (aio) {
        int rc;

        bzero(aio, sizeof(*aio));
        aio->aio_offset = offset * sizeof(*sb);
        aio->aio_buf = (char *)sb;
        aio->aio_nbytes = len * sizeof(*sb);
#if defined(HPUX1111) || defined(HPUX1123)
        aio->aio_sigevent.sigev_notify = SIGEV_NONE;
#endif /* HPUX1111 || HPUX1123 */

#ifdef _AIO_AIX_SOURCE
        /* Legacy aio.
         */
        aio->aio_whence = SEEK_SET;
        aio->aio_flag = AIO_SIGNAL;

        /* aio->aio_event Not Used */
        rc = aio_read(fd, aio);
#else
        /* Posix aio.
         */
        aio->aio_lio_opcode = LIO_READ;
        aio->aio_fildes = fd;
        rc = aio_read(aio);
#endif /* _AIO_AIX_SOURCE */

        if (rc) {
            eprint("getrgn: aio_read: %s\n", strerror(errno));
            assert(0);
            exit(EX_OSERR);
        }
        return;
    }
#endif /* HAVE_AIO */

    /* TODO: We should use probably use pread(), if available.
     */

    if (-1 == lseek(fd, offset * sizeof(*sb), SEEK_SET)) {
        eprint("getrgn: lseek: %s\n", strerror(errno));
        exit(EX_OSERR);
    }

    cc = read(fd, sb, len * sizeof(*sb));
    if (-1 == cc) {
        eprint("getrgn: read: %s\n", strerror(errno));
        exit(EX_IOERR);
    } else if (cc != len * sizeof(*sb)) {
        eprint("getrgn: read: tried to read %ld bytes at offset "
               "%ld but only %lu bytes were read\n",
               len * sizeof(*sb),
               (long)offset * sizeof(*sb),
               (long)cc);
        assert(0);
        exit(EX_IOERR);
    }
}


/* Write the given records to disk.
 */
void
putrgn(int fd, sector_t *sb, off_t offset, size_t len, aiocbptr_t aio)
{
    off_t off;
    ssize_t cc;

    if (!fExec) {
        return;
    }

    offset += oseek;

#if HAVE_AIO
    if (aio) {
        int rc;

        bzero(aio, sizeof(*aio));
        aio->aio_offset = offset * sizeof(*sb);
        aio->aio_buf = (char *)sb;
        aio->aio_nbytes = len * sizeof(*sb);
#if defined(HPUX1111) || defined(HPUX1123)
        aio->aio_sigevent.sigev_notify = SIGEV_NONE;
#endif /* HPUX1111 || HPUX1123 */

#ifdef _AIO_AIX_SOURCE
        /* Legacy aio.
         */
        aio->aio_flag = AIO_SIGNAL;
        aio->aio_whence = SEEK_SET;
        /* aio->aio_event Not Used */
        rc = aio_write(fd, aio);
#else
        /* Posix aio.
         */
        aio->aio_lio_opcode = LIO_WRITE;
        aio->aio_fildes = fd;
        rc = aio_write(aio);
#endif /* _AIO_AIX_SOURCE */

        if (rc == -1) {
            eprint("putrgn: aio_write: %s\n", strerror(errno));
            exit(EX_OSERR);
        }
        return;
    }
#endif /* HAVE_AIO */

    /* TODO: We should use probably use pwrite(), if available.
     */

    off = lseek(fd, offset * sizeof(*sb), SEEK_SET);
    if (off != (offset * sizeof(*sb))) {
        if (-1 == off) {
            eprint("putrgn: lseek: %s\n",
                   strerror(errno));
        } else {
            eprint("putrgn: lseek: invalid offset %d\n",
                   off);
        }
        exit(EX_OSERR);
    }

    cc = write(fd, sb, len * sizeof(*sb));
    if (-1 == cc) {
        eprint("putrgn: write: %s\n", strerror(errno));
        exit(EX_IOERR);
    } else if (cc != (len * sizeof(*sb))) {
        eprint("putrgn: write: tried to write %ld bytes at offset "
               "%ld but only %lu bytes were written\n", (long)cc,
               (long)offset * sizeof(*sb),
               len * sizeof(*sb));
        assert(0);
        exit(EX_IOERR);
    }
}


/* Convert the nnn part of svn's "$Revision: 202 $" into a number.
 */
unsigned long
svnrev2num(const char *revision)
{
    while (revision && *revision && !isdigit((int)*revision)) {
        ++revision;
    }

    return strtoul(revision, (char **)0, 10);
}


/* Get the user and system time in milliseconds.
 */
void
getustime(long *utime, long *stime)
{
    struct rusage r;
    int rc;

    rc = getrusage(RUSAGE_SELF, &r);
    if (rc) {
        assert(0);
    }

    *utime = (r.ru_utime.tv_sec * 1000000 + r.ru_utime.tv_usec) / 1000;
    *stime = (r.ru_stime.tv_sec * 1000000 + r.ru_stime.tv_usec) / 1000;
}


/* $Id: dits.c 202 2013-07-05 20:27:35Z greg $
 *
 * This program finds the size of a disk partition.  It does so by
 * repeated brute force application of the half split method, starting
 * with the (maximum possible partition size / 2) and moving forward or
 * back depending on whether the device can be read at that offset.
 *
 * To be useful, this program needs to operate in a large file environment.
 * To attain that, it either needs to be compiled as a 64bit program, or
 * as a 32bit program that groks large files.
 *
 * While FreeBSD5 has native 32bit LFS support, AIX 5.2 and Solaris 9
 * do not, and so compiling on those platforms requires additional
 * flags in order to pull in the correct definitions.  In a typical 32bit
 * environment, off_t is a long.  In a 32bit LFS environment, off_t becomes
 * a long long.
 *
 * AIX:      cc -D_LARGEFILES getpsize.c
 * Solaris:  cc -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 getpsize.c
 * FreeBSD:  cc getpsize.c
 */

/* Max number of bytes in a device.  This number must be greater
 * than the number of blocks in any device or else getpsize()
 * won't work correctly.
 */
#define DEV_BYTES_MAX       (1024LL*1024*1024*1024*1024)    /* 1PB */
/*#define DEV_BYTES_MAX     (128LL*1024*1024*1024*1024)*/   /* 128TB */


/* Typically, I/O to a block disk device may only take place
 * on a sector boundary.  This macro rounds the given byte
 * offset down to a sector boundary.
 */
#define DEV_ROUND(o)    ((o) & ~(DEV_BSIZE - 1))


/* Returns the number of bytes in `psize' of the device given by `fd'.
 */
int
getpsize(int fd, off_t *psize)
{
    int64_t offset;
    int64_t diff;
    ssize_t cc;

    *psize = 0;

    offset = DEV_BYTES_MAX / 2;
    for (diff = offset / 2; diff > 0; diff /= 2) {
        char buf[512];

        dprint(4, "getpsize: %lld/%lld %lld/%lld %lld\n",
               offset, offset / DEV_BSIZE,
               DEV_ROUND(offset), DEV_ROUND(offset) / DEV_BSIZE,
               diff);

        cc = pread(fd, buf, sizeof(buf), (off_t)DEV_ROUND(offset));
        if (-1 == cc) {
            if ((ENXIO == errno) || (EOVERFLOW == errno) ||
                (EIO == errno)) {
                offset -= diff;
            } else if ((EINTR != errno) && (EAGAIN != errno)) {
                return errno;
            }
        } else if (sizeof(buf) == cc) {
            offset += diff;
        } else if (0 == cc) {
            break;
        } else if (cc != sizeof(buf)) {
            return EIO;
        }
    }

    *psize = DEV_ROUND(offset);

    dprint(4, "getpsize: offset=%lld/%lld diff=%lld psize=%lld/%lld\n",
           offset, offset/DEV_BSIZE, diff, *psize, *psize / DEV_BSIZE);

    return 0;
}


/* Reliable signal.
 */
int
reliable_signal(int signo, sigfunc_t func)
{
    struct sigaction nact;

    bzero(&nact, sizeof(nact));

    nact.sa_handler = func;
    sigemptyset(&nact.sa_mask);

    if ((SIGALRM == signo) || (SIGINT == signo)) {
#ifdef SA_INTERRUPT
        nact.sa_flags |= SA_INTERRUPT;
#endif
    } else {
#ifdef SA_RESTART
        nact.sa_flags |= SA_RESTART;
#endif
    }

    return sigaction(signo, &nact, (struct sigaction *)0);
}
