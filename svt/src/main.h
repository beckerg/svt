/*
 * Copyright (c) 2001-2006,2011,2015,2019,2022 Greg Becker.  All rights reserved.
 */
#ifndef PROG_H
#define PROG_H

#define FSX_MAGIC       (0x900dcafe900dbeef)

#ifndef DEV_BSIZE
#define DEV_BSIZE       (512)
#endif

#if !defined HAVE_STRTOLL
#if defined strtoimax || defined HAVE_STRTOIMAX
/* HPUX 11.0 has strtoimax(), but not strtoll() */
#define strtoll strtoimax
#define HAVE_STRTOLL
#endif
#endif

/* The command line parser sets the following global variables:
 */
extern char *progname;      // The programe name (i.e., the basename of argv[0])
extern int verbosity;       // The number of times -v appeared on the command line

extern bool headers;
extern bool verify;

/* By default dprint() and eprint() print to stderr.  You can change that
 * behavior by simply setting these variables to a different stream.
 */
extern FILE *dprint_stream;
extern FILE *eprint_stream;


/* dprint() prints a message if (lvl >= verbosity).  ('verbosity' is
 * incremented for each -v option given on the command line).
 * Each message is preceded by: "progname(pid): func:line"
 */
#define dprint(lvl, ...)                                            \
do {                                                                \
    if ((lvl) <= verbosity) {                                       \
        dprint_impl((lvl), __func__, __LINE__, __VA_ARGS__);        \
    }                                                               \
} while (0);

extern void dprint_impl(int lvl, const char *func, int line, const char *fmt, ...)
    __attribute__((format (printf, 4, 5)));


/* Call eprint() to print an error message that should always be emitted.
 * It simply prints the given message preceded by the program name.
 */
extern void eprint(const char *fmt, ...)
    __attribute__((format (printf, 1, 2)));


#endif /* PROG_H */
