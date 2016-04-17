# $Id: Makefile.am 15 2005-04-23 13:04:30Z greg $
#
bin_PROGRAMS = svt
svt_SOURCES = main.h main.c cf.h cf.c init.h init.c check.h check.c test.h test.c rtck.h rtck.c tb.h tb.c murmur3.h murmur3.c clp.c

# svt.1 was generated from svt.txt by txt2man:
# $ txt2man -p -s 1 svt.txt > svt.1
#
man1_MANS = svt.1
EXTRA_DIST = svt.txt svt.1

DEFS += -DSVT_VERSION=\"${PACKAGE_VERSION}\"
