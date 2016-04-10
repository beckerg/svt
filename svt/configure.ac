# $Id$
#
# Process this file with autoconf to produce a configure script.
#
AC_INIT([fsx],[1.0],[greg@codeconcepts.com])
AC_PREREQ(2.61)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE

AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CC
AC_CANONICAL_HOST

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([aio.h errno.h fcntl.h stdlib.h string.h strings.h sys/file.h sys/param.h unistd.h stdbool.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPE([int64_t])

# Checks for library functions.
AC_FUNC_FORK
#AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([alarm bzero ftruncate memset strerror strrchr strtoul strtoll strtoimax setpgid])

AC_CHECK_FUNCS([aio_read aio_write aio_error aio_return aio_suspend])

# Check for some target-specific stuff
#
# mmap on aix works for our purposes although it doesn't pass the
# configure test.
#
case "$host" in
*-*-aix6*)
	CFLAGS="$CFLAGS -DAIX6 -DHAVE_MMAP"
	;;

*-*-aix5*)
	CFLAGS="$CFLAGS -DAIX5 -DHAVE_MMAP"
	;;

*-*-aix4*)
	CFLAGS="$CFLAGS -DAIX4 -DHAVE_MMAP"
	;;

*-*-freebsd*)
	CFLAGS="$CFLAGS"
	;;

*-*-solaris2.8*)
	CFLAGS="$CFLAGS"
	LIBS="$LIBS -lrt"
	;;

*-*-solaris2.9*)
	CFLAGS="$CFLAGS"
	LIBS="$LIBS -lrt"
	;;

*-*-solaris2.10)
	CFLAGS="$CFLAGS"
	LIBS="$LIBS -lrt"
	;;

i386-pc-solaris2.11)
	CFLAGS="$CFLAGS"
	LIBS="$LIBS -lrt"
	;;

*-*-hpux11.11*)
	CFLAGS="$CFLAGS +DAportable -DHPUX1111 -D_FILE_OFFSET_BITS=64 -DHAVE_MMAP"
	LDFLAGS="$LDFLAGS -lrt"
	;;

*-*-hpux11.23*)
	CFLAGS="$CFLAGS +DAportable -DHPUX1123 -D_FILE_OFFSET_BITS=64 -DHAVE_MMAP"
	LDFLAGS="$LDFLAGS -lrt"
	;;

*-*-linux-gnu)
	CFLAGS="$CFLAGS"
	LIBS="$LIBS -lrt"
	;;

*)
	echo "unrecognized platform: host="$host
	;;
esac



AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
