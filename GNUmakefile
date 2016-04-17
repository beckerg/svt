# $Id$


SUBDIRS = svt

SVT_VERSION	:= 1.0.0
SVT_DIST	:= svt-${SVT_VERSION}
SVT_DEST	:= /usr/local/www/apache24/data/codeconcepts/


.DELETE_ON_ERROR:

.PHONY:	all clean clobber cscope debug distclean tags ${SUBDIRS}


all cscope debug tags: ${SUBDIRS}

${SUBDIRS}:
	if [ ! -f $@/Makefile ] ; then cd $@ && ./configure; fi
	${MAKE} -C $@ ${MAKECMDGOALS}

clean: ${SUBDIRS}
	rm -rf svt-*

clobber: distclean

distclean: ${SUBDIRS}
	rm -rf svt-* ${SVT_DIST}.diff

# The 'port' target generates a tarball and a diff file for the FreeBSD
# ports system.  The tarball goes into the website for distribution, and
# the diff file must be submitted via send-pr(1).
#
port: ${SVT_DIST}.diff

${SVT_DIST}.diff: ${SVT_DIST}
	-(cd $</ports && diff -u /usr/ports/devel/svt .) > $@

# We first update ports/Makefile to reflect the current version of svt.c
# If there are any pending modifications to the svt tree we bail.
# Next, we create a new directory named for the current version of svt,
# and then tar it up in a reproducible manner by keeping the tarball
# strictly ordered and the dates of all files fixed to the date of the
# last checkin to svt.c.
#
${SVT_DIST}:
	sed -i '' -E 's/(PORTVERSION=[^0-9]*).*/\1'${SVT_VERSION}'/' svt/ports/Makefile
	svnversion svt | grep -v 'M$$'
	rm -rf svt-*
	cp -a svt $@
	cd $@ && make distclean || true
	rm -f $@/ports/distinfo
	find -d $@ -exec touch -d "${SVT_DATE}" {} \; -print | sort | \
		tar --uid 0 --gid 0 -jncf $@.tar.bz2 -T-
	sudo cp -a $@.tar.bz2 ${SVT_DEST}
	sudo rm -f /usr/ports/distfiles/svt-*
	cd $@/ports && sudo make makesum



