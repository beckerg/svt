# svt

## DESCRIPTION ##

    svt is a tool for validating disk drivers, file systems, and
    lock managers.  More than a simple exerciser, svt is able to
    detect if certain data integrity error occur.


## BUILDING ##

    To build, simply type ``./configure && make''.


## DIRECTORIES ##

    src		The source code to dits.
    ports	Stuff for the FreeBSD ports system.


## CAVEATS ##

    svt is still in the process of being fully converted to the
    autoconf system of configuration so not all facilities are
    currently being handled in the proper manner.

    The configure script built on FreeBSD doesn't run on Solaris.
    For now, run ``./bootstrap'' to build a working configure.
