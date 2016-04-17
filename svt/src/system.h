/*
 * Copyright (c) 2001-2006,2015 Greg Becker.  All rights reserved.
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
#ifndef SYSTEM_H
#define SYSTEM_H

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

#if HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#include <assert.h>
#include <signal.h>
#include <sysexits.h>
#include <fcntl.h>
#include <time.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/select.h>
#include <math.h>

#endif /* SYSTEM_H */
