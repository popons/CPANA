#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(clpe, 20100819a, cpana@isl.rdc.toshiba.co.jp)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([clpe.h])
AM_CONFIG_HEADER([config.h])

AH_TOP([#ifndef _CLPE_CONFIG_H
#define _CLPE_CONFIG_H
#include <clpe/preconfig.h>
])
AH_BOTTOM([#include <clpe/postconfig.h>
#endif /* !_CLPE_CONFIG_H */
])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AC_C_BIGENDIAN(, [
  AC_DEFINE([WORDS_LITTLEENDIAN], 1,
	    [Define to 1 if your processor stores words with the least
      significant byte first (like Intel and VAX, unlike Motorola and SPARC).])
])

# Checks for libraries.
AC_MSG_CHECKING(--with-openssl)
AC_ARG_WITH(openssl,
[  --with-openssl          use OpenSSL],
  with_openssl=$withval
  AC_MSG_RESULT($with_openssl),
  with_openssl=yes
  AC_MSG_RESULT($with_openssl (default)))
if test $with_openssl != no; then
  AC_DEFINE(WITH_OPENSSL, 1, [if OpenSSL is enabled])
  if test $with_openssl != yes; then
    CPPFLAGS="$CPPFLAGS -I$with_openssl/include"
    LDFLAGS="$LDFLAGS -L$with_openssl"
  fi
  AC_CHECK_LIB(dl, dlopen)
  LIBS="$LIBS -lcrypto"
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h err.h inttypes.h paths.h syslog.h windows.h])
AC_CHECK_HEADERS([wincrypt.h],,,
[#if HAVE_WINDOWS_H
# include <windows.h>
#endif
])
AC_CHECK_HEADER([wincrypt.h],[LIBS="-ladvapi32 $LIBS"],[],
[#if HAVE_WINDOWS_H
# include <windows.h>
#endif
])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([warn warnx err errx srandom])
AC_CHECK_FUNCS([asprintf vasprintf _vsnprintf vsnprintf])

dnl # autoconf cannot find CryptGenRandom@12 from libadvapi32.a,
dnl # so we need another way to guess.
dnl # see AC_CHECK_HEADER(wincrypt.h,...)
dnl AC_CHECK_LIB(advapi32, CryptGenRandom)

## If we're using GCC, ask for aggressive warnings.
case "$GCC" in
  yes ) CFLAGS="$CFLAGS -Wall -Wpointer-arith" ;;
esac

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
