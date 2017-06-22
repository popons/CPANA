#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(cpana, 20100819a, cpana@isl.rdc.toshiba.co.jp)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([cpana.h])
AM_CONFIG_HEADER([config.h])
AC_CANONICAL_HOST

AH_TOP([#ifndef _CPANA_CONFIG_H
#define _CPANA_CONFIG_H
#include <cpana/preconfig.h>
])
AH_BOTTOM([#include <cpana/postconfig.h>
#endif /* !_CPANA_CONFIG_H */
])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AC_CHECK_TOOL(RANLIB, ranlib, :)

case "$host" in
*-*-solaris*)
  AC_DEFINE(__EXTENSIONS__, 1, [Define to 1 for va_copy on Solaris])
  ;;
esac

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([sys/select.h sys/socket.h arpa/inet.h netinet/in.h])
AC_CHECK_HEADERS([net/if.h],[],[],
[#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_CHECK_HEADERS([inttypes.h syslog.h windows.h])
AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],[],[],
[#if HAVE_WINDOWS_H
# include <windows.h>
#endif
])

AC_CHECK_HEADER([winsock2.h],[LIBS="-lws2_32 $LIBS"],[],
[#if HAVE_WINDOWS_H
# include <windows.h>
#endif
])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_LIB(nsl, inet_pton)
AC_CHECK_LIB(socket, socket)
AC_CHECK_FUNCS([asprintf vasprintf _vsnprintf gettimeofday])
AC_CHECK_FUNCS([inet_addr inet_pton inet_aton])

## If we're using GCC, ask for aggressive warnings.
case "$GCC" in
  yes ) CFLAGS="$CFLAGS -Wall -Wpointer-arith" ;;
esac

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
