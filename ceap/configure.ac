#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(ceap, 20100819a, cpana@isl.rdc.toshiba.co.jp)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([ceap.h])
AM_CONFIG_HEADER([config.h])

AH_TOP([#ifndef _CEAP_CONFIG_H
#define _CEAP_CONFIG_H
#include <ceap/preconfig.h>
])
AH_BOTTOM([#include <ceap/postconfig.h>
#endif /* !_CEAP_CONFIG_H */
])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

# Checks for libraries.
AC_MSG_CHECKING(--with-libradius)
AC_ARG_WITH(libradius,
[  --with-libradius        enable RADIUS support using libradius],,
  with_libradius=no
)
AC_MSG_RESULT($with_libradius)
AM_CONDITIONAL(RADIUS,test x$with_libradius != xno)
if test x"$with_libradius" != x"no"; then
  AC_DEFINE(WITH_RADIUS, 1, [if RADIUS support is enabled])
  if test x"$with_libradius" != x"yes"; then
    CPPFLAGS="$CPPFLAGS -I$with_libradius"
    LDFLAGS="$LDFLAGS -L$with_libradius"
  fi
fi

AC_MSG_CHECKING(--with-openssl)
AC_ARG_WITH(openssl,
[  --with-openssl          use OpenSSL],
  with_openssl=$withval
  AC_MSG_RESULT($with_openssl),
  with_openssl=yes
  AC_MSG_RESULT($with_openssl (default)))
if test $with_openssl != no; then
  if test $with_openssl != yes; then
    CPPFLAGS="$CPPFLAGS -I$with_openssl/include"
    LDFLAGS="$LDFLAGS -L$with_openssl"
  fi
  AC_CHECK_LIB(dl, dlopen)
  AC_CHECK_LIB(ssl, SSL_CTX_new,, [AC_MSG_ERROR("cannot find libssl")], [-lssl -lcrypto])
  LIBS="$LIBS -lssl -lcrypto"
fi

AC_MSG_CHECKING(--enable-eap-tls)
with_eap_tls=no
AC_ARG_ENABLE(eap-tls,
[  --enable-eap-tls       use EAP-TLS],
  with_eap_tls=$enableval)
AC_MSG_RESULT($with_eap_tls)
AM_CONDITIONAL(EAPTLS, test x"$with_eap_tls" != xno)
if test x"$with_eap_tls" != x"no"; then
  if test x"$with_openssl" = x"no"; then
    AC_MSG_ERROR(--enable-eap-tls need --with-openssl)
  fi
  AC_DEFINE(ENABLE_EAP_TLS, 1, [define if EAP-TLS is enabled])
fi

AC_MSG_CHECKING(--enable-eap-ttls)
with_eap_ttls=$with_eap_tls
AC_ARG_ENABLE(eap-ttls,
[  --enable-eap-ttls       use EAP-TTLS],
  with_eap_ttls=$enableval)
AC_MSG_RESULT($with_eap_ttls)
AM_CONDITIONAL(EAPTTLS, test x"$with_eap_ttls" != xno)
if test x"$with_eap_ttls" != x"no"; then
  if test x"$with_openssl" = x"no"; then
    AC_MSG_ERROR(--enable-eap-ttls need --with-openssl)
  fi
  AC_DEFINE(ENABLE_EAP_TTLS, 1, [define if EAP-TTLS is enabled])
fi

# Checks for header files.
AC_CHECK_HEADERS([radlib.h radius.h],[break],[])
AC_CHECK_HEADERS([stdbool.h stdlib.h arpa/inet.h inttypes.h syslog.h windows.h])
AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],[],[],
[#if HAVE_WINDOWS_H
# include <windows.h>
#endif
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE

# Checks for library functions.
AC_CHECK_FUNCS(getenv)

## If we're using GCC, ask for aggressive warnings.
case "$GCC" in
  yes ) CFLAGS="$CFLAGS -Wall -Wpointer-arith" ;;
esac

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
