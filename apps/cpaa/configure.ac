#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(cpaa, 20100819a, cpana@isl.rdc.toshba.co.jp)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([main.c])
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP

# Checks for libraries.
AC_CHECK_LIB(nsl, inet_pton)
AC_CHECK_LIB(socket, socket)

AC_MSG_CHECKING(--with-libradius)
AC_ARG_WITH(libradius,
[  --with-libradius        enable RADIUS support using libradius],,
  with_libradius=no
)
AC_MSG_RESULT($with_libradius)
AM_CONDITIONAL(RADIUS,test x"$with_libradius" != xno)
if test x"$with_libradius" != x"no"; then
  AC_DEFINE(WITH_RADIUS, 1, [if RADIUS support is enabled])
  if test x"$with_libradius" != x"yes"; then
    CPPFLAGS="$CPPFLAGS -I$with_libradius"
    LDFLAGS="$LDFLAGS -L$with_libradius"
  fi
  AC_CHECK_LIB(radius, rad_auth_open,,[AC_MSG_ERROR("cannot find libradius")],[-lcrypto])
  LIBS="$LIBS -lcrypto"
  AC_CHECK_HEADERS([sys/param.h])
  AC_CHECK_FUNCS([gethostname])
fi

AC_MSG_CHECKING(--with-openssl)
AC_ARG_WITH(openssl,
[  --with-openssl          use OpenSSL],
  with_openssl=$withval
  AC_MSG_RESULT($with_openssl),
  with_openssl=yes
  AC_MSG_RESULT($with_openssl (default))
)
AM_CONDITIONAL(OPENSSL, test x"$with_openssl" != xno)
if test $with_openssl != no; then
  AC_DEFINE(WITH_OPENSSL, 1, [if OpenSSL is enabled])
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
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h stdlib.h sys/socket.h inttypes.h syslog.h])
AC_CHECK_HEADERS([sys/wait.h])

AC_CHECK_HEADERS([windows.h])
AC_CHECK_HEADER([wincrypt.h],[LIBS="-ladvapi32 $LIBS"],[],
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
AC_CHECK_FUNCS([fork _spawnve])

## If we're using GCC, ask for aggressive warnings.
case "$GCC" in
  yes ) CFLAGS="$CFLAGS -Wall -Wpointer-arith" ;;
esac

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
