## Process this file with automake to produce Makefile.in

INCLUDES = -I$(srcdir)/.. -I$(top_builddir)/..

lib_LTLIBRARIES = libceap.la
libceap_la_LDFLAGS = -version-info 0:0:0
libceap_la_SOURCES = ctx.c ses.c auth.c log.c sendpkt.c recv.c \
	authstand.c peerstand.c identauth.c identpeer.c md5auth.c md5peer.c \
	psk.c pskauth.c pskpeer.c \
	ceap.h ctx.h ses.h auth.h log.h preconfig.h postconfig.h psk.h

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
