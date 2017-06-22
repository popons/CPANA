## Process this file with automake to produce Makefile.in

INCLUDES = -I$(srcdir)/.. -I$(top_builddir)/..
lib_LTLIBRARIES = libcpana.la
libcpana_la_LDFLAGS = -version-info 0:0:0
libcpana_la_SOURCES = init.c ctx.c ev.c io.c ioinet6.c ioinet.c msg.h msg.c msgparse.c \
	avp.h avp.c evsimple.c paa.c pac.c log.c hash.c msgsend.c ses.c \
	cpana.h constants.h functions.h types.h io.h ev.h ctx.h hash.h ses.h \
	log.h ses_p.h preconfig.h postconfig.h avpeap.c seq.c \
	rand.c memdup.c auth.c avpcommon.c debug.c strlcat.c debug.h util.h

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
