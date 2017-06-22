## Process this file with automake to produce Makefile.in

INCLUDES = -I$(srcdir)/.. -I$(top_builddir)/..
lib_LTLIBRARIES = libclpe.la
libclpe_la_LDFLAGS = -version-info 0:0:0
libclpe_la_SOURCES = rand.c log.c logfp.c clpe.h rand.h log.h \
	md5.h md5c.c debug.h preconfig.h postconfig.h misc.h \
	blkciph.h ctr.h ctr.c \
	aesaes.h aesopt.h aeskey.c aescrypt.c aestab.c \
	omac.h omac.c eax.h eax.c \
	asprintf.c vasprintf.c \
	hash.c hash.h hmac.c hmac.h sha1.c 
EXTRA_libclpe_la_SOURCES = aestest.c omactest.c ctrtest.c eaxtest.c

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
