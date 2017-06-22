## Process this file with automake to produce Makefile.in

if RADIUS
RADLIB = -lradius
else
RADLIB =
endif

if OPENSSL
OPENSSLLIB = -lssl -lcrypto
else
OPENSSLLIB =
endif

bin_PROGRAMS = cpaa
cpaa_SOURCES = main.c cpaa.h \
	../common/xmalloc.c ../common/xmalloc.h \
	../common/spawnvem.c ../common/spawnvem.h \
	../common/allocenvpair.c ../common/allocenvpair.h
cpaa_LDADD = -L../../cpana/.libs -lcpana -L../../ceap/.libs -lceap -L../../clpe/.libs -lclpe $(RADLIB) $(OPENSSLLIB)
INCLUDES = -I$(srcdir)/.. -I$(srcdir)/../.. -I$(top_builddir)/.. -I$(top_builddir)/../..
EXTRA_DIST = userdb.example
