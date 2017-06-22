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

bin_PROGRAMS = cpac
cpac_SOURCES = main.c cpac.h \
	../common/xmalloc.c ../common/xmalloc.h \
	../common/spawnvem.c ../common/spawnvem.h \
	../common/allocenvpair.c ../common/allocenvpair.h
cpac_LDADD = -L../../cpana/.libs -lcpana -L../../ceap/.libs -lceap -L../../clpe/.libs -lclpe $(OPENSSLLIB)
INCLUDES = -I$(srcdir)/.. -I$(srcdir)/../.. -I$(top_builddir)/.. -I$(top_builddir)/../..
