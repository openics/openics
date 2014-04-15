bin_PROGRAMS = icsids

INCLUDES = -I../libics -I../../nids

AM_CFLAGS = -DENABLE_TCPREASM
AM_LDFLAGS = -lpthread -lpcap -lpcre -lnet -lrt -lm

icsids_SOURCES = \
 icsids.c icsids.h \
 icsids-args.c icsids-args.h \
 icsids-process.c icsids-process.h

icsids_LDADD = \
 $(top_builddir)/src/libics/libics.la \
 $(top_builddir)/nids/libnids.a

