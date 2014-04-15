h_sources = ics.h icscommon.h icspredicate.h icsiec61131.h \
            icsdnp3.h icsenip.h icscip.h icsmodbus.h

c_sources = ics.c icscommon.c icspredicate.c \
            icsdnp3.c icsenip.c icscip.c icsmodbus.c 

library_includedir = $(includedir)/libics
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)
AM_CFLAGS = -D_GNU_SOURCE -g3 -Wall -Wextra -std=gnu99 -pedantic

lib_LTLIBRARIES = libics.la
libics_la_SOURCES = $(h_sources) $(c_sources)
libics_la_LDFLAGS = 

