SUBDIRS=.
lib_LTLIBRARIES=libndpRI.la

include_HEADERS=include/ndpreader.hpp\
		include/ndpheader.h \
		include/ndpreader.h

LIBS=$(NONNEMEA_LIBS)
libndpRI_src=ndpreader.cpp

libndpRI_la_SOURCES=$(libndpRI_src)

libndpRI_la_LIBADD= -lnuma -lnfb
libndpRI_la_CXXFLAGS= -I include -std=c++11 -Wno-write-strings

METASOURCES = AUTO
