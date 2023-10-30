if HAVE_GOOGLETEST
cppflags=-I$(top_srcdir)/include/ -I$(top_srcdir)/googletest/googletest/include
ldflags=-lipfixprobe -L$(top_srcdir)/.libs -lgtest -L$(top_srcdir)/googletest/googletest/lib
else
cppflags=
ldflags=
endif

check_PROGRAMS=utils byte_utils options flowifc unirec cache

if HAVE_GOOGLETEST
utils_SOURCES=utils.cpp
else
utils_SOURCES=skip.cpp
endif
utils_CPPFLAGS=$(cppflags)
utils_LDFLAGS=$(ldflags)

if HAVE_GOOGLETEST
byte_utils_SOURCES=byte-utils.cpp
else
byte_utils_SOURCES=skip.cpp
endif
byte_utils_CPPFLAGS=$(cppflags)
byte_utils_LDFLAGS=$(ldflags)

if HAVE_GOOGLETEST
options_SOURCES=options.cpp
else
options_SOURCES=skip.cpp
endif
options_CPPFLAGS=$(cppflags)
options_LDFLAGS=$(ldflags)

if HAVE_GOOGLETEST
flowifc_SOURCES=flowifc.cpp
else
flowifc_SOURCES=skip.cpp
endif
flowifc_CPPFLAGS=$(cppflags)
flowifc_LDFLAGS=$(ldflags) -ldl

if HAVE_GOOGLETEST
unirec_SOURCES=unirec.cpp
else
unirec_SOURCES=skip.cpp
endif
unirec_CPPFLAGS=$(cppflags)
unirec_LDFLAGS=$(ldflags)

if HAVE_GOOGLETEST
cache_SOURCES=cache.cpp
else
cache_SOURCES=skip.cpp
endif
cache_CPPFLAGS=$(cppflags)
cache_LDFLAGS=$(ldflags)

TESTS=$(check_PROGRAMS)
