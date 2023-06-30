SUBDIRS=

if WITH_NDP
SUBDIRS+=input/nfbCInterface
endif

SUBDIRS+=. tests init
bin_PROGRAMS=ipfixprobe ipfixprobe_stats

DISTCHECK_CONFIGURE_FLAGS="--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)"

ipfixprobe_LDFLAGS=-lpthread -ldl -latomic
ipfixprobe_CFLAGS=-I$(srcdir)/include/ -fPIC
ipfixprobe_CXXFLAGS=-std=gnu++11 -Wno-write-strings -I$(srcdir)/include/ -fPIC

if OS_CYGWIN
ipfixprobe_CXXFLAGS+=-Wl,--export-all-symbols
else
ipfixprobe_CXXFLAGS+=-Wl,--export-dynamic
endif

ipfixprobe_input_src=\
		input/benchmark.cpp \
		input/benchmark.hpp \
		input/parser.cpp \
		input/parser.hpp \
		input/headers.hpp

# How to create loadable example.so plugin:
#pkglib_LTLIBRARIES=example.la
#example_la_CXXFLAGS=-I$(srcdir)/include/
#example_la_SOURCES=example.cpp example.hpp
#example_la_LDFLAGS=-module -shared -avoid-version


if WITH_NDP
ipfixprobe_LDFLAGS+=-lnuma -lndpRI -L$(srcdir)/input/nfbCInterface/
ipfixprobe_CXXFLAGS+=-I$(srcdir)/input/nfbCInterface/include/
ipfixprobe_input_src+=\
		input/ndp.cpp \
		input/ndp.hpp
endif

if WITH_RAW
ipfixprobe_input_src+=\
		input/raw.cpp \
		input/raw.hpp
endif

if WITH_PCAP
ipfixprobe_input_src+=\
		input/pcap.cpp \
		input/pcap.hpp
endif

if WITH_STEM
ipfixprobe_input_src+=\
		input/stem.cpp \
		input/stem.hpp
endif

ipfixprobe_storage_src=\
		storage/cache.cpp \
		storage/cache.hpp \
		storage/fragmentationCache/fragmentCache.cpp \
		storage/fragmentationCache/fragmentCache.hpp \
		storage/xxhash.c \
		storage/xxhash.h

ipfixprobe_output_src=\
		output/ipfix.cpp \
		output/ipfix.hpp \
		output/text.cpp \
		output/text.hpp \
		output/ipfix-basiclist.cpp

if WITH_NEMEA
ipfixprobe_output_src+=\
			output/unirec.hpp \
			output/unirec.cpp \
			fields.c \
			fields.h
endif

ipfixprobe_process_src=\
		process/http.cpp \
		process/http.hpp \
		process/rtsp.cpp \
		process/rtsp.hpp \
		process/sip.cpp \
		process/sip.hpp \
		process/tls.cpp \
		process/tls.hpp \
		process/tls_parser.cpp \
		process/tls_parser.hpp \
		process/smtp.cpp \
		process/smtp.hpp \
		process/dns-utils.hpp \
		process/dns.cpp \
		process/dns.hpp \
		process/passivedns.cpp \
		process/passivedns.hpp \
		process/ntp.cpp \
		process/ntp.hpp \
		process/idpcontent.hpp \
		process/idpcontent.cpp \
		process/netbios.hpp \
		process/netbios.cpp \
		process/bstats.hpp \
		process/bstats.cpp \
		process/phists.cpp \
		process/phists.hpp \
		process/pstats.hpp \
		process/pstats.cpp \
		process/ovpn.hpp \
		process/ovpn.cpp \
		process/ssdp.hpp \
		process/ssdp.cpp \
		process/dnssd.hpp \
		process/dnssd.cpp \
		process/basicplus.hpp \
		process/basicplus.cpp \
		process/wg.hpp \
		process/wg.cpp \
		process/stats.cpp \
		process/stats.hpp \
		process/md5.hpp \
		process/md5.cpp \
		process/common.hpp \
		process/ssadetector.hpp \
		process/ssadetector.cpp \
		process/icmp.hpp \
		process/icmp.cpp

if WITH_QUIC
ipfixprobe_process_src+=\
		process/quic.hpp \
		process/quic.cpp \
		process/quic_parser.cpp \
		process/quic_parser.hpp

endif

if WITH_FLEXPROBE
ipfixprobe_process_src+=\
		process/flexprobe-data.h \
		process/flexprobe-data-processing.cpp \
		process/flexprobe-data-processing.h \
		process/flexprobe-tcp-tracking.cpp \
		process/flexprobe-tcp-tracking.h \
		process/flexprobe-encryption-processing.cpp \
		process/flexprobe-encryption-processing.h
endif

if WITH_OSQUERY
ipfixprobe_input_src+=\
      process/osquery.cpp\
      process/osquery.hpp
endif

if WITH_DPDK
ipfixprobe_input_src+=\
		input/dpdk/dpdkMbuf.hpp \
		input/dpdk/dpdkMbuf.cpp \
		input/dpdk/dpdkDevice.hpp \
		input/dpdk/dpdkDevice.cpp \
        input/dpdk.cpp \
        input/dpdk.h \
	input/dpdk-ring.cpp \
	input/dpdk-ring.h
endif

ipfixprobe_headers_src=\
		include/ipfixprobe/plugin.hpp \
		include/ipfixprobe/input.hpp \
		include/ipfixprobe/storage.hpp \
		include/ipfixprobe/output.hpp \
		include/ipfixprobe/process.hpp \
		include/ipfixprobe/options.hpp \
		include/ipfixprobe/utils.hpp \
		include/ipfixprobe/ipfix-basiclist.hpp \
		include/ipfixprobe/flowifc.hpp \
		include/ipfixprobe/ipaddr.hpp \
		include/ipfixprobe/packet.hpp \
		include/ipfixprobe/ring.h \
		include/ipfixprobe/byte-utils.hpp \
		include/ipfixprobe/ipfix-elements.hpp

ipfixprobe_src=\
		$(ipfixprobe_input_src) \
		$(ipfixprobe_storage_src) \
		$(ipfixprobe_output_src) \
		$(ipfixprobe_process_src) \
		$(ipfixprobe_headers_src) \
		pluginmgr.cpp \
		pluginmgr.hpp \
		options.cpp \
		utils.cpp \
		ring.c \
		workers.cpp \
		workers.hpp \
		stats.cpp \
		stats.hpp \
		ipfixprobe.hpp \
		ipfixprobe.cpp

if WITH_LIBUNWIND
ipfixprobe_src+=\
		stacktrace.cpp \
		stacktrace.hpp
endif

ipfixprobe_SOURCES=$(ipfixprobe_src) main.cpp

ipfixprobe_stats_CXXFLAGS=-std=gnu++11 -Wno-write-strings -I$(srcdir)/include/
ipfixprobe_stats_SOURCES=ipfixprobe_stats.cpp \
		include/ipfixprobe/options.hpp \
		include/ipfixprobe/utils.hpp \
		stats.cpp \
		stats.hpp \
		options.cpp \
		utils.cpp

pkgdocdir=${docdir}/ipfixprobe
pkgdoc_DATA=README.md
EXTRA_DIST=README.md \
	pcaps/README.md \
	pcaps/mixed.pcap \
	pcaps/dns.pcap \
	pcaps/dnssd.pcap \
	pcaps/http.pcap \
	pcaps/rtsp.pcap \
	pcaps/tls.pcap \
	pcaps/ntp.pcap \
	pcaps/sip.pcap \
	pcaps/ssdp.pcap \
	pcaps/netbios.pcap \
	pcaps/smtp.pcap \
	pcaps/ovpn.pcap \
	pcaps/idpcontent.pcap \
	pcaps/bstats.pcap \
	pcaps/wg.pcap \
	pcaps/quic_initial-sample.pcap \
	debian/control debian/changelog debian/watch debian/copyright debian/patches debian/patches/series \
	debian/source debian/source/format debian/source/local-options debian/source/include-binaries \
	debian/rules debian/README.Debian debian/compat

bashcompl_DATA=ipfixprobe.bash

if HAVE_GOOGLETEST
check_LTLIBRARIES=libipfixprobe.la
libipfixprobe_la_SOURCES=$(ipfixprobe_src)
libipfixprobe_la_LDFLAGS=$(ipfixprobe_LDFLAGS)
libipfixprobe_la_CFLAGS=$(ipfixprobe_CFLAGS)
libipfixprobe_la_CXXFLAGS=$(ipfixprobe_CXXFLAGS)

check-local:
	@if test -e googletest/googletest/Makefile; then \
		( cd googletest/googletest && $(MAKE) $(AM_MAKEFLAGS) lib/libgtest.la lib/libgtest_main.la ); \
		( cd googletest/googlemock && $(MAKE) $(AM_MAKEFLAGS) lib/libgmock.la lib/libgmock_main.la ); \
	else \
		echo "missing googletest submodule, run `git submodule init && git submodule update` and reconfigure"; \
	fi;

clean-local:
	@if test -e googletest/googletest/Makefile; then \
	  ( cd googletest/googletest && $(MAKE) $(AM_MAKEFLAGS) clean; ) \
	fi
endif

RPMDIR = RPMBUILD

if MAKE_RPMS
RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)

.PHONY: srpm
srpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -bs $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

.PHONY: rpm
rpm: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with pcap --with unwind;

.PHONY: rpm-nemea
rpm-nemea: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with nemea --with pcap --with unwind;

.PHONY: rpm-ndp
rpm-ndp: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with ndp --with unwind;
else
endif

rpm-clean:
	rm -rf $(RPMDIR)

if WITH_NEMEA
include ./aminclude.am
else
fields.h fields.c:
	touch $@
endif

if MAKE_DEB
.PHONY: deb-source
deb-source:
	make dist && make distdir && ln -fs ipfixprobe-@VERSION@.tar.gz ipfixprobe_@VERSION@ubuntu@RELEASE@.orig.tar.gz && cd ipfixprobe-@VERSION@ && debuild -S

.PHONY: deb
deb:
	make dist && make distdir && ln -fs ipfixprobe-@VERSION@.tar.gz ipfixprobe_@VERSION@ubuntu@RELEASE@.orig.tar.gz && cd ipfixprobe-@VERSION@ && debuild
else
endif

