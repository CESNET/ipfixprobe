SUBDIRS=

if HAVE_NDP
SUBDIRS+=input/nfbCInterface
endif

SUBDIRS+=. tests init
bin_PROGRAMS=ipfixprobe

DISTCHECK_CONFIGURE_FLAGS="--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)"

ipfixprobe_LDFLAGS=-lpthread -ldl
if HAVE_NDP
ipfixprobe_LDFLAGS+=-lnuma -lnfb -lndpRI -L$(srcdir)/input/nfbCInterface/
endif

ipfixprobe_CXXFLAGS=-std=gnu++11 -Wno-write-strings -I$(srcdir)/include/ -I$(srcdir)/input/nfbCInterface/include/ -Wl,--export-dynamic
ipfixprobe_CFLAGS=-I$(srcdir)/include/

ipfixprobe_input_src=\
		input/raw.cpp \
		input/raw.hpp \
		input/pcap.cpp \
		input/pcap.hpp \
		input/ndp.cpp \
		input/ndp.hpp \
		input/benchmark.cpp \
		input/benchmark.hpp \
		input/parser.cpp \
		input/parser.hpp \
		input/headers.hpp

ipfixprobe_storage_src=\
		storage/cache.cpp \
		storage/cache.hpp \
		storage/xxhash.c \
		storage/xxhash.h

ipfixprobe_output_src=\
		output/ipfix.cpp \
		output/ipfix.hpp \
		output/text.cpp \
		output/text.hpp \
		output/ipfix-basiclist.cpp

ipfixprobe_process_src=\
		process/http.cpp \
		process/http.hpp \
		process/rtsp.cpp \
		process/rtsp.hpp \
		process/sip.cpp \
		process/sip.hpp \
		process/tls.cpp \
		process/tls.hpp \
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
		process/md5.cpp

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
		stacktrace.cpp \
		stacktrace.hpp \
		options.cpp \
		utils.cpp \
		ring.c \
		workers.cpp \
		workers.hpp \
		ipfixprobe.hpp \
		ipfixprobe.cpp \
		main.cpp

if WITH_NEMEA
ipfixprobe_src+=\
			fields.c \
			fields.h

ipfixprobe_output_src+=\
			output/unirec.hpp \
			output/unirec.cpp
endif


ipfixprobe_SOURCES=$(ipfixprobe_src)

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
	pcaps/wg.pcap

bashcompl_DATA=ipfixprobe.bash


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
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with unwind;

.PHONY: rpm-nemea
rpm-nemea: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with nemea --with unwind;

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
