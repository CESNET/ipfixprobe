if HAVE_NDP
SUBDIRS=nfbCInterface
else
SUBDIRS=
endif

SUBDIRS+=. tests init
bin_PROGRAMS=ipfixprobe

DISTCHECK_CONFIGURE_FLAGS="--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)"

if HAVE_NDP
AM_LDFLAGS=${srcdir}/nfbCInterface/libndpRI.la
ipfixprobe_ldflags=-lnuma -lnfb -lndpRI
else
ipfixprobe_ldflags=-lpcap
endif

ipfixprobe_CXXFLAGS=-std=c++98 -Wno-write-strings -I./nfbCInterface/include/


ipfixprobe_src=main.cpp \
		ipfixprobe.h \
		packet.h \
		packetreceiver.h \
		pcapreader.h \
		flowexporter.h \
		flowifc.h \
		flowcache.h \
		pcapreader.cpp \
		nhtflowcache.cpp \
		nhtflowcache.h \
		stats.cpp \
		stats.h \
		flowcacheplugin.h \
		httpplugin.cpp \
		httpplugin.h \
		rtspplugin.cpp \
		rtspplugin.h \
		sipplugin.cpp \
		sipplugin.h \
		tlsplugin.cpp \
		tlsplugin.h \
		smtpplugin.cpp \
		smtpplugin.h \
		dnsplugin.cpp \
		dnsplugin.h \
		passivednsplugin.cpp \
		passivednsplugin.h \
		ntpplugin.cpp \
		ntpplugin.h \
		ipaddr.h \
		arpplugin.cpp \
		arpplugin.h \
		ipfixexporter.cpp \
		ipfix-elements.h \
		ipfixexporter.h \
		xxhash.c \
		xxhash.h \
		dns.h \
		conversion.h \
		conversion.cpp \
		pstatsplugin.h \
		pstatsplugin.cpp \
		ovpnplugin.h \
		ovpnplugin.cpp \
		byte-utils.h \
		ssdpplugin.h \
		ssdpplugin.cpp \
		dnssdplugin.h \
		dnssdplugin.cpp \
		md5.h \
		md5.cpp \
		idpcontentplugin.h \
		idpcontentplugin.cpp \
		netbiosplugin.h \
		netbiosplugin.cpp \
		bstatsplugin.h \
		bstatsplugin.cpp \
		ipfix-basiclist.cpp \
		ipfix-basiclist.h \
		basicplusplugin.h \
		basicplusplugin.cpp


if WITH_NEMEA
ipfixprobe_SOURCES=$(ipfixprobe_src) \
			fields.c \
			fields.h \
			unirecexporter.h \
			unirecexporter.cpp
else
ipfixprobe_SOURCES=$(ipfixprobe_src)
endif

pkgdocdir=${docdir}/ipfixprobe
pkgdoc_DATA=README.md
EXTRA_DIST=README.md \
	traffic-samples/README.md \
	traffic-samples/arp-sample.pcap \
	traffic-samples/mixed-sample.pcap \
	traffic-samples/dns-sample.pcap \
	traffic-samples/dnssd-sample.pcap \
	traffic-samples/http-sample.pcap \
	traffic-samples/rtsp-sample.pcap \
	traffic-samples/tls-sample.pcap \
	traffic-samples/ntp-sample.pcap \
	traffic-samples/sip-sample.pcap \
	traffic-samples/ssdp-sample.pcap \
	traffic-samples/netbios-sample.pcap \
	traffic-samples/smtp-sample.pcap \
	traffic-samples/ovpn-sample.pcap \
	traffic-samples/idpcontent-sample.pcap \
	traffic-samples/bstats-sample.pcap

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
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm;

.PHONY: rpm-nemea
rpm-nemea: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with nemea;

.PHONY: rpm-ndp
rpm-ndp: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm --with ndp;
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
