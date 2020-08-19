if HAVE_NDP
SUBDIRS=nfbCInterface
else
SUBDIRS=
endif

SUBDIRS+=. tests
bin_PROGRAMS=ipfixprobe

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
		httpsplugin.cpp \
		httpsplugin.h \
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
		dnssdplugin.cpp


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
	traffic-samples/https-sample.pcap \
	traffic-samples/ntp-sample.pcap \
	traffic-samples/sip-sample.pcap \
	traffic-samples/ssdp-sample.pcap \
	traffic-samples/smtp-sample.pcap \
	traffic-samples/ovpn-sample.pcap

bashcompl_DATA=ipfixprobe.bash

if WITH_NEMEA
include ./aminclude.am
endif

