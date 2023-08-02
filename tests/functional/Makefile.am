TESTS=basic.sh \
	basicplus.sh \
	http.sh \
	rtsp.sh \
	tls.sh \
	dns.sh \
	passivedns.sh \
	dnssd.sh \
	sip.sh \
	smtp.sh \
	ntp.sh \
	pstats.sh \
	ovpn.sh \
	ssdp.sh \
	netbios.sh \
	idpcontent.sh \
	bstats.sh \
	phists.sh \
	wg.sh \
	ssadetector.sh \
	vlan.sh \
	nettisa.sh

if WITH_QUIC
TESTS+=\
	quic.sh
endif

EXTRA_DIST=common.sh \
	basic.sh \
	basicplus.sh \
	http.sh \
	rtsp.sh \
	tls.sh \
	dns.sh \
	passivedns.sh \
	dnssd.sh \
	sip.sh \
	smtp.sh \
	ntp.sh \
	pstats.sh \
	ovpn.sh \
	ssdp.sh \
	netbios.sh \
	idpcontent.sh \
	bstats.sh \
	phists.sh \
	wg.sh \
	quic.sh \
	nettisa.sh \
	ssadetector.sh \
	vlan.sh \
	reference/basic \
	reference/basicplus \
	reference/pstats \
	reference/ssdp \
	reference/dns \
	reference/dnssd \
	reference/http \
	reference/rtsp \
	reference/tls \
	reference/ntp \
	reference/sip \
	reference/smtp \
	reference/passivedns \
	reference/ovpn \
	reference/idpcontent \
	reference/netbios \
	reference/bstats \
	reference/phists \
	reference/wg \
	reference/quic \
	reference/ssadetector \
	reference/vlan \
	reference/nettisa

clean-local:
	rm -rf output
