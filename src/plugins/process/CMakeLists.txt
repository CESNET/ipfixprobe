add_subdirectory(common)
add_subdirectory(basicplus)
add_subdirectory(bstats)
add_subdirectory(icmp)
add_subdirectory(vlan)
add_subdirectory(flowHash)
add_subdirectory(osquery)
add_subdirectory(idpContent)
add_subdirectory(phists)
add_subdirectory(pstats)
add_subdirectory(ovpn)
add_subdirectory(wg)
add_subdirectory(ssdp)
add_subdirectory(ssaDetector)
add_subdirectory(mqtt)
add_subdirectory(dns)
add_subdirectory(dnssd)
add_subdirectory(netbios)
add_subdirectory(passiveDns)
add_subdirectory(smtp)
add_subdirectory(quic)
add_subdirectory(tls)
add_subdirectory(http)

if (ENABLE_PROCESS_EXPERIMENTAL)
	add_subdirectory(sip)
	add_subdirectory(rtsp)
	add_subdirectory(mpls)
	add_subdirectory(ntp)
	add_subdirectory(nettisa)
endif()
