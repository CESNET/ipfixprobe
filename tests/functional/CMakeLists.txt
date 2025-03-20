file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tests/functional/results)

macro(add_process_plugin_test test_name plugin_name pcap_file)
    add_test(
        NAME ${test_name}
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_test.sh ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${plugin_name} ${pcap_file}
    )
endmacro()

add_process_plugin_test(BasicProcessPlugin basic mixed.pcap)
add_process_plugin_test(BasicPlusProcessPlugin basicplus http.pcap)
add_process_plugin_test(BstatsProcessPlugin bstats bstats.pcap)
add_process_plugin_test(DnsProcessPlugin dns dns.pcap)
add_process_plugin_test(DnssdProcessPlugin dnssd dnssd.pcap)
add_process_plugin_test(HttpProcessPlugin http http.pcap)
add_process_plugin_test(IdpcontentProcessPlugin idpcontent idpcontent.pcap)
add_process_plugin_test(MqttProcessPlugin mqtt mqtt.pcap)
add_process_plugin_test(NetbiosProcessPlugin netbios netbios.pcap)
add_process_plugin_test(NettisaProcessPlugin nettisa mixed.pcap)
add_process_plugin_test(NtpProcessPlugin ntp ntp.pcap)
add_process_plugin_test(OvpnProcessPlugin ovpn ovpn.pcap)
add_process_plugin_test(PassivednsProcessPlugin passivedns dns.pcap)
add_process_plugin_test(PhistsProcessPlugin phists mixed.pcap)
add_process_plugin_test(PstatsProcessPlugin pstats mixed.pcap)
add_process_plugin_test(QuicProcessPlugin quic quic_initial-sample.pcap.pcap)
add_process_plugin_test(RtspProcessPlugin rtsp rtsp.pcap)
add_process_plugin_test(SipProcessPlugin sip sip.pcap)
add_process_plugin_test(SmtpProcessPlugin smtp smtp.pcap)
add_process_plugin_test(SsadetectorProcessPlugin ssadetector ovpn.pcap)
add_process_plugin_test(SsdpProcessPlugin ssdp ssdp.pcap)
add_process_plugin_test(TlsProcessPlugin tls tls.pcap)
add_process_plugin_test(VlanProcessPlugin vlan vlan.pcap)
add_process_plugin_test(WgProcessPlugin wg wg.pcap)


add_custom_target(tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}  # 📌 Testy spouštíme z build dir
)
