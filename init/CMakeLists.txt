install(FILES 
    dpdk_direct.conf.example
    dpdk_mring.conf.example
    link0.conf.example
    DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/ipfixprobe
)

install(FILES 
    ipfixprobe-monitoring.target
    ipfixprobe@.service
    DESTINATION ${INSTALL_UNIT_DIR}
)

install(PROGRAMS ipfixprobed DESTINATION ${CMAKE_INSTALL_BINDIR})
