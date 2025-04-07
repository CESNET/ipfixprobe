install(FILES
	DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/ipfixprobe
)

install(FILES
	ipfixprobe-monitoring.target
	ipfixprobe@.service
	DESTINATION ${INSTALL_UNIT_DIR}
)

install(PROGRAMS ipfixprobed DESTINATION ${CMAKE_INSTALL_BINDIR})
