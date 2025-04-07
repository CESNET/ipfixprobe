install(FILES
	DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/ipfixprobe
)

install(FILES
	ipfixprobe-monitoring.target
	ipfixprobe@.service
	DESTINATION ${INSTALL_UNIT_DIR}
)

install(PROGRAMS ipfixprobed DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES schema.json DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/")
install(PROGRAMS config2args.py DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/")
