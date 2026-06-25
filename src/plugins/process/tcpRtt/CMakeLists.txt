project(ipfixprobe-process-tcp-rtt VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-tcp-rtt plugin")

add_library(ipfixprobe-process-tcp-rtt MODULE
	src/tcpRtt.cpp
	src/tcpRtt.hpp
)

set_target_properties(ipfixprobe-process-tcp-rtt PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-tcp-rtt PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-process-tcp-rtt PRIVATE
	ipfixprobe-output-ipfix
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-tcp-rtt PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-tcp-rtt
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
