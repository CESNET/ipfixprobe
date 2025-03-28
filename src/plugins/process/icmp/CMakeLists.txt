project(ipfixprobe-process-icmp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-icmp plugin")

add_library(ipfixprobe-process-icmp MODULE
	src/icmp.cpp
	src/icmp.hpp
)

set_target_properties(ipfixprobe-process-icmp PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-icmp PRIVATE ${CMAKE_SOURCE_DIR}/include/)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-icmp PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-icmp
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
