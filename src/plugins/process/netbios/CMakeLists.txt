project(ipfixprobe-process-netbios VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-netbios plugin")

add_library(ipfixprobe-process-netbios MODULE
	src/netbios.cpp
	src/netbios.hpp
)

set_target_properties(ipfixprobe-process-netbios PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-netbios PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-netbios PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-netbios
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
