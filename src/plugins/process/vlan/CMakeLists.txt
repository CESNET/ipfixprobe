project(ipfixprobe-process-vlan VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-vlan plugin")

add_library(ipfixprobe-process-vlan MODULE
	src/vlan.cpp
	src/vlan.hpp
)

set_target_properties(ipfixprobe-process-vlan PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-vlan PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-vlan PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-vlan
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
