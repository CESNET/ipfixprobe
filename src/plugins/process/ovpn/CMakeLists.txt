project(ipfixprobe-process-ovpn VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ovpn plugin")

add_library(ipfixprobe-process-ovpn MODULE
	src/ovpn.cpp
	src/ovpn.hpp
)

set_target_properties(ipfixprobe-process-ovpn PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-ovpn PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-ovpn PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
	)
endif()

install(TARGETS ipfixprobe-process-ovpn
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
