project(ipfixprobe-process-mpls VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-mpls plugin")

add_library(ipfixprobe-process-mpls MODULE
	src/mpls.cpp
	src/mpls.hpp
)

set_target_properties(ipfixprobe-process-mpls PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-mpls PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-mpls PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-mpls
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
