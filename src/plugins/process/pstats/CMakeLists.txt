project(ipfixprobe-process-pstats VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-pstats plugin")

add_library(ipfixprobe-process-pstats MODULE
	src/pstats.cpp
	src/pstats.hpp
)

set_target_properties(ipfixprobe-process-pstats PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-pstats PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-process-pstats PRIVATE
	ipfixprobe-output-ipfix
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-pstats PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-pstats
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
