project(ipfixprobe-process-basicplus VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-basicplus plugin")

add_library(ipfixprobe-process-basicplus MODULE
	src/basicplus.cpp
	src/basicplus.hpp
)

set_target_properties(ipfixprobe-process-basicplus PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_link_libraries(ipfixprobe-process-basicplus PRIVATE
	ipfixprobe-output-ipfix
)

target_include_directories(ipfixprobe-process-basicplus PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-basicplus PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
	)
endif()

install(TARGETS ipfixprobe-process-basicplus
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
