project(ipfixprobe-process-phists VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-phists plugin")

add_library(ipfixprobe-process-phists MODULE
	src/phists.cpp
	src/phists.hpp
)

set_target_properties(ipfixprobe-process-phists PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-phists PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-process-phists PRIVATE
	ipfixprobe-output-ipfix
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-phists PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
	)
endif()

install(TARGETS ipfixprobe-process-phists
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
