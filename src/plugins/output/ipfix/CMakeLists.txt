project(ipfixprobe-output-ipfix VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-ipfix plugin")

add_library(ipfixprobe-output-ipfix SHARED
	src/ipfix.hpp
	src/ipfix.cpp
	src/ipfix-basiclist.cpp
)

set_target_properties(ipfixprobe-output-ipfix PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-output-ipfix PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-output-ipfix PRIVATE
	lz4::lz4
)

install(
	TARGETS ipfixprobe-output-ipfix
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
