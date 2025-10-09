project(ipfixprobe-input-nfb VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-nfb plugin")

add_library(ipfixprobe-input-nfb MODULE
	src/ndp.hpp
	src/ndp.cpp
	src/ndpHeader.hpp
	src/ndpReader.cpp
	src/ndpReader.hpp
	../parser/parser.cpp
	../parser/parser.hpp
)

set_target_properties(ipfixprobe-input-nfb PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-input-nfb PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/input/parser
	${telemetry_SOURCE_DIR}/include
)

target_link_libraries(ipfixprobe-input-nfb PRIVATE
	nfb::nfb
	numa::numa
)

install(TARGETS ipfixprobe-input-nfb
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
