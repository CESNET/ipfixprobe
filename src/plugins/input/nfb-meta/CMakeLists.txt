project(ipfixprobe-input-nfb-meta VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-nfb-meta plugin ")

add_library(ipfixprobe-input-nfb-meta MODULE
	src/ndpMeta.hpp
	src/ndpMeta.cpp
	../nfb/src/ndpCore.hpp
	../nfb/src/ndpCore.cpp
	../nfb/src/ndpReader.hpp
	../nfb/src/ndpReader.cpp
	../nfb/src/ndpHeader.hpp
	../parser/parser.cpp
	../parser/parser.hpp
)

set_target_properties(ipfixprobe-input-nfb-meta PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-input-nfb-meta PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/input/parser
)

target_link_libraries(ipfixprobe-input-nfb-meta PRIVATE
	nfb::nfb
	numa::numa
	telemetry::telemetry
)

install(TARGETS ipfixprobe-input-nfb-meta
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
