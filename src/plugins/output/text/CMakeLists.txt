project(ipfixprobe-output-text VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-text plugin")

add_library(ipfixprobe-output-text MODULE
	src/textOutputPlugin.hpp
	src/textOutputPlugin.cpp
)

set_target_properties(ipfixprobe-output-text PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-output-text PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/outputPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

install(
	TARGETS ipfixprobe-output-text
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
