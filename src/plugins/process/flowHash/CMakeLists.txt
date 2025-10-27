project(ipfixprobe-process-flowhash VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-flowhash plugin")

add_library(ipfixprobe-process-flowhash MODULE
	src/flowHash.cpp
	src/flowHash.hpp
	src/flowHashContext.hpp
	src/flowHashFields.hpp
)

set_target_properties(ipfixprobe-process-flowhash PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-flowhash PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-flowhash PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-flowhash
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
