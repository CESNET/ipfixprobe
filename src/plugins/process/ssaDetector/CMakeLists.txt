project(ipfixprobe-process-ssadetector VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ssadetector plugin")

add_library(ipfixprobe-process-ssadetector MODULE
	src/ssaDetector.cpp
	src/ssaDetector.hpp
	src/ssaDetectorContext.hpp
	src/ssaDetectorFields.hpp
	src/packetStorage.hpp
)

set_target_properties(ipfixprobe-process-ssadetector PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-ssadetector PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-ssadetector PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-ssadetector
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
