project(ipfixprobe-process-ssdp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ssdp plugin")

add_library(ipfixprobe-process-ssdp MODULE
	src/ssdp.cpp
	src/ssdp.hpp
	src/ssdpContext.hpp
	src/ssdpFields.hpp
)

set_target_properties(ipfixprobe-process-ssdp PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-ssdp PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-ssdp PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-ssdp
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
