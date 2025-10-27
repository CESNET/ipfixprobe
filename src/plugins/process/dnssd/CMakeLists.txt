project(ipfixprobe-process-dnssd VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-dnssd plugin")

add_library(ipfixprobe-process-dnssd MODULE
	src/dnssd.cpp
	src/dnssd.hpp
	src/dnssdContext.hpp
	src/dnssdFields.hpp
	src/dnssdRecord.hpp
	src/serviceFilter.cpp
	src/serviceFilter.hpp
)

set_target_properties(ipfixprobe-process-dnssd PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-dnssd PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-dnssd PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-dnssd
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
