project(ipfixprobe-process-bstats VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-bstats plugin")

add_library(ipfixprobe-process-bstats MODULE
	src/burstStats.cpp
	src/burstStats.hpp
	src/burstStatsContext.hpp
	src/burstStatsFields.hpp
	src/burst.hpp	
)

set_target_properties(ipfixprobe-process-bstats PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-bstats PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_link_libraries(ipfixprobe-process-bstats PRIVATE
	ipfixprobe-core
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-bstats PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-bstats
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
