project(ipfixprobe-process-osquery VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-osquery plugin")

add_library(ipfixprobe-process-osquery MODULE
	src/osquery.cpp
	src/osquery.hpp
	src/osqueryContext.hpp
	src/osqueryFields.hpp
	src/osqueryRequestManager.hpp
	src/osqueryRequestManager.cpp
	src/fileDescriptor.hpp
	src/fileDescriptor.cpp
	src/osqueryStateHandler.hpp
	src/process.cpp
	src/process.hpp
)

set_target_properties(ipfixprobe-process-osquery PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-osquery PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-osquery PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-osquery
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
