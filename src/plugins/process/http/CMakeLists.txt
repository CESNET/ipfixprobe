project(ipfixprobe-process-http VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-http plugin")

add_library(ipfixprobe-process-http MODULE
	src/http.cpp
	src/http.hpp
)

set_target_properties(ipfixprobe-process-http PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-http PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-http PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
	)
endif()

install(TARGETS ipfixprobe-process-http
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
