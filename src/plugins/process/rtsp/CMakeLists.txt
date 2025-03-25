project(ipfixprobe-process-rtsp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-rtsp plugin")

add_library(ipfixprobe-process-rtsp MODULE
	src/rtsp.cpp
	src/rtsp.hpp
)

set_target_properties(ipfixprobe-process-rtsp PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-rtsp PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-rtsp PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
	)
endif()

install(TARGETS ipfixprobe-process-rtsp
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
