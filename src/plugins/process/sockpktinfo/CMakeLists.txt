project(ipfixprobe-process-sockpktinfo VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-sockpktinfo plugin")

add_library(ipfixprobe-process-sockpktinfo MODULE
	src/sockpktinfo.cpp
	src/sockpktinfo.hpp
)

set_target_properties(ipfixprobe-process-sockpktinfo PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-sockpktinfo PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-sockpktinfo PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-sockpktinfo
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
