project(ipfixprobe-process-ntp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ntp plugin")

add_library(ipfixprobe-process-ntp MODULE
	src/ntp.cpp
	src/ntp.hpp
)

set_target_properties(ipfixprobe-process-ntp PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-ntp PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-ntp PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-ntp
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
