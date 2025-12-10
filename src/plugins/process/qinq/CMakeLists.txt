project(ipfixprobe-process-qinq VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-qinq plugin")

add_library(ipfixprobe-process-qinq MODULE
	src/qinq.cpp
	src/qinq.hpp
)

set_target_properties(ipfixprobe-process-qinq PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-qinq PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-qinq PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-qinq
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
