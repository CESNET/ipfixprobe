project(ipfixprobe-process-sip VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-sip plugin")

add_library(ipfixprobe-process-sip MODULE
	src/sip.cpp
	src/sip.hpp
)

set_target_properties(ipfixprobe-process-sip PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-sip PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-sip PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
	)
endif()

install(TARGETS ipfixprobe-process-sip
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
