add_library(ipfixprobe-process-common STATIC
	common.hpp
	dns-utils.hpp
	md5.hpp
	md5.cpp
	tls_parser.hpp
	tls_parser.cpp
)

target_include_directories(ipfixprobe-process-common PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_property(TARGET ipfixprobe-process-common PROPERTY POSITION_INDEPENDENT_CODE ON)