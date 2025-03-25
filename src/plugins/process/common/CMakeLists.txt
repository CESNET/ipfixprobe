add_library(ipfixprobe-process-tls-parser STATIC
	tlsParser/tls_parser.hpp
	tlsParser/tls_parser.cpp
)

target_include_directories(ipfixprobe-process-tls-parser PUBLIC
	${CMAKE_SOURCE_DIR}/include
)

set_property(TARGET ipfixprobe-process-tls-parser
	PROPERTY POSITION_INDEPENDENT_CODE ON
)
