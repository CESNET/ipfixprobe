project(ipfixprobe-process-quic VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-quic plugin")

add_library(ipfixprobe-process-quic MODULE
    src/quic.cpp
    src/quic.hpp
	src/quic_parser.cpp
    src/quic_parser.hpp
)

set_target_properties(ipfixprobe-process-quic PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-quic PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

target_link_libraries(ipfixprobe-process-quic PRIVATE 
	OpenSSL::Crypto
	ipfixprobe-process-tls-parser
    ipfixprobe-output-ipfix
)

install(
    TARGETS ipfixprobe-process-quic
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)