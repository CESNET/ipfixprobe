project(ipfixprobe-process-quic VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-quic plugin")

add_library(ipfixprobe-process-quic SHARED
    src/quic.cpp
    src/quic.hpp
	src/quic_parser.cpp
    src/quic_parser.hpp
)

target_include_directories(ipfixprobe-process-quic PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-quic PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

target_link_libraries(ipfixprobe-process-quic PRIVATE 
	crypto
	ipfixprobe-process-common
)

install(
    TARGETS ipfixprobe-process-quic
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
