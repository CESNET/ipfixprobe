project(ipfixprobe-output-ipfix VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-ipfix plugin")

add_library(ipfixprobe-output-ipfix SHARED
    ipfix.hpp
    ipfix.cpp
	ipfix-basiclist.cpp
)

target_include_directories(ipfixprobe-output-ipfix PRIVATE ${CMAKE_SOURCE_DIR}/include/)

target_link_libraries(ipfixprobe-output-ipfix PRIVATE lz4)

install(
    TARGETS ipfixprobe-output-ipfix
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
