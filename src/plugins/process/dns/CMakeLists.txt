project(ipfixprobe-process-dns VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-dns plugin")

add_library(ipfixprobe-process-dns SHARED
    src/dns.cpp
    src/dns.hpp
)

target_include_directories(ipfixprobe-process-dns PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

install(
    TARGETS ipfixprobe-process-dns
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
