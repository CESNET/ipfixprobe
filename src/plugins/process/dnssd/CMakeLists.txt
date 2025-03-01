project(ipfixprobe-process-dnssd VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-dnssd plugin")

add_library(ipfixprobe-process-dnssd SHARED
    src/dnssd.cpp
    src/dnssd.hpp
)

target_include_directories(ipfixprobe-process-dnssd PRIVATE 
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

install(
    TARGETS ipfixprobe-process-dnssd
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
