project(ipfixprobe-process-icmp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-icmp plugin")

add_library(ipfixprobe-process-icmp SHARED
    src/icmp.cpp
    src/icmp.hpp
)

target_include_directories(ipfixprobe-process-icmp PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-icmp
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
