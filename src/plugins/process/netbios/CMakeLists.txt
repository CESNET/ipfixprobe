project(ipfixprobe-process-netbios VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-netbios plugin")

add_library(ipfixprobe-process-netbios SHARED
    src/netbios.cpp
    src/netbios.hpp
)

target_include_directories(ipfixprobe-process-netbios PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-netbios PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

install(
    TARGETS ipfixprobe-process-netbios
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
