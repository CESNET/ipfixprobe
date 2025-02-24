project(ipfixprobe-process-mpls VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-mpls plugin")

add_library(ipfixprobe-process-mpls SHARED
    src/mpls.cpp
    src/mpls.hpp
)

target_include_directories(ipfixprobe-process-mpls PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-mpls PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

install(
    TARGETS ipfixprobe-process-mpls
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
