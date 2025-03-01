project(ipfixprobe-process-flowhash VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-flowhash plugin")

add_library(ipfixprobe-process-flowhash SHARED
    src/flow_hash.cpp
    src/flow_hash.hpp
)

target_include_directories(ipfixprobe-process-flowhash PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-flowhash
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
