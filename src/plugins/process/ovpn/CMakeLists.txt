project(ipfixprobe-process-ovpn VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ovpn plugin")

add_library(ipfixprobe-process-ovpn SHARED
    src/ovpn.cpp
    src/ovpn.hpp
)

target_include_directories(ipfixprobe-process-ovpn PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-ovpn PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

install(
    TARGETS ipfixprobe-process-ovpn
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
