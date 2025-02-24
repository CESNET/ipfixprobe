project(ipfixprobe-process-vlan VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-vlan plugin")

add_library(ipfixprobe-process-vlan SHARED
    src/vlan.cpp
    src/vlan.hpp
)

target_include_directories(ipfixprobe-process-vlan PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-vlan PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

install(
    TARGETS ipfixprobe-process-vlan
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
