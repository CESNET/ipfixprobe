project(ipfixprobe-process-phists VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-phists plugin")

add_library(ipfixprobe-process-phists SHARED
    src/phists.cpp
    src/phists.hpp
)

target_include_directories(ipfixprobe-process-phists PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-phists PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

install(
    TARGETS ipfixprobe-process-phists
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
