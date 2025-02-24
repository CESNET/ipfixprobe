project(ipfixprobe-process-wg VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-wg plugin")

add_library(ipfixprobe-process-wg SHARED
    src/wg.cpp
    src/wg.hpp
)

target_include_directories(ipfixprobe-process-wg PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-wg
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
