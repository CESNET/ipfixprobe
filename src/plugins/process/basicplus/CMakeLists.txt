project(ipfixprobe-process-basicplus VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-basicplus plugin")

add_library(ipfixprobe-process-basicplus SHARED
    src/basicplus.cpp
    src/basicplus.hpp
)

target_include_directories(ipfixprobe-process-basicplus PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-basicplus
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
