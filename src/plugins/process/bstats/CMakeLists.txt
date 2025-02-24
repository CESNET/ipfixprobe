project(ipfixprobe-process-bstats VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-bstats plugin")

add_library(ipfixprobe-process-bstats SHARED
    src/bstats.cpp
    src/bstats.hpp
)

target_include_directories(ipfixprobe-process-bstats PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-bstats
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
