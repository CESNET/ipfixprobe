project(ipfixprobe-process-stats VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-stats plugin")

add_library(ipfixprobe-process-stats SHARED
    src/stats.cpp
    src/stats.hpp
)

target_include_directories(ipfixprobe-process-stats PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-stats
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
