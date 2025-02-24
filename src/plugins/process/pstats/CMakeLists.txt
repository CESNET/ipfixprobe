project(ipfixprobe-process-pstats VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-pstats plugin")

add_library(ipfixprobe-process-pstats SHARED
    src/pstats.cpp
    src/pstats.hpp
)

target_include_directories(ipfixprobe-process-pstats PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-process-pstats PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/process/common)

install(
    TARGETS ipfixprobe-process-pstats
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
