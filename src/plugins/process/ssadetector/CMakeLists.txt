project(ipfixprobe-process-ssadetector VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ssadetector plugin")

add_library(ipfixprobe-process-ssadetector SHARED
    src/ssadetector.cpp
    src/ssadetector.hpp
)

target_include_directories(ipfixprobe-process-ssadetector PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-ssadetector
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
