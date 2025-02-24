project(ipfixprobe-process-ntp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ntp plugin")

add_library(ipfixprobe-process-ntp SHARED
    src/ntp.cpp
    src/ntp.hpp
)

target_include_directories(ipfixprobe-process-ntp PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-ntp
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
