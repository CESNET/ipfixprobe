project(ipfixprobe-process-ssdp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ssdp plugin")

add_library(ipfixprobe-process-ssdp SHARED
    src/ssdp.cpp
    src/ssdp.hpp
)

target_include_directories(ipfixprobe-process-ssdp PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-ssdp
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
