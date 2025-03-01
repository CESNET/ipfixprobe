project(ipfixprobe-process-sip VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-sip plugin")

add_library(ipfixprobe-process-sip SHARED
    src/sip.cpp
    src/sip.hpp
)

target_include_directories(ipfixprobe-process-sip PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-sip
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
