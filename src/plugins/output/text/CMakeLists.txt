project(ipfixprobe-output-text VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-text plugin")

add_library(ipfixprobe-output-text SHARED
    text.hpp
    text.cpp
)

target_include_directories(ipfixprobe-output-text PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-output-text
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
