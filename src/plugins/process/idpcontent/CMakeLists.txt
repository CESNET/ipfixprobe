project(ipfixprobe-process-idpcontent VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-idpcontent plugin")

add_library(ipfixprobe-process-idpcontent SHARED
    src/idpcontent.cpp
    src/idpcontent.hpp
)

target_include_directories(ipfixprobe-process-idpcontent PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-idpcontent
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
