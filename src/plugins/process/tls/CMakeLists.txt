project(ipfixprobe-process-tls VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-tls plugin")

add_library(ipfixprobe-process-tls SHARED
    src/tls.cpp
    src/tls.hpp
)

target_include_directories(ipfixprobe-process-tls PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

target_link_libraries(ipfixprobe-process-tls PRIVATE ipfixprobe-process-common)

install(
    TARGETS ipfixprobe-process-tls
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
