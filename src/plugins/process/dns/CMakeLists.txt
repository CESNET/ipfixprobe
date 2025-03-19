project(ipfixprobe-process-dns VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-dns plugin")

add_library(ipfixprobe-process-dns MODULE
    src/dns.cpp
    src/dns.hpp
)

set_target_properties(ipfixprobe-process-dns PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-dns PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

install(TARGETS ipfixprobe-process-dns
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)