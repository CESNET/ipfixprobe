project(ipfixprobe-process-http VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-http plugin")

add_library(ipfixprobe-process-http MODULE
    src/http.cpp
    src/http.hpp
)

set_target_properties(ipfixprobe-process-http PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-http PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

install(TARGETS ipfixprobe-process-http
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)