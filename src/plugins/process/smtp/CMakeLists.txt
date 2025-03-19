project(ipfixprobe-process-smtp VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-smtp plugin")

add_library(ipfixprobe-process-smtp MODULE
    src/smtp.cpp
    src/smtp.hpp
)

set_target_properties(ipfixprobe-process-smtp PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-smtp PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

install(TARGETS ipfixprobe-process-smtp
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)