project(ipfixprobe-process-osquery VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-osquery plugin")

add_library(ipfixprobe-process-osquery SHARED
    src/osquery.cpp
    src/osquery.hpp
)

target_include_directories(ipfixprobe-process-osquery PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-osquery
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
