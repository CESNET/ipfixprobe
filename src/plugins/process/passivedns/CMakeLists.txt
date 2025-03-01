project(ipfixprobe-process-passivedns VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-passivedns plugin")

add_library(ipfixprobe-process-passivedns SHARED
    src/passivedns.cpp
    src/passivedns.hpp
)

target_include_directories(ipfixprobe-process-bstats PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-process-passivedns
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
