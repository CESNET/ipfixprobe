project(ipfixprobe-output-unirec VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-unirec plugin")

add_library(ipfixprobe-output-unirec SHARED
    unirec.cpp
    unirec.hpp
)

target_include_directories(ipfixprobe-output-text PRIVATE ${CMAKE_SOURCE_DIR}/include/)

install(
    TARGETS ipfixprobe-output-text
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
