project(ipfixprobe-process-nettisa VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-nettisa plugin")

add_library(ipfixprobe-process-nettisa SHARED
    src/nettisa.cpp
    src/nettisa.hpp
)

target_include_directories(ipfixprobe-process-nettisa PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

target_link_libraries(ipfixprobe-process-nettisa PRIVATE ipfixprobe-process-common)

install(
    TARGETS ipfixprobe-process-nettisa
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
