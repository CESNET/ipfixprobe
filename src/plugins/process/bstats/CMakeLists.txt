project(ipfixprobe-process-bstats VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-bstats plugin")

add_library(ipfixprobe-process-bstats MODULE
    src/bstats.cpp
    src/bstats.hpp
)

set_target_properties(ipfixprobe-process-bstats PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-bstats PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-process-bstats PRIVATE 
    ipfixprobe-output-ipfix
)

install(TARGETS ipfixprobe-process-bstats
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)