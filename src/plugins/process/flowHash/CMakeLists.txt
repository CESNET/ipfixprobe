project(ipfixprobe-process-flowhash VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-flowhash plugin")

add_library(ipfixprobe-process-flowhash MODULE
    src/flow_hash.cpp
    src/flow_hash.hpp
)

set_target_properties(ipfixprobe-process-flowhash PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-flowhash PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

install(TARGETS ipfixprobe-process-flowhash
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)