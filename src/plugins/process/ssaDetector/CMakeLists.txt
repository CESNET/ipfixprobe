project(ipfixprobe-process-ssadetector VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ssadetector plugin")

add_library(ipfixprobe-process-ssadetector MODULE
    src/ssadetector.cpp
    src/ssadetector.hpp
)

set_target_properties(ipfixprobe-process-ssadetector PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-ssadetector PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
)

install(TARGETS ipfixprobe-process-ssadetector
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)