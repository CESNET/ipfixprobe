project(ipfixprobe-process-idpcontent VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-idpcontent plugin")

add_library(ipfixprobe-process-idpcontent MODULE
    src/idpcontent.cpp
    src/idpcontent.hpp
)

set_target_properties(ipfixprobe-process-idpcontent PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-idpcontent PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

install(TARGETS ipfixprobe-process-idpcontent
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)