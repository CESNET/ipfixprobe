project(ipfixprobe-process-mqtt VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-mqtt plugin")

add_library(ipfixprobe-process-mqtt MODULE
    src/mqtt.cpp
    src/mqtt.hpp
)

set_target_properties(ipfixprobe-process-mqtt PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-mqtt PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
)

install(TARGETS ipfixprobe-process-mqtt
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
