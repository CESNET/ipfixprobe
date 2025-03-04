project(ipfixprobe-input-raw VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-raw plugin")

add_library(ipfixprobe-input-raw MODULE
    src/raw.cpp
    src/raw.hpp
    ../parser/parser.cpp
    ../parser/parser.hpp
)

set_target_properties(ipfixprobe-input-raw PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-input-raw PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/input/parser
)

target_link_libraries(ipfixprobe-input-raw PRIVATE 
    telemetry::telemetry
)

install(TARGETS ipfixprobe-input-raw
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
