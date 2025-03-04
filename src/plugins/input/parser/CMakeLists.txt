add_library(ipfixprobe-parser STATIC
    parser.hpp
    parser.cpp
	headers.hpp
)

target_include_directories(ipfixprobe-parser PUBLIC ${CMAKE_SOURCE_DIR}/include)

set_property(TARGET ipfixprobe-parser PROPERTY POSITION_INDEPENDENT_CODE ON)
