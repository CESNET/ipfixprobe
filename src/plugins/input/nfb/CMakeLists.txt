project(ipfixprobe-input-nfb VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-nfb plugin")

add_library(ipfixprobe-input-nfb MODULE
    src/ndp.hpp
    src/ndp.cpp
	src/ndpheader.h
	src/ndpreader.cpp
	src/ndpreader.h
	src/ndpreader.hpp
)

target_include_directories(ipfixprobe-input-nfb PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/input/common
)

target_link_libraries(ipfixprobe-input-nfb PRIVATE ipfixprobe-parser)
target_link_libraries(ipfixprobe-input-nfb PRIVATE nfb::nfb)

install(
    TARGETS ipfixprobe-input-nfb
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
