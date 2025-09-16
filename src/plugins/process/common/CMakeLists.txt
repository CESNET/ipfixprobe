add_library(ipfixprobe-process-tls-parser STATIC
	tlsParser/tlsParser.hpp
	tlsParser/tlsParser.cpp
)

target_include_directories(ipfixprobe-process-tls-parser PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${Boost_INCLUDE_DIRS}
)

target_link_libraries(ipfixprobe-process-tls-parser PRIVATE ${Boost_LIBRARIES})


set_property(TARGET ipfixprobe-process-tls-parser
	PROPERTY POSITION_INDEPENDENT_CODE ON
)
