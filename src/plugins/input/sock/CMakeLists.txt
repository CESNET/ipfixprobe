project(ipfixprobe-input-sock VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-sock plugin")

add_library(ipfixprobe-input-sock MODULE
	src/sock.cpp
	src/sock.hpp
	../parser/parser.cpp
	../parser/parser.hpp
)

set_target_properties(ipfixprobe-input-sock PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)
target_include_directories(ipfixprobe-input-sock PRIVATE
	${SOCK_INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/input/parser
)

target_compile_definitions(ipfixprobe-input-sock PRIVATE
	WITH_SOCK
)

target_link_libraries(ipfixprobe-input-sock PRIVATE
	${SOCK_LIBRARIES}
	telemetry::telemetry
)

install(TARGETS ipfixprobe-input-sock
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
