add_library(ipfixprobe-core STATIC
	ipfixprobe.cpp
	ipfixprobe.hpp
	options.cpp
	pluginmgr.cpp
	pluginmgr.hpp
	ring.c
	stacktrace.cpp
	stacktrace.hpp
	stats.cpp
	stats.hpp
	utils.cpp
	workers.cpp
	workers.hpp
	input.cpp
)


target_include_directories(ipfixprobe-core PUBLIC 
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_BINARY_DIR}/src
)

target_compile_options(ipfixprobe-core PRIVATE -fPIC)

set(CORE_LIB -Wl,--whole-archive ipfixprobe-core -Wl,--no-whole-archive)

target_link_libraries(ipfixprobe-core 
	pthread
	telemetry::telemetry
	telemetry::appFs
	atomic::atomic
	unwind::unwind
	${CMAKE_DL_LIBS}
)

add_executable(ipfixprobe main.cpp)
target_link_libraries(ipfixprobe ${CORE_LIB})
target_link_options(ipfixprobe PRIVATE -Wl,--export-dynamic)

set_target_properties(
    ipfixprobe PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

install(TARGETS ipfixprobe DESTINATION "${INSTALL_DIR_BIN}")
