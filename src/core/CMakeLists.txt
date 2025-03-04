add_executable(ipfixprobe 
	main.cpp
	ipfixprobe.cpp
	ipfixprobe.hpp
	options.cpp
	ring.c
	stacktrace.cpp
	stacktrace.hpp
	stats.cpp
	stats.hpp
	utils.cpp
	workers.cpp
	workers.hpp
	inputPlugin.cpp
	pluginManager.cpp
	pluginManager.hpp
)


target_include_directories(ipfixprobe PUBLIC 
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_BINARY_DIR}/src
)

target_link_options(ipfixprobe PRIVATE -Wl,--export-dynamic)

set_target_properties(
    ipfixprobe PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_link_libraries(ipfixprobe PRIVATE 
	pthread
	telemetry::telemetry
	telemetry::appFs
	atomic::atomic
	unwind::unwind
	${CMAKE_DL_LIBS}
)

install(TARGETS ipfixprobe DESTINATION "${INSTALL_DIR_BIN}")
