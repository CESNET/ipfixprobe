add_library(ipfixprobe-core STATIC
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
	fieldManager.cpp
	xxhash.c
	outputConfigurationParser/outputConfigurationParser.cpp
	outputConfigurationParser/outputAction.cpp
	outputConfigurationParser/fieldMap.hpp
)

target_include_directories(ipfixprobe-core PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/outputPlugin
	${CMAKE_BINARY_DIR}/src
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_compile_options(ipfixprobe-core PRIVATE -fPIC)

#add_library(ipfixprobe-plugin-factory STATIC
#	pluginFactory.cpp
#)

#target_include_directories(ipfixprobe-plugin-factory PUBLIC
#	${CMAKE_SOURCE_DIR}/include
#)

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
