add_subdirectory(core)
add_subdirectory(plugins)

configure_file(
	${CMAKE_SOURCE_DIR}/src/buildConfig.hpp.in
	${CMAKE_BINARY_DIR}/src/buildConfig.hpp
)
