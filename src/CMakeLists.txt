add_subdirectory(core)

configure_file(
	${CMAKE_SOURCE_DIR}/src/buildConfig.hpp.in
	${CMAKE_BINARY_DIR}/src/buildConfig.hpp
)
