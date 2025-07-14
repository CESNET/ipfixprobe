add_library(top-ports STATIC
	topPorts.cpp
	topPorts.hpp
)

target_include_directories(top-ports PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_BINARY_DIR}/src
)

target_compile_options(top-ports PRIVATE -fPIC)
