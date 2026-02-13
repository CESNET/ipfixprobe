project(ipfixprobe-storage-cache VERSION 1.0.0 DESCRIPTION "ipfixprobe-storage-cache plugin")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

add_library(ipfixprobe-storage-cache MODULE
	src/cache.hpp
	src/cache.cpp
	src/fragmentationCache/fragmentationCache.cpp
	src/fragmentationCache/fragmentationCache.hpp
	src/fragmentationCache/fragmentationKeyData.hpp
	src/fragmentationCache/fragmentationTable.cpp
	src/fragmentationCache/fragmentationTable.hpp
	src/fragmentationCache/ringBuffer.hpp
	src/fragmentationCache/timevalUtils.hpp
	src/sourceOptimization.cpp
	src/sourceOptimization.hpp
	src/xxhash.c
	src/xxhash.h
)

set_target_properties(ipfixprobe-storage-cache PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-storage-cache PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${telemetry_SOURCE_DIR}/include
)

install(TARGETS ipfixprobe-storage-cache
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/storage/"
)
