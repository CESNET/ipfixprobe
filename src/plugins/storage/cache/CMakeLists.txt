project(ipfixprobe-storage-cache VERSION 1.0.0 DESCRIPTION "ipfixprobe-storage-cache plugin")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

add_library(ipfixprobe-storage-cache MODULE
	src/cache.hpp
	src/cache.cpp
	src/cacheOptParser.hpp
	src/cacheOptParser.cpp
	src/cacheRowSpan.hpp
	src/cacheStats.hpp
	src/flowKey.hpp
	src/flowKeyFactory.hpp
	src/flowRecord.hpp
	src/flowRecord.cpp
	src/fragmentationCache/fragmentationCache.cpp
	src/fragmentationCache/fragmentationCache.hpp
	src/fragmentationCache/fragmentationKeyData.hpp
	src/fragmentationCache/fragmentationTable.cpp
	src/fragmentationCache/fragmentationTable.hpp
	src/fragmentationCache/ringBuffer.hpp
	src/fragmentationCache/timevalUtils.hpp
	src/xxhash.c
	src/xxhash.h
)

add_compile_definitions(maybe_virtual=) # No need for virtual functions if ctt cache is not being compiled

set_target_properties(ipfixprobe-storage-cache PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_compile_options(ipfixprobe-storage-cache PRIVATE
  $<$<CONFIG:Release>: -O4 -flto=auto -fopt-info-optimized -fopt-info-inline>
)

target_include_directories(ipfixprobe-storage-cache PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-storage-cache PRIVATE
	telemetry::telemetry
	telemetry::appFs
)

install(TARGETS ipfixprobe-storage-cache
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/storage/"
)
