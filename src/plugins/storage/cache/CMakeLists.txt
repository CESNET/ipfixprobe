project(ipfixprobe-storage-cache VERSION 1.0.0 DESCRIPTION "ipfixprobe-storage-cache plugin")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

find_package(xxhash REQUIRED)

add_library(ipfixprobe-storage-cache SHARED
    src/cache.hpp
    src/cache.cpp
	src/fragmentationCache/fragmentationCache.cpp
	src/fragmentationCache/fragmentationCache.hpp
	src/fragmentationCache/fragmentationKeyData.hpp
	src/fragmentationCache/fragmentationTable.cpp
	src/fragmentationCache/fragmentationTable.hpp
	src/fragmentationCache/ringBuffer.hpp
	src/fragmentationCache/timevalUtils.hpp
)

target_include_directories(ipfixprobe-storage-cache PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_link_libraries(ipfixprobe-storage-cache PRIVATE xxhash::xxhash)

install(
    TARGETS ipfixprobe-storage-cache
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/storage/"
)
