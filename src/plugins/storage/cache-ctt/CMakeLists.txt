project(ipfixprobe-storage-cache-ctt VERSION 1.0.0 DESCRIPTION "ipfixprobe-storage-cache-ctt plugin")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

add_library(ipfixprobe-storage-cache-ctt MODULE
	src/cacheCtt.hpp
	src/cacheCtt.cpp
	src/cacheOptParserCtt.hpp
	src/cacheOptParserCtt.cpp
	src/cttController.hpp
	src/cttController.cpp
	src/flowRecordCtt.hpp
	src/flowRecordCtt.cpp
	src/cttRemoveQueue.hpp
	src/cttRemoveQueue.cpp
	../cache/src/cache.hpp
	../cache/src/cache.cpp
	../cache/src/cacheOptParser.hpp
	../cache/src/cacheOptParser.cpp
	../cache/src/cacheRowSpan.hpp
	../cache/src/cacheStats.hpp
	../cache/src/flowKey.hpp
	../cache/src/flowKeyFactory.hpp
	../cache/src/flowRecord.hpp
	../cache/src/flowRecord.cpp
	../cache/src/fragmentationCache/fragmentationCache.cpp
	../cache/src/fragmentationCache/fragmentationCache.hpp
	../cache/src/fragmentationCache/fragmentationKeyData.hpp
	../cache/src/fragmentationCache/fragmentationTable.cpp
	../cache/src/fragmentationCache/fragmentationTable.hpp
	../cache/src/fragmentationCache/ringBuffer.hpp
	../cache/src/fragmentationCache/timevalUtils.hpp
	../cache/src/xxhash.c
	../cache/src/xxhash.h
)

add_compile_definitions(maybe_virtual=virtual)

set_target_properties(ipfixprobe-storage-cache-ctt PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_compile_options(ipfixprobe-storage-cache-ctt PRIVATE
  $<$<CONFIG:Release>: -O4 -flto=auto -fwhole-program>
)

target_include_directories(ipfixprobe-storage-cache-ctt PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-storage-cache-ctt PRIVATE
	telemetry::telemetry
	telemetry::appFs
	ctt
	feta
)

install(TARGETS ipfixprobe-storage-cache-ctt
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/storage/"
)

set(LIB_CTT_KEY_SIZE "0" CACHE STRING "Set the custom size value for cttctl")
set(LIB_CTT_STATE_SIZE "0" CACHE STRING "Set the custom size value for cttctl")
set(LIB_CTT_STATE_MASK_SIZE "0" CACHE STRING "Set the custom size value for cttctl")

add_definitions(
	-DLIB_CTT_VERSION_MAJOR=${VERSION_MAJOR}
	-DLIB_CTT_VERSION_MINOR=${VERSION_MINOR}
	-DLIB_CTT_KEY_SIZE=${LIB_CTT_KEY_SIZE}
	-DLIB_CTT_STATE_SIZE=${LIB_CTT_STATE_SIZE}
	-DLIB_CTT_STATE_MASK_SIZE=${LIB_CTT_STATE_MASK_SIZE}
)

