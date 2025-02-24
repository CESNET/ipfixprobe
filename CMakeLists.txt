cmake_minimum_required(VERSION 3.12)

set(VERSION_MAJOR 5)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)
set(VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

project(ipfixprobe VERSION ${VERSION})

include(cmake/build_type.cmake)
include(cmake/installation.cmake)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

#option(ENABLE_INPUT_PCAP "Enable Input PCAP plugin" ON)
#option(ENABLE_INPUT_NFB  "Enable Input NFB plugin"  ON)
#option(ENABLE_INPUT_DPDK "Enable Input DPDK plugin" ON)
#option(ENABLE_INPUT_RAW  "Enable Input RAW plugin"  ON)

#option(ENABLE_OUTPUT_IPFIX  "Enable Output IPFIX plugin"  ON)
#option(ENABLE_OUTPUT_TEXT   "Enable Output TEXT plugin"   ON)
#option(ENABLE_OUTPUT_UNIREC "Enable Output UNIREC plugin" ON)


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


option(ENABLE_RPMBUILD "Enable support for building RPM packages" ON)

option(ENABLE_INPUT_PCAP "Enable build of input PCAP plugin" ON)
option(ENABLE_INPUT_DPDK "Enable build of input DPDK plugin" ON)
option(ENABLE_INPUT_NFB  "Enable build of input NFB plugin"  ON)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -g -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -ggdb3")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g -O3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -ggdb3")

if(CMAKE_EXPORT_COMPILE_COMMANDS)
	set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

include(cmake/dependencies.cmake)

add_subdirectory(external)
add_subdirectory(src)
add_subdirectory(pkg)
