cmake_minimum_required(VERSION 3.22)

set(VERSION_MAJOR 5)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)
set(VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

project(ipfixprobe VERSION ${VERSION} LANGUAGES CXX C)

include(cmake/build_type.cmake)
include(cmake/installation.cmake)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

option(ENABLE_INPUT_PCAP "Enable build of input PCAP plugin" ON)
option(ENABLE_INPUT_DPDK "Enable build of input DPDK plugin" OFF)
option(ENABLE_INPUT_NFB  "Enable build of input NFB plugin"  OFF)

option(ENABLE_OUTPUT_UNIREC  "Enable build of output UNIREC plugin" OFF)

option(ENABLE_PROCESS_EXPERIMENTAL "Enable build of experimental process plugins" OFF)
option(ENABLE_RPMBUILD "Enable build of RPM package" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -ggdb3")


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -ggdb3")

include(cmake/dependencies.cmake)

add_subdirectory(external)
add_subdirectory(src)
add_subdirectory(pkg)
