project(ipfixprobe-input-dpdk VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-dpdk plugin")

# Použijeme pkg-config pro hledání DPDK
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Knihovna: ipfixprobe-input-dpdk
add_library(ipfixprobe-input-dpdk MODULE
    src/dpdk.cpp
    src/dpdkDevice.cpp
    src/dpdkDevice.hpp
    src/dpdk.h
    src/dpdkMbuf.cpp
    src/dpdkMbuf.hpp
    src/dpdkPortTelemetry.cpp
    src/dpdkPortTelemetry.hpp
    src/dpdkTelemetry.cpp
    src/dpdkTelemetry.hpp
    src/dpdk-ring.cpp
    src/dpdk-ring.h
)

# Přidání include cest
target_include_directories(ipfixprobe-input-dpdk PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(ipfixprobe-input-dpdk PRIVATE ${DPDK_INCLUDE_DIRS})
target_include_directories(ipfixprobe-input-dpdk PRIVATE ${CMAKE_SOURCE_DIR}/src/plugins/input/common)

target_compile_options(ipfixprobe-input-dpdk PRIVATE ${DPDK_CFLAGS_OTHER})

target_link_libraries(ipfixprobe-input-dpdk PRIVATE ${DPDK_LIBRARIES})
message(STATUS "DPDK Libraries: ${DPDK_LIBRARIES}")
install(
    TARGETS ipfixprobe-input-dpdk
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
