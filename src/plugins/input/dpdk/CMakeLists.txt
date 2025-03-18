project(ipfixprobe-input-dpdk VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-dpdk plugin")

add_library(ipfixprobe-input-dpdk MODULE
    src/dpdk.cpp
    src/dpdkDevice.cpp
    src/dpdkDevice.hpp
    src/dpdk.hpp
    src/dpdkMbuf.cpp
    src/dpdkMbuf.hpp
    src/dpdkPortTelemetry.cpp
    src/dpdkPortTelemetry.hpp
    src/dpdkTelemetry.cpp
    src/dpdkTelemetry.hpp
    src/dpdk-ring.cpp
    src/dpdk-ring.hpp
)

set_target_properties(ipfixprobe-input-dpdk PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-input-dpdk PRIVATE 
	${DPDK_INCLUDE_DIRS}
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/input/parser
)

target_compile_options(ipfixprobe-input-dpdk PRIVATE ${DPDK_CFLAGS_OTHER})
target_compile_options(ipfixprobe-input-dpdk PRIVATE -Wno-volatile -Wno-pedantic)

target_link_libraries(ipfixprobe-input-dpdk PRIVATE
	ipfixprobe-parser
	${DPDK_LIBRARIES}
)

install(TARGETS ipfixprobe-input-dpdk
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)