# Project dependencies
find_package(PkgConfig REQUIRED)

find_package(Threads REQUIRED)
find_package(Atomic REQUIRED)
find_package(Unwind REQUIRED)
find_package(LZ4 REQUIRED)

if (ENABLE_INPUT_PCAP)
	pkg_check_modules(PCAP REQUIRED libpcap)
endif()
	
if (ENABLE_INPUT_DPDK)
	pkg_check_modules(DPDK REQUIRED libdpdk)
endif()

if (ENABLE_INPUT_NFB)
	find_package(NFB REQUIRED)
	find_package(NUMA REQUIRED)
endif()

if (ENABLE_OUTPUT_UNIREC OR ENABLE_NEMEA)
	find_package(LIBTRAP REQUIRED)
	find_package(UNIREC REQUIRED)
endif()

if (ENABLE_TESTS)
	#find_package(NEMEA_MODULES REQUIRED) // TODO: NEMEA_MODULES
endif()
