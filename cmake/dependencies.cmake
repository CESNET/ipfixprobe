# Project dependencies
find_package(PkgConfig REQUIRED)

find_package(Threads REQUIRED)
find_package(Atomic REQUIRED)
find_package(Unwind REQUIRED)
find_package(LZ4 REQUIRED)
find_package(OpenSSL REQUIRED)

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
	execute_process(
		COMMAND rpm -q nemea-modules
		RESULT_VARIABLE NEMEA_INSTALLED
		OUTPUT_QUIET ERROR_QUIET
	)
	if (NOT NEMEA_INSTALLED EQUAL 0)
		message(FATAL_ERROR "NEMEA modules package is missing! Install it using: dnf install nemea-modules")
	endif()
endif()
