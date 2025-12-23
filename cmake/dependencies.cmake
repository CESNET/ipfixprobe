# Project dependencies
find_package(PkgConfig REQUIRED)
include(FetchContent)

find_package(Threads REQUIRED)
find_package(Atomic REQUIRED)
find_package(Unwind REQUIRED)
find_package(LZ4 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

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

if (ENABLE_OUTPUT_IPFIX)
	find_package(yaml-cpp REQUIRED)
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

	FetchContent_Declare(
		googletest
 		URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
		DOWNLOAD_EXTRACT_TIMESTAMP TRUE
	)
	FetchContent_MakeAvailable(googletest)
endif()
