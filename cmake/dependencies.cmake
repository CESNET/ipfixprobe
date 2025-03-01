find_package(PkgConfig REQUIRED)

find_package(unwind REQUIRED)
find_package(atomic REQUIRED)
find_package(lz4 REQUIRED)

find_package(Threads REQUIRED)
if(NOT CMAKE_USE_PTHREADS_INIT)
  message(FATAL_ERROR "pthreads not found!")
endif()

if (ENABLE_INPUT_PCAP)
	pkg_check_modules(PCAP REQUIRED libpcap)
endif()

if (ENABLE_INPUT_DPDK)
	pkg_check_modules(DPDK REQUIRED libdpdk)
endif()

if (ENABLE_INPUT_NFB)
	find_package(NFB REQUIRED)
endif()

if (ENABLE_OUTPUT_UNIREC)
	find_package(Nemea REQUIRED)
endif()
