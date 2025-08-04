add_subdirectory(raw)
add_subdirectory(parser)

if (ENABLE_INPUT_PCAP)
	add_subdirectory(pcap)
endif()

if (ENABLE_INPUT_DPDK)
	add_subdirectory(dpdk)
endif()

if (ENABLE_INPUT_NFB)
	add_subdirectory(nfb)
endif()
