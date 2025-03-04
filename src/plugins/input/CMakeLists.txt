add_subdirectory(parser)

if (ENABLE_INPUT_PCAP)
	add_subdirectory(pcap)
endif()
