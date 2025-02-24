add_executable(ipfixprobe 
	main.cpp
	ipfixprobe.cpp
	ipfixprobe1.hpp
	options.cpp
	pluginmgr.cpp
	pluginmgr.hpp
	ring.c
	stacktrace.cpp
	stacktrace.hpp
	stats.cpp
	stats.hpp
	utils.cpp
	workers.cpp
	workers.hpp
	input.cpp
	logger.cpp
)

target_compile_definitions(ipfixprobe PUBLIC FUSE_USE_VERSION=30 _FILE_OFFSET_BITS=64)
target_include_directories(ipfixprobe PUBLIC ${CMAKE_SOURCE_DIR}/include)


target_link_options(ipfixprobe PRIVATE -Wl,--export-dynamic)
set_target_properties(
    ipfixprobe PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_link_libraries(ipfixprobe PRIVATE 
	telemetry::telemetry
	telemetry::appFs
	spdlog::spdlog
	pthread
	atomic
	unwind
	#ipfixprobe-storage-cache
	#ipfixprobe-process-basicplus
	#ipfixprobe-process-bstats
	#ipfixprobe-process-http
	#ipfixprobe-process-icmp
	#ipfixprobe-process-pstats
	#ipfixprobe-process-mpls
	#ipfixprobe-process-nettisa
	#ipfixprobe-process-phists
	#ipfixprobe-process-ovpn
	#ipfixprobe-process-ntp
	#ipfixprobe-process-vlan
	#ipfixprobe-process-osquery
	#ipfixprobe-process-netbios
	#ipfixprobe-process-tls
	#ipfixprobe-process-wg
	#ipfixprobe-process-rtsp
	#ipfixprobe-process-smtp
	#ipfixprobe-process-quic
	ipfixprobe-output-ipfix
	#ipfixprobe-output-text
	${CMAKE_DL_LIBS}
)


install(TARGETS ipfixprobe DESTINATION "${INSTALL_DIR_BIN}")