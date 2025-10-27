project(ipfixprobe-process-quic VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-quic plugin")

add_library(ipfixprobe-process-quic MODULE
	src/quic.cpp
	src/quic.hpp
	src/quicParser.cpp
	src/quicParser.hpp
	src/quicConnectionId.hpp
	src/quicContext.hpp
	src/quicFields.hpp
	src/quicHeaderView.hpp
	src/quicHeaderView.cpp
	src/quicInitialHeaderView.hpp
	src/quicInitialHeaderView.cpp
	src/quicInitialSecrets.hpp
	#src/quicPacketType.hpp
	src/quicSalt.hpp
	src/quicTemporalStorage.hpp
	src/quicTypesCumulative.hpp
	src/quicVariableInt.hpp
	src/quicVersion.hpp
)

set_target_properties(ipfixprobe-process-quic PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-quic PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_link_libraries(ipfixprobe-process-quic PRIVATE
	OpenSSL::Crypto
	ipfixprobe-process-tls-parser
	ipfixprobe-output-ipfix
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-quic PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(
	TARGETS ipfixprobe-process-quic
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
