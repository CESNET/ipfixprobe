project(ipfixprobe-process-ovpn VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-ovpn plugin")

add_library(ipfixprobe-process-ovpn MODULE
	src/openvpn.cpp
	src/openvpn.hpp
	src/openvpnContext.hpp
	src/openvpnFields.hpp
	src/openvpnOpcode.hpp
	src/openvpnProcessingState.hpp
	src/openvpnProcessingState.cpp
	src/rtpHeader.hpp
)

set_target_properties(ipfixprobe-process-ovpn PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-ovpn PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-ovpn PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-ovpn
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
