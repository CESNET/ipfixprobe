project(ipfixprobe-process-dns VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-dns plugin")

add_library(ipfixprobe-process-dns MODULE
	src/dns.cpp
	src/dns.hpp
	src/dnsContext.hpp
	src/dnsFields.hpp
	../common/dnsParser/dnsParser.cpp
	../common/dnsParser/dnsParser.hpp
	../common/dnsParser/dnsName.cpp
	../common/dnsParser/dnsName.hpp
	../common/dnsParser/dnsSection.cpp
	../common/dnsParser/dnsSection.hpp
	../common/dnsParser/dnsQuestion.hpp
)

set_target_properties(ipfixprobe-process-dns PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-dns PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-dns PRIVATE
		-Wl,--whole-archive -Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-dns
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
