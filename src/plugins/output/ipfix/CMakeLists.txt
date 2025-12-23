project(ipfixprobe-output-ipfix VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-ipfix plugin")

add_library(ipfixprobe-output-ipfix SHARED
	#src/ipfix.hpp
	#src/ipfix.cpp
	#src/ipfix-basiclist.cpp
	src/ipfixElements/ipfixExporterElementsParser.hpp
	src/ipfixElements/ipfixElement.hpp
	src/ipfixBuffers/ipfixBuffer.hpp
	src/ipfixBuffers/ipfixCompressedBuffer.hpp
	src/ipfixBuffers/ipfixMessageHeader.hpp
	src/ipfixBuffers/ipfixSetHeader.hpp
	src/ipfixExporterOptionsParser.hpp
	src/ipfixExporter.hpp
	src/ipfixExporter.cpp
	src/connection.hpp
	src/connection.cpp
	src/utils/byteUtils.hpp
	src/utils/heterogeneousStringHash.hpp
	src/ipfixBasicList.hpp
	src/ipfixRecord.hpp
	src/ipfixRecord.cpp
	src/ipfixTemplate.hpp
	src/ipfixTemplateBuilder.hpp
	src/protocolFieldMap.hpp
)

set_target_properties(ipfixprobe-output-ipfix PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-output-ipfix PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/outputPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_link_libraries(ipfixprobe-output-ipfix PRIVATE
	lz4::lz4
	yaml-cpp::yaml-cpp
)

install(
	TARGETS ipfixprobe-output-ipfix
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
