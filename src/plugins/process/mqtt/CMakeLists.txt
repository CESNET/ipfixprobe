project(ipfixprobe-process-mqtt VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-mqtt plugin")

add_library(ipfixprobe-process-mqtt MODULE
	src/mqtt.cpp
	src/mqtt.hpp
	src/mqttContext.hpp
	src/mqttFields.hpp
	src/mqttHeaderType.hpp
	src/mqttTypeFlag.hpp
	src/variableLengthInt.hpp
)

set_target_properties(ipfixprobe-process-mqtt PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-mqtt PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/pluginFactory
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

if(ENABLE_NEMEA)
	target_link_libraries(ipfixprobe-process-mqtt PRIVATE
		-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
		unirec::unirec
		trap::trap
	)
endif()

install(TARGETS ipfixprobe-process-mqtt
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
