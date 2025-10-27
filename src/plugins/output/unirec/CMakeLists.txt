project(ipfixprobe-output-unirec VERSION 1.0.0 DESCRIPTION "ipfixprobe-output-unirec plugin")

add_library(ipfixprobe-output-unirec MODULE
	src/unirec.cpp
	src/unirec.hpp
)

set_target_properties(ipfixprobe-output-unirec PROPERTIES
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-output-unirec PRIVATE
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/outputPlugin
	${CMAKE_SOURCE_DIR}/include/ipfixprobe/processPlugin
	${adaptmon_SOURCE_DIR}/lib/include/public/
)

target_link_libraries(ipfixprobe-output-unirec PRIVATE
	-Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
	unirec::unirec
	trap::trap
)

install(
	TARGETS ipfixprobe-output-unirec
	LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/output/"
)
