project(ipfixprobe-process-osquery VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-osquery plugin")

add_library(ipfixprobe-process-osquery MODULE
    src/osquery.cpp
    src/osquery.hpp
)

set_target_properties(ipfixprobe-process-osquery PROPERTIES
    CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-osquery PRIVATE
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
    target_link_libraries(ipfixprobe-process-osquery PRIVATE 
        -Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
        unirec::unirec
    )
endif()

install(TARGETS ipfixprobe-process-osquery
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
