project(ipfixprobe-process-wg VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-wg plugin")

add_library(ipfixprobe-process-wg MODULE
    src/wg.cpp
    src/wg.hpp
)

set_target_properties(ipfixprobe-process-wg PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-wg PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
)

if(ENABLE_NEMEA)
    target_link_libraries(ipfixprobe-process-wg PRIVATE 
        -Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
        unirec::unirec
    )
endif()

install(TARGETS ipfixprobe-process-wg
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
