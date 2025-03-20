project(ipfixprobe-process-passivedns VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-passivedns plugin")

add_library(ipfixprobe-process-passivedns MODULE
    src/passivedns.cpp
    src/passivedns.hpp
)

set_target_properties(ipfixprobe-process-passivedns PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-passivedns PRIVATE 
	${CMAKE_SOURCE_DIR}/include/
	${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

if(ENABLE_NEMEA)
    target_link_libraries(ipfixprobe-process-passivedns PRIVATE 
        -Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
        unirec::unirec
    )
endif()

install(TARGETS ipfixprobe-process-passivedns
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
