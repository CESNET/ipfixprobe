project(ipfixprobe-process-tls VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-tls plugin")

add_library(ipfixprobe-process-tls MODULE
    src/tls.cpp
    src/tls.hpp
	src/md5.cpp
	src/md5.hpp
	src/sha256.hpp
)

set_target_properties(ipfixprobe-process-tls PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-tls PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/process/common
)

target_link_libraries(ipfixprobe-process-tls PRIVATE 
	ipfixprobe-process-tls-parser
    ipfixprobe-output-ipfix
)

if(ENABLE_NEMEA)
    target_link_libraries(ipfixprobe-process-tls PRIVATE 
        -Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
        unirec::unirec
    )
endif()

install(TARGETS ipfixprobe-process-tls
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
