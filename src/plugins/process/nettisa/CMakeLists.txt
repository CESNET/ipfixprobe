project(ipfixprobe-process-nettisa VERSION 1.0.0 DESCRIPTION "ipfixprobe-process-nettisa plugin")

add_library(ipfixprobe-process-nettisa MODULE
    src/nettisa.cpp
    src/nettisa.hpp
)

set_target_properties(ipfixprobe-process-nettisa PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

target_include_directories(ipfixprobe-process-nettisa PRIVATE
    ${CMAKE_SOURCE_DIR}/include/
)

target_link_libraries(ipfixprobe-process-nettisa PRIVATE 
    ipfixprobe-core
)

if(ENABLE_NEMEA)
    target_link_libraries(ipfixprobe-process-nettisa PRIVATE 
        -Wl,--whole-archive ipfixprobe-nemea-fields -Wl,--no-whole-archive
        unirec::unirec
    )
endif()

install(TARGETS ipfixprobe-process-nettisa
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/process/"
)
