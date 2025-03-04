project(ipfixprobe-input-pcap VERSION 1.0.0 DESCRIPTION "ipfixprobe-input-pcap plugin")

add_library(ipfixprobe-input-pcap MODULE
    src/pcap.cpp
    src/pcap.hpp
)

set_target_properties(ipfixprobe-input-pcap PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)
target_include_directories(ipfixprobe-input-pcap PRIVATE 
    ${PCAP_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include/
    ${CMAKE_SOURCE_DIR}/src/plugins/input/parser
)
    
target_link_libraries(ipfixprobe-input-pcap PRIVATE 
    ipfixprobe-parser
    ${PCAP_LIBRARIES}
)

install(TARGETS ipfixprobe-input-pcap
    LIBRARY DESTINATION "${INSTALL_DIR_LIB}/ipfixprobe/input/"
)
