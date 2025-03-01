add_subdirectory(ipfix)
add_subdirectory(text)

if (ENABLE_OUTPUT_UNIREC)
    add_subdirectory(unirec)
endif ()