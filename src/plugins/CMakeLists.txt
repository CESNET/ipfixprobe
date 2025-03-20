add_subdirectory(input)
add_subdirectory(output)
add_subdirectory(process)
add_subdirectory(storage)


if(ENABLE_NEMEA OR ENABLE_OUTPUT_UNIREC)
    message(STATUS "Running ur_processor script for process plugins")

    set(OUTPUT_DIR ${CMAKE_BINARY_DIR}/src/plugins/nemea-fields/)
    file(MAKE_DIRECTORY ${OUTPUT_DIR})

    set(GENERATED_SOURCES
        ${OUTPUT_DIR}/fields.c
        ${OUTPUT_DIR}/fields.h
    )

    execute_process(
        COMMAND /usr/bin/nemea/ur_processor.sh -i ${CMAKE_CURRENT_SOURCE_DIR} -o ${OUTPUT_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE SCRIPT_RESULT
    )

    if(NOT SCRIPT_RESULT EQUAL 0)
        message(FATAL_ERROR "Script ur_processor failed")
    endif()

    add_custom_target(generate_nemea_files DEPENDS ${GENERATED_SOURCES})

    add_library(ipfixprobe-nemea-fields STATIC
        ${GENERATED_SOURCES}
    )

    add_dependencies(ipfixprobe-nemea-fields generate_nemea_files)
    target_include_directories(ipfixprobe-nemea-fields PUBLIC ${OUTPUT_DIR})

endif()